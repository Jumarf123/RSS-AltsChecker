use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryAccount {
    pub id: String,
    pub username: String,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryScanReport {
    pub accounts: Vec<MemoryAccount>,
    pub warnings: Vec<String>,
    pub processes_found: usize,
    pub processes_scanned: usize,
    pub bytes_scanned: u64,
    pub bytes_unreadable: u64,
    pub read_failures: u64,
    pub states_found: usize,
    pub incomplete: bool,
    pub launched_discord: bool,
}

pub fn scan(cancelled: &dyn Fn() -> bool) -> MemoryScanReport {
    let mut inventory = Inventory::default();
    #[cfg(windows)]
    platform::scan(cancelled, &mut inventory);
    #[cfg(not(windows))]
    {
        let _ = cancelled;
        inventory.problem("Discord process memory scanning is supported only on Windows.".into());
    }
    inventory.finish()
}

const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 96;
const MAX_SOURCES: usize = 16;

// These are projections, not serde_json::Value or untagged/flattened objects.
// Serde skips every unknown value; credentials and raw states never enter results.
#[derive(Deserialize)]
struct StateUser {
    id: String,
    username: String,
    #[serde(rename = "tokenStatus")]
    token_status: Option<u8>,
}

#[derive(Deserialize)]
struct SwitchState {
    users: Vec<StateUser>,
    #[serde(rename = "canUseMultiAccountMobile")]
    mobile: Option<bool>,
}

fn valid_account(user: &StateUser) -> bool {
    let id = user.id.as_bytes();
    (17..=20).contains(&id.len())
        && id[0] != b'0'
        && id.iter().all(u8::is_ascii_digit)
        && user.id.parse::<u64>().is_ok()
        && (2..=32).contains(&user.username.chars().count())
        && user.username.trim() == user.username
        && !user
            .username
            .chars()
            .any(|c| c.is_control() || c == '\u{FFFD}')
}

#[derive(Default)]
struct Inventory {
    report: MemoryScanReport,
    accounts: BTreeMap<String, MemoryAccount>,
    oversized: usize,
    too_deep: usize,
    truncated: usize,
    cancelled: bool,
}

impl Inventory {
    fn problem(&mut self, message: String) {
        self.report.incomplete = true;
        self.report.warnings.push(message);
    }

    fn cancel(&mut self) {
        if !self.cancelled {
            self.cancelled = true;
            self.problem("Discord memory scan cancelled; results are partial.".into());
        }
    }

    fn document(&mut self, text: &str, pid: u32, address: usize) {
        // from_str also checks the document's end. Never include parse errors or
        // input text in diagnostics: errors can contain application data.
        let Ok(state) = serde_json::from_str::<SwitchState>(text) else {
            return;
        };
        let marked = state.mobile.is_some()
            || (!state.users.is_empty() && state.users.iter().all(|u| u.token_status.is_some()));
        if !marked || !state.users.iter().all(valid_account) {
            return;
        }
        self.report.states_found += 1;
        let source = format!("memory://discord.exe/pid/{pid}/0x{address:X}");
        for user in state.users {
            let account = self
                .accounts
                .entry(user.id.clone())
                .or_insert_with(|| MemoryAccount {
                    id: user.id,
                    username: user.username.clone(),
                    sources: Vec::new(),
                });
            // Live memory provides no trustworthy chronology for renamed users.
            // Pick deterministically, independent of PID or discovery order.
            if user.username < account.username {
                account.username = user.username;
            }
            if let Err(index) = account.sources.binary_search(&source) {
                account.sources.insert(index, source.clone());
                if account.sources.len() > MAX_SOURCES {
                    account.sources.pop();
                }
            }
        }
    }

    fn finish(mut self) -> MemoryScanReport {
        if self.oversized != 0 || self.too_deep != 0 {
            self.problem(format!(
                "JSON capture limits reached: {} candidates exceeded {} bytes; {} exceeded depth {}. Additional accounts may have been missed.",
                self.oversized, MAX_JSON_BYTES, self.too_deep, MAX_JSON_DEPTH
            ));
        }
        if self.truncated != 0 {
            self.problem(format!(
                "{} possible switcher JSON candidates ended at a memory boundary or hole before completion.",
                self.truncated
            ));
        }
        self.report.accounts = self.accounts.into_values().collect();
        self.report
    }
}

// A structural capture starts at an object, not at a fixed-order property prefix.
// It never enumerates arbitrary memory strings. Its reusable scratch is bounded,
// and a full JSON deserializer, not the brace matcher, decides what is evidence.
struct JsonFrame {
    closing: u16,
    start: usize,
    has_users: bool,
    has_marker: bool,
}

#[derive(Clone, Copy)]
enum StateKey {
    Users,
    Mobile,
    TokenStatus,
}

struct JsonCapture {
    wide: bool,
    bytes: Vec<u8>,
    closing: Vec<JsonFrame>,
    address: usize,
    in_string: bool,
    escaped: bool,
    first_member: bool,
    string_start: usize,
    pending_key: Option<StateKey>,
}

impl JsonCapture {
    fn new(wide: bool) -> Self {
        Self {
            wide,
            bytes: Vec::new(),
            closing: Vec::new(),
            address: 0,
            in_string: false,
            escaped: false,
            first_member: true,
            string_start: 0,
            pending_key: None,
        }
    }

    fn clear(&mut self) {
        self.bytes.fill(0);
        self.bytes.clear();
        self.closing.clear();
        self.in_string = false;
        self.escaped = false;
        self.first_member = true;
        self.pending_key = None;
    }

    fn interesting(&self) -> bool {
        self.closing.iter().any(|f| f.has_users && f.has_marker)
    }

    fn compact(&mut self) -> bool {
        // A large enclosing cache is not the switcher state. Preserve an open
        // inner object across the buffer limit instead of dropping its prefix.
        let index = self
            .closing
            .iter()
            .position(|f| f.has_users || f.has_marker)
            .or_else(|| self.closing.iter().rposition(|f| f.closing == 125));
        let Some(index) = index else { return false };
        let start = self.closing[index].start;
        if start == 0 {
            return false;
        }
        self.bytes[..start].fill(0);
        self.bytes.drain(..start);
        self.closing.drain(..index);
        for frame in &mut self.closing {
            frame.start -= start;
        }
        self.address += start;
        self.string_start = self.string_start.saturating_sub(start);
        true
    }

    fn gap(&mut self, inventory: &mut Inventory) {
        if self.interesting() {
            inventory.truncated += 1;
        }
        self.clear();
    }

    fn append(&mut self, unit: u16) {
        if self.wide {
            self.bytes.extend_from_slice(&unit.to_le_bytes());
        } else {
            self.bytes.push(unit as u8);
        }
    }

    fn push(&mut self, unit: u16, address: usize, pid: u32, inventory: &mut Inventory) {
        if self.bytes.is_empty() {
            if unit == b'{' as u16 {
                self.address = address;
                self.closing.push(JsonFrame {
                    closing: b'}' as u16,
                    start: 0,
                    has_users: false,
                    has_marker: false,
                });
                self.append(unit);
            }
            return;
        }
        let width = if self.wide { 2 } else { 1 };
        if self.bytes.len() + width > MAX_JSON_BYTES && !self.compact() {
            if self.interesting() {
                inventory.oversized += 1;
            }
            self.clear();
            self.push(unit, address, pid, inventory);
            return;
        }
        self.append(unit);
        if self.in_string {
            if unit < 0x20 {
                self.clear();
            } else if self.escaped {
                self.escaped = false;
            } else if unit == b'\\' as u16 {
                self.escaped = true;
            } else if unit == b'"' as u16 {
                self.in_string = false;
                let body = &self.bytes[self.string_start..self.bytes.len() - width];
                self.pending_key = None;
                for (anchor, key) in [
                    (b"users".as_slice(), StateKey::Users),
                    (b"canUseMultiAccountMobile".as_slice(), StateKey::Mobile),
                    (b"tokenStatus".as_slice(), StateKey::TokenStatus),
                ] {
                    if body.len() == anchor.len() * width
                        && body
                            .chunks_exact(width)
                            .zip(anchor)
                            .all(|(unit, ascii)| unit[0] == *ascii && (width == 1 || unit[1] == 0))
                    {
                        self.pending_key = Some(key);
                    }
                }
            }
            return;
        }
        let whitespace = matches!(unit, 9 | 10 | 13 | 32);
        if !whitespace {
            if let Some(key) = self.pending_key.take() {
                if unit == 58 && self.closing.last().is_some_and(|f| f.closing == 125) {
                    match key {
                        StateKey::Users => self.closing.last_mut().unwrap().has_users = true,
                        StateKey::Mobile => self.closing.last_mut().unwrap().has_marker = true,
                        StateKey::TokenStatus => {
                            if let Some(state) = self.closing.iter_mut().rev().find(|f| f.has_users)
                            {
                                state.has_marker = true;
                            }
                        }
                    }
                }
            }
        }
        if self.first_member && !whitespace {
            self.first_member = false;
            if unit != b'"' as u16 && unit != b'}' as u16 {
                self.clear();
                self.push(unit, address, pid, inventory);
                return;
            }
        }
        match unit {
            34 => {
                self.in_string = true;
                self.string_start = self.bytes.len();
            }
            123 | 91 => {
                if self.closing.len() == MAX_JSON_DEPTH {
                    if self.interesting() {
                        inventory.too_deep += 1;
                    }
                    self.clear();
                    self.push(unit, address, pid, inventory);
                } else {
                    self.closing.push(JsonFrame {
                        closing: if unit == 123 { 125 } else { 93 },
                        start: self.bytes.len() - width,
                        has_users: false,
                        has_marker: false,
                    });
                }
            }
            125 | 93 => {
                let Some(frame) = self.closing.pop() else {
                    self.clear();
                    return;
                };
                if frame.closing != unit {
                    self.clear();
                    return;
                }
                // Validate each complete users object, including _state nested
                // in a larger cache object, without counting its wrapper twice.
                if frame.has_users {
                    let candidate = &self.bytes[frame.start..];
                    let address = self.address + frame.start;
                    if self.wide {
                        let units = candidate
                            .chunks_exact(2)
                            .map(|u| u16::from_le_bytes([u[0], u[1]]));
                        if let Ok(text) = char::decode_utf16(units).collect::<Result<String, _>>() {
                            inventory.document(&text, pid, address);
                            text.into_bytes().fill(0);
                        }
                    } else if let Ok(text) = std::str::from_utf8(candidate) {
                        inventory.document(text, pid, address);
                    }
                }
                if self.closing.is_empty() {
                    self.clear();
                }
            }
            // Only JSON punctuation, numbers and literal characters are valid
            // outside strings. Reject noise early instead of capturing a region.
            9
            | 10
            | 13
            | 32
            | 43..=46
            | 48..=58
            | 69
            | 97
            | 101
            | 102
            | 108
            | 110
            | 114
            | 115
            | 116
            | 117 => {}
            _ => self.clear(),
        }
    }
}

struct MemoryStream {
    pid: u32,
    next: Option<usize>,
    previous: Option<u8>,
    utf8: JsonCapture,
    utf16: [JsonCapture; 2],
}

impl MemoryStream {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            next: None,
            previous: None,
            utf8: JsonCapture::new(false),
            utf16: [JsonCapture::new(true), JsonCapture::new(true)],
        }
    }

    fn gap(&mut self, inventory: &mut Inventory) {
        self.utf8.gap(inventory);
        for capture in &mut self.utf16 {
            capture.gap(inventory);
        }
        self.previous = None;
        self.next = None;
    }

    fn feed(&mut self, address: usize, bytes: &[u8], inventory: &mut Inventory) {
        if self.next != Some(address) {
            self.gap(inventory);
        }
        for (offset, &byte) in bytes.iter().enumerate() {
            let at = address + offset;
            self.utf8.push(byte as u16, at, self.pid, inventory);
            if let Some(previous) = self.previous {
                let start = at - 1;
                self.utf16[start & 1].push(
                    u16::from_le_bytes([previous, byte]),
                    start,
                    self.pid,
                    inventory,
                );
            }
            self.previous = Some(byte);
        }
        self.next = address.checked_add(bytes.len());
    }
}

#[cfg(windows)]
mod platform {
    use super::{Inventory, MemoryStream};
    use std::{
        ffi::c_void,
        mem::size_of,
        thread,
        time::{Duration, Instant},
    };
    use windows::{
        core::{Interface, BSTR, PWSTR, VARIANT},
        Win32::{
            Foundation::{
                CloseHandle, GetLastError, ERROR_INVALID_ADDRESS, ERROR_NOACCESS,
                ERROR_NO_MORE_FILES, ERROR_PARTIAL_COPY, HANDLE, HWND,
            },
            Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
            System::{
                Com::{
                    CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, IServiceProvider,
                    CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED,
                },
                Diagnostics::{
                    Debug::ReadProcessMemory,
                    ToolHelp::{
                        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                        TH32CS_SNAPPROCESS,
                    },
                },
                Memory::{
                    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_MAPPED, MEM_PRIVATE,
                    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
                    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                },
                SystemInformation::{GetSystemInfo, SYSTEM_INFO},
                Threading::{
                    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
                },
            },
            UI::{
                Shell::{
                    IShellBrowser, IShellDispatch2, IShellFolderViewDual, IShellWindows,
                    SID_STopLevelBrowser, ShellWindows, SVGIO_BACKGROUND, SWC_DESKTOP,
                    SWFO_NEEDDISPATCH,
                },
                WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId, SW_SHOWNORMAL},
            },
        },
    };

    const READ_CHUNK: usize = 1024 * 1024;

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn error(operation: &str, error: windows::core::Error) -> String {
        format!(
            "{operation} failed (HRESULT 0x{:08X}).",
            error.code().0 as u32
        )
    }

    fn named(name: &[u16], expected: &[u8]) -> bool {
        let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
        name[..end].len() == expected.len()
            && name[..end].iter().zip(expected).all(|(actual, expected)| {
                u8::try_from(*actual).ok().map(|c| c.to_ascii_lowercase()) == Some(*expected)
            })
    }

    fn process_named(handle: HANDLE, name: &[u8]) -> windows::core::Result<bool> {
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(path.as_mut_ptr()),
                &mut length,
            )?;
        }
        let file = path[..length as usize]
            .rsplit(|c| *c == 92 || *c == 47)
            .next()
            .unwrap_or(&[]);
        Ok(named(file, name))
    }

    fn enumerate(cancelled: &dyn Fn() -> bool, inventory: &mut Inventory) -> (Vec<u32>, bool) {
        let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
            Ok(handle) => OwnedHandle(handle),
            Err(e) => {
                inventory.problem(error("Discord process enumeration", e));
                return (Vec::new(), false);
            }
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut result = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        let mut pids = Vec::new();
        let mut complete = true;
        loop {
            if cancelled() {
                inventory.cancel();
                complete = false;
                break;
            }
            if let Err(e) = result {
                if e.code() != windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0) {
                    inventory.problem(error("Discord process enumeration", e));
                    complete = false;
                }
                break;
            }
            if named(&entry.szExeFile, b"discord.exe") {
                pids.push(entry.th32ProcessID);
            }
            result = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        pids.sort_unstable();
        pids.dedup();
        (pids, complete)
    }

    // Use the EXISTING desktop Explorer automation object, not a new shell
    // process or ShellExecuteW in this elevated application. Explorer handles
    // the registered protocol with its own, checked unelevated desktop token.
    fn launch_from_desktop() -> Result<(), String> {
        unsafe {
            let shell_window = GetShellWindow();
            if shell_window.0.is_null() {
                return Err("No interactive Explorer desktop is available.".into());
            }
            let mut shell_pid = 0;
            if GetWindowThreadProcessId(shell_window, Some(&mut shell_pid)) == 0 {
                return Err(error(
                    "Desktop process lookup",
                    windows::core::Error::from_win32(),
                ));
            }
            let process = OwnedHandle(
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, shell_pid)
                    .map_err(|e| error("Desktop process access", e))?,
            );
            if !process_named(process.0, b"explorer.exe")
                .map_err(|e| error("Desktop executable verification", e))?
            {
                return Err("The interactive desktop is not Explorer.".into());
            }
            let mut token = HANDLE::default();
            OpenProcessToken(process.0, TOKEN_QUERY, &mut token)
                .map_err(|e| error("Desktop token query", e))?;
            let token = OwnedHandle(token);
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned = 0;
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
            .map_err(|e| error("Desktop elevation verification", e))?;
            if returned != size_of::<TOKEN_ELEVATION>() as u32 || elevation.TokenIsElevated != 0 {
                return Err("Explorer is elevated or its elevation could not be verified; refusing an elevated Discord launch.".into());
            }
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .ok()
                .map_err(|e| error("Desktop COM initialization", e))?;
            struct Apartment;
            impl Drop for Apartment {
                fn drop(&mut self) {
                    unsafe {
                        CoUninitialize();
                    }
                }
            }
            let _apartment = Apartment;
            let windows: IShellWindows = CoCreateInstance(&ShellWindows, None, CLSCTX_LOCAL_SERVER)
                .map_err(|e| error("Explorer automation access", e))?;
            let mut desktop_hwnd = 0;
            let desktop = windows
                .FindWindowSW(
                    &VARIANT::from(0i32),
                    &VARIANT::default(),
                    SWC_DESKTOP,
                    &mut desktop_hwnd,
                    SWFO_NEEDDISPATCH,
                )
                .map_err(|e| error("Explorer desktop lookup", e))?;
            let mut automation_pid = 0;
            if GetWindowThreadProcessId(
                HWND(desktop_hwnd as isize as *mut c_void),
                Some(&mut automation_pid),
            ) == 0
                || automation_pid != shell_pid
            {
                return Err(
                    "Explorer automation does not belong to the verified desktop process.".into(),
                );
            }
            let provider: IServiceProvider = desktop
                .cast()
                .map_err(|e| error("Explorer service access", e))?;
            let browser: IShellBrowser = provider
                .QueryService(&SID_STopLevelBrowser)
                .map_err(|e| error("Explorer browser access", e))?;
            let view = browser
                .QueryActiveShellView()
                .map_err(|e| error("Explorer view access", e))?;
            let dispatch: IDispatch = view
                .GetItemObject(SVGIO_BACKGROUND)
                .map_err(|e| error("Explorer view automation", e))?;
            let folder: IShellFolderViewDual = dispatch
                .cast()
                .map_err(|e| error("Explorer folder automation", e))?;
            let shell: IShellDispatch2 = folder
                .Application()
                .and_then(|app| app.cast())
                .map_err(|e| error("Explorer application automation", e))?;
            // A constant URL uses only the desktop user's registered handler.
            // No command string, executable search, or installation path is parsed.
            shell
                .ShellExecute(
                    &BSTR::from("discord://"),
                    &VARIANT::default(),
                    &VARIANT::default(),
                    &VARIANT::from("open"),
                    &VARIANT::from(SW_SHOWNORMAL.0),
                )
                .map_err(|e| error("Registered Discord protocol launch", e))
        }
    }

    fn readable(info: &MEMORY_BASIC_INFORMATION) -> bool {
        let protection = info.Protect.0;
        info.State == MEM_COMMIT
            && (info.Type == MEM_PRIVATE || info.Type == MEM_MAPPED)
            && protection & (PAGE_GUARD.0 | PAGE_NOACCESS.0) == 0
            && [
                PAGE_READONLY,
                PAGE_READWRITE,
                PAGE_WRITECOPY,
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE,
                PAGE_EXECUTE_WRITECOPY,
            ]
            .iter()
            .any(|p| p.0 == protection & 0xff)
    }

    #[derive(Default)]
    struct ReadErrors {
        calls: u64,
        skipped: u64,
        first: Option<(usize, u32)>,
    }

    impl ReadErrors {
        fn record(&self, pid: u32, inventory: &mut Inventory) {
            inventory.report.read_failures += self.calls;
            inventory.report.bytes_unreadable += self.skipped;
            if self.skipped == 0 {
                return;
            }
            // A running process can release/protect pages after VirtualQueryEx.
            // Keep honest coverage counters without treating normal races as a
            // scan failure. Unexpected persistent access errors remain visible.
            inventory.report.incomplete = true;
            if let Some((address, code)) = self.first {
                inventory.problem(format!(
                    "Discord PID {pid}: memory access failed at 0x{address:X} (HRESULT 0x{code:08X}); {} bytes could not be read.",
                    self.skipped
                ));
            }
        }
    }

    fn read_once(
        handle: HANDLE,
        address: usize,
        buffer: &mut [u8],
        errors: &mut ReadErrors,
    ) -> (usize, Option<u32>) {
        let mut received = 0;
        let result = unsafe {
            ReadProcessMemory(
                handle,
                address as *const c_void,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                Some(&mut received),
            )
        };
        let failure = if result.is_err() || received != buffer.len() {
            errors.calls += 1;
            Some(
                result
                    .err()
                    .map(|e| e.code().0 as u32)
                    .unwrap_or(windows::core::HRESULT::from_win32(ERROR_PARTIAL_COPY.0).0 as u32),
            )
        } else {
            None
        };
        // A failed call can still return a readable prefix. Never consume the
        // stale/uninitialized remainder of the reusable buffer.
        (received.min(buffer.len()), failure)
    }

    fn read_span(
        handle: HANDLE,
        start: usize,
        end: usize,
        page_size: usize,
        buffer: &mut [u8],
        stream: &mut MemoryStream,
        inventory: &mut Inventory,
        errors: &mut ReadErrors,
        cancelled: &dyn Fn() -> bool,
    ) {
        let mut address = start;
        while address < end {
            if cancelled() {
                inventory.cancel();
                return;
            }
            let chunk_end = address.saturating_add(buffer.len()).min(end);
            let (received, _) =
                read_once(handle, address, &mut buffer[..chunk_end - address], errors);
            if received != 0 {
                stream.feed(address, &buffer[..received], inventory);
                inventory.report.bytes_scanned += received as u64;
                address += received;
            }
            // Retry the uncompleted span pagewise. A single failed page must
            // not discard the rest of this chunk or virtual-memory region.
            while address < chunk_end {
                if cancelled() {
                    inventory.cancel();
                    return;
                }
                let page_end = address
                    .saturating_add(page_size - address % page_size)
                    .min(chunk_end);
                // Refresh stale region metadata after a failed bulk read. Do
                // not repeatedly read a region that has become inaccessible.
                let mut info = MEMORY_BASIC_INFORMATION::default();
                let queried = unsafe {
                    VirtualQueryEx(
                        handle,
                        Some(address as *const c_void),
                        &mut info,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                } == size_of::<MEMORY_BASIC_INFORMATION>();
                if queried && !readable(&info) {
                    let next = (info.BaseAddress as usize)
                        .checked_add(info.RegionSize)
                        .filter(|next| *next > address)
                        .unwrap_or(page_end)
                        .min(chunk_end);
                    errors.skipped += (next - address) as u64;
                    stream.gap(inventory);
                    address = next;
                    continue;
                }
                let (mut received, mut failure) =
                    read_once(handle, address, &mut buffer[..page_end - address], errors);
                if received == 0 && queried && readable(&info) {
                    (received, failure) =
                        read_once(handle, address, &mut buffer[..page_end - address], errors);
                }
                if received == 0 {
                    if let Some(code) = failure {
                        if ![ERROR_PARTIAL_COPY, ERROR_NOACCESS, ERROR_INVALID_ADDRESS]
                            .iter()
                            .any(|e| windows::core::HRESULT::from_win32(e.0).0 as u32 == code)
                        {
                            errors.first.get_or_insert((address, code));
                        }
                    }
                    errors.skipped += (page_end - address) as u64;
                    stream.gap(inventory);
                    address = page_end;
                } else {
                    stream.feed(address, &buffer[..received], inventory);
                    inventory.report.bytes_scanned += received as u64;
                    address += received;
                }
            }
        }
    }

    fn walk_memory(
        handle: HANDLE,
        pid: u32,
        start: usize,
        end: usize,
        page_size: usize,
        buffer: &mut [u8],
        inventory: &mut Inventory,
        cancelled: &dyn Fn() -> bool,
    ) {
        let mut stream = MemoryStream::new(pid);
        let mut errors = ReadErrors::default();
        let mut address = start;
        let before = inventory.report.bytes_scanned;
        while address < end {
            if cancelled() {
                inventory.cancel();
                break;
            }
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let queried = unsafe {
                VirtualQueryEx(
                    handle,
                    Some(address as *const c_void),
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if queried != size_of::<MEMORY_BASIC_INFORMATION>() {
                let code = unsafe { GetLastError().0 };
                inventory.problem(format!("VirtualQueryEx stopped for Discord PID {pid} at 0x{address:X} (Win32 {code}); its remaining address space was not scanned."));
                break;
            }
            let Some(next) = (info.BaseAddress as usize)
                .checked_add(info.RegionSize)
                .filter(|next| *next > address)
            else {
                inventory.problem(format!(
                    "Invalid virtual-memory region for Discord PID {pid} at 0x{address:X}."
                ));
                break;
            };
            if readable(&info) {
                read_span(
                    handle,
                    address,
                    next.min(end),
                    page_size,
                    buffer,
                    &mut stream,
                    inventory,
                    &mut errors,
                    cancelled,
                );
                if inventory.cancelled {
                    break;
                }
            } else {
                stream.gap(inventory);
            }
            address = next;
        }
        stream.gap(inventory);
        errors.record(pid, inventory);
        if inventory.report.bytes_scanned != before {
            inventory.report.processes_scanned += 1;
        } else if !inventory.cancelled {
            inventory.problem(format!(
                "No readable private/mapped memory was obtained from Discord PID {pid}."
            ));
        }
    }

    pub(super) fn scan(cancelled: &dyn Fn() -> bool, inventory: &mut Inventory) {
        if cancelled() {
            inventory.cancel();
            return;
        }
        let (mut pids, complete) = enumerate(cancelled, inventory);
        inventory.report.processes_found = pids.len();
        if inventory.cancelled {
            return;
        }
        if pids.is_empty() && complete {
            if cancelled() {
                inventory.cancel();
                return;
            }
            match launch_from_desktop() {
                Ok(()) => inventory.report.launched_discord = true,
                Err(reason) => {
                    inventory.problem(format!("Discord was not running and could not be launched safely: {reason} Start installed stable Discord normally from the desktop, then scan again."));
                    return;
                }
            }
            let deadline = Instant::now() + Duration::from_secs(25);
            loop {
                if cancelled() {
                    inventory.cancel();
                    return;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                thread::sleep(remaining.min(Duration::from_millis(100)));
            }
            pids = enumerate(cancelled, inventory).0;
            inventory.report.processes_found = pids.len();
            if inventory.cancelled {
                return;
            }
            if pids.is_empty() {
                inventory.problem("Explorer accepted the Discord protocol launch, but no stable discord.exe process was found after 25 seconds. Start installed stable Discord manually and scan again.".into());
                return;
            }
        }
        inventory.report.processes_found = pids.len();
        #[cfg(target_pointer_width = "32")]
        inventory.problem("This 32-bit build cannot cover 64-bit process address spaces; use the 64-bit application for a complete memory scan.".into());
        let mut system = SYSTEM_INFO::default();
        unsafe {
            GetSystemInfo(&mut system);
        }
        let page_size = system.dwPageSize as usize;
        let end = (system.lpMaximumApplicationAddress as usize).saturating_add(1);
        if page_size == 0 || end <= 1 {
            inventory.problem("Windows returned invalid memory address-space information.".into());
            return;
        }
        let mut buffer = vec![0u8; READ_CHUNK];
        for pid in pids {
            if cancelled() {
                inventory.cancel();
                break;
            }
            let process = match unsafe {
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            } {
                Ok(handle) => OwnedHandle(handle),
                Err(e) => {
                    inventory.problem(error(&format!("Read-only access to Discord PID {pid}"), e));
                    continue;
                }
            };
            match process_named(process.0, b"discord.exe") {
                Ok(true) => walk_memory(
                    process.0,
                    pid,
                    0,
                    end,
                    page_size,
                    &mut buffer,
                    inventory,
                    cancelled,
                ),
                Ok(false) => inventory.problem(format!(
                    "PID {pid} changed executable after enumeration; its memory was not read."
                )),
                Err(e) => inventory.problem(error(
                    &format!("Discord PID {pid} executable verification"),
                    e,
                )),
            }
            if inventory.cancelled {
                break;
            }
        }
        buffer.fill(0);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::System::{
            Memory::{
                VirtualAlloc, VirtualFree, VirtualProtect, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE,
                PAGE_PROTECTION_FLAGS,
            },
            Threading::GetCurrentProcessId,
        };

        struct Allocation(*mut c_void);
        impl Drop for Allocation {
            fn drop(&mut self) {
                unsafe {
                    let _ = VirtualFree(self.0, 0, MEM_RELEASE);
                }
            }
        }

        fn allocation(pages: usize) -> (Allocation, usize, OwnedHandle) {
            let mut system = SYSTEM_INFO::default();
            unsafe {
                GetSystemInfo(&mut system);
            }
            let page = system.dwPageSize as usize;
            let allocation = Allocation(unsafe {
                VirtualAlloc(None, page * pages, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
            });
            assert!(!allocation.0.is_null());
            let process = OwnedHandle(unsafe {
                OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    GetCurrentProcessId(),
                )
                .unwrap()
            });
            (allocation, page, process)
        }

        fn put(allocation: &Allocation, offset: usize, bytes: &[u8]) {
            // Writes only this test's own synthetic allocation, never a target.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    allocation.0.cast::<u8>().add(offset),
                    bytes.len(),
                );
            }
        }

        #[test]
        fn exact_process_name_and_readable_whitelist() {
            assert!(named(
                &"DiScOrD.ExE".encode_utf16().collect::<Vec<_>>(),
                b"discord.exe"
            ));
            for name in [
                "discord.exe.old",
                "discordptb.exe",
                "notdiscord.exe",
                "discord",
            ] {
                assert!(!named(
                    &name.encode_utf16().collect::<Vec<_>>(),
                    b"discord.exe"
                ));
            }
            let mut info = MEMORY_BASIC_INFORMATION {
                State: MEM_COMMIT,
                Type: MEM_PRIVATE,
                Protect: PAGE_READWRITE,
                ..Default::default()
            };
            assert!(readable(&info));
            info.Type = MEM_MAPPED;
            info.Protect = PAGE_EXECUTE_READ;
            assert!(readable(&info));
            for protection in [PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READWRITE | PAGE_GUARD] {
                info.Protect = protection;
                assert!(!readable(&info));
            }
        }

        #[test]
        fn actual_reads_retry_past_a_hole_without_joining_fragments() {
            let (allocation, page, process) = allocation(4);
            let address = allocation.0 as usize;
            let one = super::super::tests::state("698025508365008949", "first");
            let two = super::super::tests::state("1196007867317231727", "second");
            let broken = super::super::tests::state("2196007867317231727", "must_not_join");
            let split = broken.len() / 2;
            put(&allocation, 0, one.as_bytes());
            put(&allocation, page - split, &broken.as_bytes()[..split]);
            put(&allocation, 2 * page, &broken.as_bytes()[split..]);
            put(&allocation, 3 * page, two.as_bytes());
            let mut old = PAGE_PROTECTION_FLAGS::default();
            unsafe {
                VirtualProtect(
                    (address + page) as *const c_void,
                    page,
                    PAGE_NOACCESS,
                    &mut old,
                )
                .unwrap();
            }
            let mut inventory = Inventory::default();
            let mut stream = MemoryStream::new(123);
            let mut errors = ReadErrors::default();
            let mut buffer = vec![0xCC; 4 * page];
            // Deliberately pass a span containing a hole to exercise RPM's
            // partial/failed-read retry, not just VirtualQueryEx's skip path.
            read_span(
                process.0,
                address,
                address + 4 * page,
                page,
                &mut buffer,
                &mut stream,
                &mut inventory,
                &mut errors,
                &|| false,
            );
            stream.gap(&mut inventory);
            assert!(errors.calls > 0);
            assert_eq!(errors.skipped, page as u64);
            errors.record(123, &mut inventory);
            let report = inventory.finish();
            assert_eq!(report.bytes_scanned, (3 * page) as u64);
            assert_eq!(report.bytes_unreadable, page as u64);
            assert_eq!(report.read_failures, errors.calls);
            assert!(report.incomplete);
            assert!(report.warnings.is_empty(), "{:?}", report.warnings);
            assert_eq!(report.accounts.len(), 2);
            assert!(!report
                .accounts
                .iter()
                .any(|a| a.username == "must_not_join"));
        }

        #[test]
        fn recovered_reads_are_not_failures_but_persistent_access_denial_is_reported() {
            let mut inventory = Inventory::default();
            ReadErrors {
                calls: 3,
                ..Default::default()
            }
            .record(123, &mut inventory);
            let report = inventory.finish();
            assert_eq!(report.read_failures, 3);
            assert_eq!(report.bytes_unreadable, 0);
            assert!(!report.incomplete);
            assert!(report.warnings.is_empty());

            let mut inventory = Inventory::default();
            ReadErrors {
                calls: 2,
                skipped: 4096,
                first: Some((0x1000, 0x80070005)),
            }
            .record(123, &mut inventory);
            let report = inventory.finish();
            assert!(report.incomplete);
            assert_eq!(report.bytes_unreadable, 4096);
            assert_eq!(report.warnings.len(), 1);
            assert!(report.warnings[0].contains("0x80070005"));
        }

        #[test]
        fn actual_virtual_query_preserves_adjacent_readable_regions() {
            let (allocation, page, process) = allocation(2);
            let address = allocation.0 as usize;
            let text = super::super::tests::state("698025508365008949", "adjacent");
            put(&allocation, page - text.len() / 2, text.as_bytes());
            let mut old = PAGE_PROTECTION_FLAGS::default();
            unsafe {
                VirtualProtect(
                    (address + page) as *const c_void,
                    page,
                    PAGE_READONLY,
                    &mut old,
                )
                .unwrap();
            }
            let mut inventory = Inventory::default();
            walk_memory(
                process.0,
                123,
                address,
                address + 2 * page,
                page,
                &mut vec![0; READ_CHUNK],
                &mut inventory,
                &|| false,
            );
            let report = inventory.finish();
            assert_eq!(report.accounts.len(), 1);
            assert_eq!(report.processes_scanned, 1);
            assert_eq!(report.bytes_scanned, (2 * page) as u64);
            assert!(!report.incomplete, "{:?}", report.warnings);
        }

        #[test]
        fn cancellation_prevents_even_a_controlled_read() {
            let (allocation, page, process) = allocation(1);
            let mut inventory = Inventory::default();
            walk_memory(
                process.0,
                123,
                allocation.0 as usize,
                allocation.0 as usize + page,
                page,
                &mut vec![0; READ_CHUNK],
                &mut inventory,
                &|| true,
            );
            let report = inventory.finish();
            assert!(report.incomplete);
            assert_eq!(report.bytes_scanned, 0);
            assert_eq!(report.processes_scanned, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"_state":{"users":[{"id":"698025508365008949","avatar":null,"username":"jumarf","discriminator":"0","tokenStatus":2,"pushSyncToken":null},{"id":"1196007867317231727","avatar":null,"username":"cuffy123_20423","tokenStatus":2}],"canUseMultiAccountMobile":false},"_version":1}"#;

    pub(super) fn state(id: &str, username: &str) -> String {
        format!(
            r#"{{"users":[{{"id":"{id}","username":{},"tokenStatus":2}}]}}"#,
            serde_json::to_string(username).unwrap()
        )
    }

    fn synthetic(bytes: &[u8], chunk: usize) -> MemoryScanReport {
        let mut inventory = Inventory::default();
        let mut stream = MemoryStream::new(42);
        for (index, part) in bytes.chunks(chunk).enumerate() {
            stream.feed(0x1000 + index * chunk, part, &mut inventory);
        }
        stream.gap(&mut inventory);
        inventory.finish()
    }

    #[test]
    fn sample_two_users_and_only_public_projection() {
        let text = SAMPLE.replace(
            "\"avatar\":null",
            "\"token\":\"SYNTHETIC_SECRET\",\"avatar\":null",
        );
        let report = synthetic(text.as_bytes(), 17);
        assert_eq!(report.accounts.len(), 2);
        assert_eq!(report.states_found, 1);
        assert!(report
            .accounts
            .iter()
            .any(|a| a.id == "698025508365008949" && a.username == "jumarf"));
        assert_eq!(
            report.accounts[0].sources,
            ["memory://discord.exe/pid/42/0x100A"]
        );
        assert!(!format!("{report:?}").contains("SYNTHETIC_SECRET"));
        assert!(!report.incomplete);
    }

    #[test]
    fn six_accounts_reordered_properties_and_duplicate_ids() {
        let users = (0..6)
            .map(|n| {
                format!(r#"{{"username":"user{n}","tokenStatus":2,"id":"119600786731723172{n}"}}"#)
            })
            .collect::<Vec<_>>()
            .join(", \n");
        let text = format!(
            r#"{{ "_version" : 1, "_state" : {{ "canUseMultiAccountMobile" : false, "other" : [], "users" : [ {users}, {{"username":"user0","id":"1196007867317231720","tokenStatus":2}} ] }} }}"#
        );
        let report = synthetic(text.as_bytes(), 3);
        assert_eq!(report.accounts.len(), 6);
        assert_eq!(report.states_found, 1);
        assert!(!report.incomplete);
    }

    #[test]
    fn extended_unicode_escaped_braces_and_utf16_both_alignments() {
        let username = "\u{0416}\u{00E9}\u{1F680}\"}[]\\z";
        let text = state("698025508365008949", username);
        assert_eq!(synthetic(text.as_bytes(), 1).accounts[0].username, username);
        let wide: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        for prefix in [0, 1] {
            let mut bytes = vec![0xFF; prefix];
            bytes.extend_from_slice(&wide);
            for chunk in [1, 2, 3, 7, 64] {
                let report = synthetic(&bytes, chunk);
                assert_eq!(report.accounts.len(), 1);
                assert_eq!(report.accounts[0].username, username);
                assert_eq!(
                    report.accounts[0].sources[0],
                    format!("memory://discord.exe/pid/42/0x{:X}", 0x1000 + prefix)
                );
            }
        }
        let escaped = r#"{"users":[{"id":"698025508365008949","username":"\u0416\u00e9\ud83d\ude80","tokenStatus":2}]}"#;
        assert_eq!(
            synthetic(escaped.as_bytes(), 2).accounts[0].username,
            "\u{0416}\u{00E9}\u{1F680}"
        );
    }

    #[test]
    fn every_document_and_anchor_split_is_preserved() {
        for bytes in [
            SAMPLE.as_bytes().to_vec(),
            SAMPLE.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        ] {
            for split in 1..bytes.len() {
                let mut inventory = Inventory::default();
                let mut stream = MemoryStream::new(77);
                stream.feed(0x1001, &bytes[..split], &mut inventory);
                stream.feed(0x1001 + split, &bytes[split..], &mut inventory);
                stream.gap(&mut inventory);
                assert_eq!(inventory.finish().accounts.len(), 2, "split {split}");
            }
        }
    }

    #[test]
    fn long_documents_and_arbitrary_leading_properties_are_not_truncated_at_4k() {
        let text = format!(
            r#"{{"unrelated":"{}",{}"users":[{{"username":"long_document","id":"698025508365008949","tokenStatus":2}}]}}"#,
            "x".repeat(16000),
            " ".repeat(9000)
        );
        let report = synthetic(text.as_bytes(), 4096);
        assert_eq!(report.accounts.len(), 1);
        assert!(!report.incomplete);
    }

    #[test]
    fn unrelated_lists_malformed_and_truncated_documents_are_rejected() {
        for text in [
            r#"{"id":"698025508365008949","username":"cached_user","tokenStatus":2}"#,
            r#"{"users":[{"id":"698025508365008949","username":"cached_user"}]}"#,
            r#"{"users":[],"cache":true}"#,
            r#"{"users":[{"id":"698025508365008949","username":"cached_user","tokenStatus":2},{"id":"1196007867317231727","username":"other_user"}]}"#,
            r#"{"users":[{"id":"698025508365008949","username":"bad\q","tokenStatus":2}]}"#,
            r#"{"users":[{"id":"698025508365008949","username":"valid","tokenStatus":2}],}"#,
            r#"{"users":[{"id":"698025508365008949","username":"valid","tokenStatus":2}]"#,
            r#"{"users":[{"id":"698025508365008949","username":"valid","tokenStatus":2}],"users":[]}"#,
        ] {
            assert!(synthetic(text.as_bytes(), 5).accounts.is_empty());
        }
        // The inner _state is itself a complete valid users object even if its
        // surrounding wrapper is truncated in a different allocation.
        let partial_wrapper = synthetic(&SAMPLE.as_bytes()[..SAMPLE.len() - 1], 4);
        assert_eq!(partial_wrapper.accounts.len(), 2);
        assert!(!partial_wrapper.incomplete);
        assert_eq!(
            synthetic(br#"{"canUseMultiAccountMobile":false,"users":[]}"#, 7).states_found,
            1
        );
        assert_eq!(synthetic(br#"{"canUseMultiAccountMobile":true,"users":[{"id":"698025508365008949","username":"valid"}]}"#, 9).accounts.len(), 1);
    }

    #[test]
    fn invalid_ids_names_and_utf_encodings_are_rejected() {
        for id in [
            "",
            "123",
            "00000000000000000",
            "69802550836500894x",
            "18446744073709551616",
            "123456789012345678901",
        ] {
            assert!(synthetic(state(id, "valid").as_bytes(), 7)
                .accounts
                .is_empty());
        }
        for name in [
            "",
            "x",
            "  ",
            " leading",
            "trailing ",
            "line\nfeed",
            "null\0char",
            "\u{FFFD}bad",
            "abcdefghijklmnopqrstuvwxyz1234567",
        ] {
            assert!(synthetic(state("698025508365008949", name).as_bytes(), 7)
                .accounts
                .is_empty());
        }
        let text = state("698025508365008949", "extended");
        let mut bad_utf8 = text.as_bytes().to_vec();
        let index = text.find("extended").unwrap();
        bad_utf8[index] = 0xFF;
        assert!(synthetic(&bad_utf8, 3).accounts.is_empty());
        let mut bad_utf16: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        bad_utf16[index * 2..index * 2 + 2].copy_from_slice(&0xD800u16.to_le_bytes());
        assert!(synthetic(&bad_utf16, 3).accounts.is_empty());
    }

    #[test]
    fn gaps_never_join_carry_or_json() {
        let text = state("698025508365008949", "must_not_join");
        for bytes in [
            text.as_bytes().to_vec(),
            text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        ] {
            for split in [1, 3, bytes.len() / 2, bytes.len() - 2] {
                for explicit_gap in [false, true] {
                    let mut inventory = Inventory::default();
                    let mut stream = MemoryStream::new(1);
                    stream.feed(0x1000, &bytes[..split], &mut inventory);
                    if explicit_gap {
                        stream.gap(&mut inventory);
                    }
                    let next = 0x1000 + split + usize::from(!explicit_gap);
                    stream.feed(next, &bytes[split..], &mut inventory);
                    stream.gap(&mut inventory);
                    assert!(inventory.finish().accounts.is_empty());
                }
            }
        }
    }

    #[test]
    fn states_pids_usernames_and_bounded_sources_dedupe_deterministically() {
        fn run(reverse: bool) -> MemoryScanReport {
            let mut inventory = Inventory::default();
            let mut pids: Vec<_> = (1..=25).collect();
            if reverse {
                pids.reverse();
            }
            for pid in pids {
                let mut stream = MemoryStream::new(pid);
                let text = format!(
                    "{}\0{}",
                    state(
                        "698025508365008949",
                        if pid % 2 == 0 { "zulu" } else { "alpha" }
                    ),
                    state("1196007867317231727", "second")
                );
                stream.feed(0x2000, text.as_bytes(), &mut inventory);
                stream.gap(&mut inventory);
            }
            inventory.finish()
        }
        let report = run(false);
        assert_eq!(report.accounts, run(true).accounts);
        assert_eq!(report.accounts.len(), 2);
        assert_eq!(report.states_found, 50);
        assert!(report
            .accounts
            .iter()
            .all(|a| a.sources.len() == MAX_SOURCES));
        assert_eq!(
            report
                .accounts
                .iter()
                .find(|a| a.id == "698025508365008949")
                .unwrap()
                .username,
            "alpha"
        );
    }

    #[test]
    fn nested_states_are_found_without_counting_wrappers_twice() {
        let second = state("2196007867317231727", "nested_account");
        let text = format!(r#"{{"cache":[{SAMPLE},{{"saved":{second}}}]}}"#);
        for bytes in [
            text.as_bytes().to_vec(),
            text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        ] {
            let report = synthetic(&bytes, 7);
            assert_eq!(report.states_found, 2);
            assert_eq!(report.accounts.len(), 3);
            assert!(!report.incomplete);
            assert!(report.accounts.iter().all(|a| a.sources.len() == 1));
        }
    }

    #[test]
    fn complete_independent_state_after_gap_is_not_discarded() {
        let mut inventory = Inventory::default();
        let mut stream = MemoryStream::new(1);
        let split = SAMPLE.find("{\"users\"").unwrap();
        stream.feed(0x1000, &SAMPLE.as_bytes()[..split], &mut inventory);
        stream.feed(0x2000, &SAMPLE.as_bytes()[split..], &mut inventory);
        stream.gap(&mut inventory);
        let report = inventory.finish();
        assert_eq!(report.accounts.len(), 2);
        assert_eq!(report.states_found, 1);
        assert!(report
            .accounts
            .iter()
            .all(|a| a.sources == ["memory://discord.exe/pid/1/0x2000"]));
    }

    #[test]
    fn unrelated_json_limits_do_not_report_missing_switcher_accounts() {
        let valid = state("698025508365008949", "after_noise");
        let padding = "x".repeat(MAX_JSON_BYTES);
        for noise in [
            format!(r#"{{"cache":"{padding}"}}"#),
            format!(r#"{{"label":"users","cache":"{padding}"}}"#),
            format!(r#"{{"users":[],"cache":"{padding}"}}"#),
            format!(
                "{{\"unknown\":{}0{}}}",
                "[".repeat(MAX_JSON_DEPTH),
                "]".repeat(MAX_JSON_DEPTH)
            ),
        ] {
            let text = format!("{noise}\0{valid}");
            let report = synthetic(text.as_bytes(), 8192);
            assert_eq!(report.accounts.len(), 1);
            assert!(!report.incomplete, "{:?}", report.warnings);
            assert!(report.warnings.is_empty());
        }
    }

    #[test]
    fn large_enclosing_cache_preserves_a_state_crossing_the_capture_limit() {
        let valid = state("698025508365008949", "inside_cache");
        for width in [1, 2] {
            let text = format!(
                r#"{{"cache":"{}","saved":{valid}}}"#,
                "x".repeat(MAX_JSON_BYTES / width - 64)
            );
            let address = 0x1000 + text.find("{\"users\"").unwrap() * width;
            let bytes = if width == 1 {
                text.into_bytes()
            } else {
                text.encode_utf16().flat_map(u16::to_le_bytes).collect()
            };
            let report = synthetic(&bytes, 4093);
            assert_eq!(report.accounts.len(), 1);
            assert_eq!(report.states_found, 1);
            assert_eq!(
                report.accounts[0].sources,
                [format!("memory://discord.exe/pid/42/0x{address:X}")]
            );
            assert!(!report.incomplete, "{:?}", report.warnings);
        }
    }

    #[test]
    fn resource_limits_are_diagnostic_and_scanning_recovers() {
        let valid = state("698025508365008949", "after_limit");
        let oversized = format!(
            "{{\"canUseMultiAccountMobile\":false,\"users\":[],\"padding\":\"{}\"}}\0{valid}",
            "x".repeat(MAX_JSON_BYTES)
        );
        let report = synthetic(oversized.as_bytes(), 8192);
        assert!(report.incomplete);
        assert!(report.warnings.iter().any(|w| w.contains("capture limits")));
        assert_eq!(report.accounts.len(), 1);
        let deep = format!(
            "{{\"canUseMultiAccountMobile\":false,\"users\":[],\"unknown\":{}0{}}}\0{valid}",
            "[".repeat(MAX_JSON_DEPTH),
            "]".repeat(MAX_JSON_DEPTH)
        );
        let report = synthetic(deep.as_bytes(), 64);
        assert!(report.incomplete);
        assert_eq!(report.accounts.len(), 1);
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_is_explicit() {
        let report = scan(&|| false);
        assert!(report.incomplete);
        assert!(!report.warnings.is_empty());
    }
}
