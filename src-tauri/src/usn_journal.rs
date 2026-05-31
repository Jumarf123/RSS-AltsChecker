use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct UsnEvent {
    pub drive: String,
    pub path: String,
    pub reason: String,
    pub timestamp_utc: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UsnDriveStatus {
    pub drive: String,
    pub status: String,
    pub records_scanned: usize,
    pub oldest_entry_utc: Option<String>,
    pub newest_entry_utc: Option<String>,
    pub oldest_entry_date_utc: Option<String>,
    pub last_deletion_utc: Option<String>,
    pub age: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UsnJournalReport {
    pub status: String,
    pub drives: Vec<UsnDriveStatus>,
    pub minecraft_events: Vec<UsnEvent>,
    pub discord_events: Vec<UsnEvent>,
    pub scanned_records: usize,
}

#[derive(Debug, Clone, Default)]
pub struct UsnScanOutput {
    pub report: Option<UsnJournalReport>,
    pub warnings: Vec<String>,
    pub scanned_locations: Vec<String>,
}

#[cfg(not(windows))]
pub fn scan_for_minecraft_discord() -> UsnScanOutput {
    UsnScanOutput {
        report: Some(UsnJournalReport {
            status: "USN Journal доступен только на Windows".to_string(),
            ..UsnJournalReport::default()
        }),
        ..UsnScanOutput::default()
    }
}

#[cfg(windows)]
pub fn scan_for_minecraft_discord() -> UsnScanOutput {
    windows_impl::scan()
}

#[cfg(test)]
mod tests {
    #[test]
    fn usn_scan_returns_report_object() {
        let output = super::scan_for_minecraft_discord();
        assert!(output.report.is_some());
    }

    #[cfg(windows)]
    #[test]
    fn minecraft_dated_log_name_is_detected() {
        assert!(super::windows_impl::is_minecraft_dated_log_name(
            "2026-02-18-1.log.gz"
        ));
        assert!(super::windows_impl::is_minecraft_dated_log_name(
            "2026-02-18-2.log"
        ));
        assert!(!super::windows_impl::is_minecraft_dated_log_name(
            "scan_latest.log"
        ));
    }

    #[cfg(windows)]
    #[test]
    fn minecraft_usn_log_name_is_strict() {
        assert!(super::windows_impl::is_minecraft_usn_log_name("latest.log"));
        assert!(super::windows_impl::is_minecraft_usn_log_name(
            "latest.log.1"
        ));
        assert!(super::windows_impl::is_minecraft_usn_log_name(
            "2026-02-18-2.log.gz"
        ));
        assert!(!super::windows_impl::is_minecraft_usn_log_name(
            "latest.log.backup"
        ));
        assert!(!super::windows_impl::is_minecraft_usn_log_name(
            "R-gpu-0-g6-c200-2026-2-19-13-42-33-231.log"
        ));
        assert!(!super::windows_impl::is_minecraft_usn_log_name(
            "000005.ldb"
        ));
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::collections::{HashMap, HashSet};
    use std::env;
    use std::ffi::c_void;
    use std::mem;

    use bitflags::bitflags;
    use chrono::{DateTime, Duration, Local, Utc};
    use windows::core::{Error as WinError, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{
        FSCTL_ENUM_USN_DATA, FSCTL_GET_NTFS_FILE_RECORD, FSCTL_QUERY_USN_JOURNAL,
        FSCTL_READ_USN_JOURNAL, MFT_ENUM_DATA_V0, NTFS_FILE_RECORD_INPUT_BUFFER,
        READ_USN_JOURNAL_DATA_V0, USN_JOURNAL_DATA_V0,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    use super::{UsnDriveStatus, UsnEvent, UsnJournalReport, UsnScanOutput};

    const READ_BUFFER_SIZE: usize = 1 * 1024 * 1024;
    const MFT_ENUM_BUFFER_SIZE: usize = 2 * 1024 * 1024;
    const NTFS_FILE_RECORD_BUFFER_SIZE: usize = 32 * 1024;
    const MAX_RECORDS_PER_DRIVE: usize = 1_000_000;
    const MAX_EVENTS_PER_CATEGORY: usize = 80;
    const RECENT_USN_WINDOW: i64 = 2 * 1024 * 1024 * 1024;
    const MAX_MFT_ENUM_GUARD: usize = 8192;

    bitflags! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        struct ReasonFlags: u32 {
            const DATA_OVERWRITE = 0x0000_0001;
            const DATA_EXTEND = 0x0000_0002;
            const FILE_CREATE = 0x0000_0100;
            const FILE_DELETE = 0x0000_0200;
            const RENAME_OLD_NAME = 0x0000_1000;
            const RENAME_NEW_NAME = 0x0000_2000;
            const STREAM_CHANGE = 0x0020_0000;
            const CLOSE = 0x8000_0000;
        }
    }

    #[derive(Debug)]
    struct VolumeHandle {
        raw: HANDLE,
    }

    unsafe impl Send for VolumeHandle {}
    unsafe impl Sync for VolumeHandle {}

    impl Drop for VolumeHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.raw);
            }
        }
    }

    #[derive(Clone, Debug)]
    struct VolumeInfo {
        name: String,
        device_path: String,
    }

    #[derive(Clone, Debug)]
    struct ParsedUsnRecord {
        file_reference_number: u64,
        parent_file_reference_number: u64,
        timestamp_utc: DateTime<Utc>,
        reason: ReasonFlags,
        file_attributes: u32,
        file_name: String,
    }

    #[derive(Clone, Debug)]
    struct RawUsnEvent {
        parent_file_reference_number: u64,
        timestamp_utc: DateTime<Utc>,
        reason: String,
        file_name: String,
    }

    #[derive(Clone, Debug)]
    struct MftNode {
        file_reference_number: u64,
        parent_file_reference_number: u64,
        name: String,
    }

    #[derive(Default)]
    struct MftResolveResult {
        nodes: HashMap<u64, MftNode>,
        usn_journal_last_write_utc: Option<DateTime<Utc>>,
    }

    #[derive(Default)]
    struct DriveScanOutput {
        records_scanned: usize,
        oldest: Option<DateTime<Utc>>,
        newest: Option<DateTime<Utc>>,
        last_deletion: Option<DateTime<Utc>>,
        minecraft_events: Vec<UsnEvent>,
        discord_events: Vec<UsnEvent>,
        warnings: Vec<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DriveScanErrorKind {
        Unsupported,
        Permission,
        Other,
    }

    #[derive(Debug, Clone)]
    struct DriveScanError {
        kind: DriveScanErrorKind,
        message: String,
    }

    impl DriveScanError {
        fn unsupported(message: String) -> Self {
            Self {
                kind: DriveScanErrorKind::Unsupported,
                message,
            }
        }

        fn permission(message: String) -> Self {
            Self {
                kind: DriveScanErrorKind::Permission,
                message,
            }
        }

        fn other(message: String) -> Self {
            Self {
                kind: DriveScanErrorKind::Other,
                message,
            }
        }
    }

    pub fn scan() -> UsnScanOutput {
        let mut out = UsnScanOutput::default();

        let volumes = match enumerate_ntfs_volumes() {
            Ok(volumes) => volumes,
            Err(error) => {
                out.warnings
                    .push(format!("USN: enumerate volumes failed: {error}"));
                out.report = Some(UsnJournalReport {
                    status: "USN Journal недоступен".to_string(),
                    ..UsnJournalReport::default()
                });
                return out;
            }
        };

        if volumes.is_empty() {
            out.report = Some(UsnJournalReport {
                status: "USN Journal: NTFS диски не найдены".to_string(),
                ..UsnJournalReport::default()
            });
            return out;
        }

        let system_drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let system_drive = system_drive.trim_end_matches('\\').to_ascii_lowercase();

        let mut ordered_volumes = volumes;
        ordered_volumes.sort_by_key(|volume| {
            if volume.name.to_ascii_lowercase() == system_drive {
                0usize
            } else {
                1usize
            }
        });

        let mut drives = Vec::<UsnDriveStatus>::new();
        let mut minecraft_events = Vec::<UsnEvent>::new();
        let mut discord_events = Vec::<UsnEvent>::new();
        let mut scanned_records = 0usize;

        for volume in ordered_volumes {
            out.scanned_locations
                .push(format!("usn_volume: {}", volume.name));

            match scan_drive(&volume) {
                Ok(scan) => {
                    scanned_records += scan.records_scanned;
                    out.warnings.extend(scan.warnings.iter().cloned());

                    for event in scan.minecraft_events {
                        if minecraft_events.len() < MAX_EVENTS_PER_CATEGORY {
                            minecraft_events.push(event);
                        }
                    }
                    for event in scan.discord_events {
                        if discord_events.len() < MAX_EVENTS_PER_CATEGORY {
                            discord_events.push(event);
                        }
                    }

                    drives.push(UsnDriveStatus {
                        drive: volume.name.clone(),
                        status: classify_age_status(scan.oldest),
                        records_scanned: scan.records_scanned,
                        oldest_entry_utc: scan.oldest.map(format_utc),
                        newest_entry_utc: scan.newest.map(format_utc),
                        oldest_entry_date_utc: scan.oldest.map(format_utc_date),
                        last_deletion_utc: scan.last_deletion.map(format_utc),
                        age: scan.newest.map(humanize_age_since),
                    });
                }
                Err(error) => {
                    let is_system = volume.name.to_ascii_lowercase() == system_drive;
                    match error.kind {
                        DriveScanErrorKind::Unsupported => {
                            if is_system {
                                drives.push(UsnDriveStatus {
                                    drive: volume.name.clone(),
                                    status: "Недоступно (USN не поддерживается)".to_string(),
                                    records_scanned: 0,
                                    oldest_entry_utc: None,
                                    newest_entry_utc: None,
                                    oldest_entry_date_utc: None,
                                    last_deletion_utc: None,
                                    age: None,
                                });
                            }
                        }
                        DriveScanErrorKind::Permission => {
                            if is_system {
                                drives.push(UsnDriveStatus {
                                    drive: volume.name.clone(),
                                    status: "Недоступно (нужны права администратора)".to_string(),
                                    records_scanned: 0,
                                    oldest_entry_utc: None,
                                    newest_entry_utc: None,
                                    oldest_entry_date_utc: None,
                                    last_deletion_utc: None,
                                    age: None,
                                });
                            }
                        }
                        DriveScanErrorKind::Other => {
                            if is_system {
                                out.warnings.push(format!(
                                    "USN {}: {}",
                                    volume.name,
                                    error.message.trim()
                                ));
                                drives.push(UsnDriveStatus {
                                    drive: volume.name.clone(),
                                    status: "Недоступно (права или политика системы)".to_string(),
                                    records_scanned: 0,
                                    oldest_entry_utc: None,
                                    newest_entry_utc: None,
                                    oldest_entry_date_utc: None,
                                    last_deletion_utc: None,
                                    age: None,
                                });
                            } else {
                                out.warnings.push(format!(
                                    "USN {}: пропущен ({})",
                                    volume.name,
                                    error.message.trim()
                                ));
                            }
                        }
                    }
                }
            }
        }

        let status = summarize_global_status(&drives);
        out.report = Some(UsnJournalReport {
            status,
            drives,
            minecraft_events,
            discord_events,
            scanned_records,
        });
        out
    }

    fn summarize_global_status(drives: &[UsnDriveStatus]) -> String {
        if drives.is_empty() {
            return "USN Journal: данных нет".to_string();
        }

        if drives
            .iter()
            .any(|drive| drive.status.contains("<24h") || drive.status.contains("Likely cleared"))
        {
            return "USN: журнал выглядит свежим (<24h), проверь вручную".to_string();
        }
        if drives.iter().any(|drive| drive.status.contains("<14d")) {
            return "USN: активность журнала <14 дней (возможна очистка)".to_string();
        }
        let has_unavailable = drives
            .iter()
            .any(|drive| drive.status.contains("Недоступно"));
        let has_data = drives.iter().any(|drive| drive.records_scanned > 0);
        if has_unavailable && !has_data {
            return "USN: частично недоступен".to_string();
        }

        if has_data {
            "USN: проверка завершена".to_string()
        } else {
            "USN: данных не найдено".to_string()
        }
    }

    fn classify_age_status(oldest: Option<DateTime<Utc>>) -> String {
        let Some(oldest) = oldest else {
            return "Journal active (age unknown)".to_string();
        };

        let age = Utc::now() - oldest;
        if age < Duration::hours(24) {
            "Journal active <24h (Likely cleared)".to_string()
        } else if age < Duration::days(14) {
            "Journal active <14d (Possible overwrite)".to_string()
        } else {
            "Journal active >14d (Normal)".to_string()
        }
    }

    fn scan_drive(volume: &VolumeInfo) -> Result<DriveScanOutput, DriveScanError> {
        let handle = open_volume(&volume.device_path).map_err(classify_open_volume_error)?;
        let journal = query_journal(&handle).map_err(classify_query_journal_error)?;

        let oldest = read_first_timestamp(&handle, &journal);
        let mut out = scan_recent_events(volume, &handle, &journal)?;
        out.oldest = oldest.or(out.oldest);
        Ok(out)
    }

    fn classify_open_volume_error(error: WinError) -> DriveScanError {
        let code = win32_error_code(&error);
        match code {
            5 => {
                DriveScanError::permission(format!("open volume requires elevated rights: {error}"))
            }
            1 | 50 | 87 => DriveScanError::unsupported(format!("open volume unsupported: {error}")),
            _ => DriveScanError::other(format!("open volume failed: {error}")),
        }
    }

    fn classify_query_journal_error(error: WinError) -> DriveScanError {
        let code = win32_error_code(&error);
        match code {
            1 | 50 | 87 | 1179 => {
                DriveScanError::unsupported(format!("query journal unsupported: {error}"))
            }
            5 => DriveScanError::permission(format!(
                "query journal requires elevated rights: {error}"
            )),
            _ => DriveScanError::other(format!("query journal failed: {error}")),
        }
    }

    fn win32_error_code(error: &WinError) -> u32 {
        let hr = error.code().0 as u32;
        if (hr & 0xFFFF0000) == 0x80070000 {
            hr & 0xFFFF
        } else {
            hr
        }
    }

    fn scan_recent_events(
        volume: &VolumeInfo,
        handle: &VolumeHandle,
        journal: &USN_JOURNAL_DATA_V0,
    ) -> Result<DriveScanOutput, DriveScanError> {
        let mut out = DriveScanOutput::default();
        let mut matched_minecraft = Vec::<RawUsnEvent>::new();

        let mut start = if journal.NextUsn - journal.FirstUsn > RECENT_USN_WINDOW {
            journal.NextUsn - RECENT_USN_WINDOW
        } else {
            journal.FirstUsn
        };
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        let mask = ReasonFlags::DATA_OVERWRITE
            | ReasonFlags::DATA_EXTEND
            | ReasonFlags::FILE_CREATE
            | ReasonFlags::FILE_DELETE
            | ReasonFlags::RENAME_NEW_NAME
            | ReasonFlags::RENAME_OLD_NAME
            | ReasonFlags::STREAM_CHANGE;

        let mut guard = 0usize;
        while start < journal.NextUsn && out.records_scanned < MAX_RECORDS_PER_DRIVE && guard < 2048
        {
            guard += 1;

            let params = READ_USN_JOURNAL_DATA_V0 {
                StartUsn: start,
                ReasonMask: u32::MAX,
                ReturnOnlyOnClose: 0,
                Timeout: 0,
                BytesToWaitFor: 0,
                UsnJournalID: journal.UsnJournalID,
            };

            let bytes = read_journal_chunk(handle, &params, &mut buffer)
                .map_err(classify_read_journal_error)?;
            if bytes <= 8 {
                break;
            }

            let (next_usn, records) =
                parse_usn_buffer(&buffer[..bytes as usize]).map_err(|error| {
                    DriveScanError::other(format!("parse usn buffer failed: {error}"))
                })?;
            if records.is_empty() {
                if next_usn as i64 <= start {
                    break;
                }
                start = next_usn as i64;
                continue;
            }

            for record in records {
                out.records_scanned += 1;
                out.oldest = Some(match out.oldest {
                    Some(current) => current.min(record.timestamp_utc),
                    None => record.timestamp_utc,
                });
                out.newest = Some(match out.newest {
                    Some(current) => current.max(record.timestamp_utc),
                    None => record.timestamp_utc,
                });

                if !record.reason.intersects(mask) {
                    continue;
                }

                let reason = describe_reason(record.reason).to_string();
                let lower_file_name = record.file_name.to_ascii_lowercase();

                if looks_like_minecraft_trace(&lower_file_name) {
                    matched_minecraft.push(RawUsnEvent {
                        parent_file_reference_number: frn_base(record.parent_file_reference_number),
                        timestamp_utc: record.timestamp_utc,
                        reason,
                        file_name: record.file_name,
                    });
                }

                if out.records_scanned >= MAX_RECORDS_PER_DRIVE {
                    break;
                }
            }

            if next_usn as i64 <= start {
                break;
            }
            start = next_usn as i64;
        }

        let needed_parents = matched_minecraft
            .iter()
            .map(|event| event.parent_file_reference_number)
            .filter(|value| *value != 0)
            .collect::<HashSet<_>>();

        let mft_resolve = if needed_parents.is_empty() {
            MftResolveResult::default()
        } else {
            match build_mft_index(handle, journal, &needed_parents) {
                Ok(resolve) => resolve,
                Err(error) => {
                    out.warnings.push(format!(
                        "USN {}: MFT index unavailable ({})",
                        volume.name,
                        error.message.trim()
                    ));
                    MftResolveResult::default()
                }
            }
        };

        out.last_deletion = mft_resolve.usn_journal_last_write_utc;

        let mut seen_minecraft = HashSet::<String>::new();
        for event in matched_minecraft {
            if out.minecraft_events.len() >= MAX_EVENTS_PER_CATEGORY {
                break;
            }
            let parent_path = resolve_parent_path(
                &volume.name,
                event.parent_file_reference_number,
                &mft_resolve.nodes,
            );
            let full_path = match parent_path {
                Some(parent) => format!("{parent}\\{}", event.file_name),
                None => format!("{}\\{}", volume.name, event.file_name),
            };
            let lower = full_path.to_ascii_lowercase();
            let timestamp = format_utc(event.timestamp_utc);
            let key = format!("{lower}|{}|{timestamp}", event.reason);
            if seen_minecraft.insert(key) {
                out.minecraft_events.push(UsnEvent {
                    drive: volume.name.clone(),
                    path: full_path,
                    reason: event.reason,
                    timestamp_utc: timestamp,
                });
            }
        }

        Ok(out)
    }

    fn build_mft_index(
        handle: &VolumeHandle,
        journal: &USN_JOURNAL_DATA_V0,
        needed_parent_frns: &HashSet<u64>,
    ) -> Result<MftResolveResult, DriveScanError> {
        if needed_parent_frns.is_empty() {
            return Ok(MftResolveResult::default());
        }

        let mut out = MftResolveResult::default();
        let mut pending = needed_parent_frns.clone();
        let mut start = 0u64;
        let mut guard = 0usize;
        let mut buffer = vec![0u8; MFT_ENUM_BUFFER_SIZE];

        while guard < MAX_MFT_ENUM_GUARD {
            guard += 1;
            let params = MFT_ENUM_DATA_V0 {
                StartFileReferenceNumber: start,
                LowUsn: 0,
                HighUsn: journal.NextUsn,
            };
            let bytes = match read_mft_chunk(handle, &params, &mut buffer) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let code = win32_error_code(&error);
                    // End of MFT enumeration is expected.
                    if code == 38 || code == 259 {
                        break;
                    }
                    if out.nodes.is_empty() {
                        return Err(classify_enum_mft_error(error));
                    }
                    break;
                }
            };
            if bytes <= 8 {
                break;
            }

            let (next_reference, records) =
                parse_usn_buffer(&buffer[..bytes as usize]).map_err(|error| {
                    DriveScanError::other(format!("parse mft buffer failed: {error}"))
                })?;

            for record in records {
                let record_key = frn_base(record.file_reference_number);
                let parent_key = frn_base(record.parent_file_reference_number);
                let is_directory = (record.file_attributes & FILE_ATTRIBUTE_DIRECTORY.0)
                    == FILE_ATTRIBUTE_DIRECTORY.0;
                let is_extend = record.file_name.eq_ignore_ascii_case("$extend");
                let is_usn_journal = record.file_name.eq_ignore_ascii_case("$usnjrnl");
                let is_needed = pending.contains(&record_key);

                if is_directory || is_needed || is_extend || is_usn_journal {
                    out.nodes.entry(record_key).or_insert(MftNode {
                        file_reference_number: record.file_reference_number,
                        parent_file_reference_number: parent_key,
                        name: record.file_name.clone(),
                    });
                }

                if pending.remove(&record_key)
                    && parent_key != 0
                    && parent_key != record_key
                    && !out.nodes.contains_key(&parent_key)
                {
                    pending.insert(parent_key);
                }
            }

            if next_reference <= start {
                break;
            }
            start = next_reference;
            if pending.is_empty() && locate_usn_journal_frn(&out.nodes).is_some() {
                break;
            }
        }

        if let Some(usn_frn) = locate_usn_journal_frn(&out.nodes) {
            out.usn_journal_last_write_utc = read_file_record_modified_time(handle, usn_frn);
        }

        Ok(out)
    }

    fn locate_usn_journal_frn(nodes: &HashMap<u64, MftNode>) -> Option<u64> {
        let extend_frn = nodes
            .iter()
            .find_map(|(frn, node)| node.name.eq_ignore_ascii_case("$extend").then_some(*frn));

        nodes.iter().find_map(|(_frn, node)| {
            if !node.name.eq_ignore_ascii_case("$usnjrnl") {
                return None;
            }
            if let Some(extend) = extend_frn {
                if node.parent_file_reference_number != extend {
                    return None;
                }
            }
            Some(node.file_reference_number)
        })
    }

    fn resolve_parent_path(
        drive: &str,
        parent_file_reference_number: u64,
        nodes: &HashMap<u64, MftNode>,
    ) -> Option<String> {
        if parent_file_reference_number == 0 {
            return Some(drive.to_string());
        }

        let mut current = parent_file_reference_number;
        let mut segments = Vec::<String>::new();
        let mut guard = 0usize;

        while guard < 256 {
            guard += 1;
            let Some(node) = nodes.get(&current) else {
                break;
            };

            let name = node.name.trim();
            if name.is_empty() || name == "\\" {
                break;
            }
            segments.push(name.to_string());

            if node.parent_file_reference_number == 0
                || node.parent_file_reference_number == current
            {
                break;
            }
            current = node.parent_file_reference_number;
        }

        if segments.is_empty() {
            return None;
        }

        segments.reverse();
        let mut path = drive.to_string();
        for segment in segments {
            path.push('\\');
            path.push_str(&segment);
        }
        Some(path)
    }

    fn read_mft_chunk(
        handle: &VolumeHandle,
        params: &MFT_ENUM_DATA_V0,
        buffer: &mut [u8],
    ) -> Result<u32, WinError> {
        let mut bytes = 0u32;
        unsafe {
            DeviceIoControl(
                handle.raw,
                FSCTL_ENUM_USN_DATA,
                Some(params as *const _ as *const c_void),
                mem::size_of::<MFT_ENUM_DATA_V0>() as u32,
                Some(buffer.as_mut_ptr() as *mut c_void),
                buffer.len() as u32,
                Some(&mut bytes),
                None,
            )
        }?;

        Ok(bytes)
    }

    fn classify_enum_mft_error(error: WinError) -> DriveScanError {
        let code = win32_error_code(&error);
        match code {
            5 => DriveScanError::permission(format!("enum mft requires elevated rights: {error}")),
            1 | 50 | 87 | 1179 => {
                DriveScanError::unsupported(format!("enum mft unsupported: {error}"))
            }
            _ => DriveScanError::other(format!("enum mft failed: {error}")),
        }
    }

    fn read_file_record_modified_time(handle: &VolumeHandle, frn: u64) -> Option<DateTime<Utc>> {
        let input = NTFS_FILE_RECORD_INPUT_BUFFER {
            FileReferenceNumber: frn as i64,
        };
        let mut buffer = vec![0u8; NTFS_FILE_RECORD_BUFFER_SIZE];
        let mut bytes = 0u32;
        let result = unsafe {
            DeviceIoControl(
                handle.raw,
                FSCTL_GET_NTFS_FILE_RECORD,
                Some(&input as *const _ as *const c_void),
                mem::size_of::<NTFS_FILE_RECORD_INPUT_BUFFER>() as u32,
                Some(buffer.as_mut_ptr() as *mut c_void),
                buffer.len() as u32,
                Some(&mut bytes),
                None,
            )
        };
        if result.is_err() {
            return None;
        }

        let used = bytes as usize;
        if used < 12 {
            return None;
        }
        let file_record_length = read_u32(&buffer[8..12]) as usize;
        let record_start = 12usize;
        let record_end = record_start.saturating_add(file_record_length).min(used);
        if record_end <= record_start {
            return None;
        }

        parse_standard_info_modified_time(&buffer[record_start..record_end])
    }

    fn parse_standard_info_modified_time(record: &[u8]) -> Option<DateTime<Utc>> {
        if record.len() < 24 {
            return None;
        }
        let first_attr_offset = read_u16(&record[20..22]) as usize;
        if first_attr_offset >= record.len() {
            return None;
        }

        let mut offset = first_attr_offset;
        while offset + 16 <= record.len() {
            let attr_type = read_u32(&record[offset..offset + 4]);
            if attr_type == 0xFFFF_FFFF {
                break;
            }
            let attr_length = read_u32(&record[offset + 4..offset + 8]) as usize;
            if attr_length < 16 || offset + attr_length > record.len() {
                break;
            }

            let non_resident = record[offset + 8];
            if attr_type == 0x10 && non_resident == 0 {
                if offset + 24 > record.len() {
                    break;
                }
                let value_length = read_u32(&record[offset + 16..offset + 20]) as usize;
                let value_offset = read_u16(&record[offset + 20..offset + 22]) as usize;
                let value_start = offset + value_offset;
                let value_end = value_start.saturating_add(value_length);
                if value_length >= 16 && value_end <= record.len() {
                    let modified_raw = read_i64(&record[value_start + 8..value_start + 16]);
                    return Some(filetime_to_datetime(modified_raw));
                }
                break;
            }

            offset += attr_length;
        }

        None
    }

    fn classify_read_journal_error(error: WinError) -> DriveScanError {
        let code = win32_error_code(&error);
        match code {
            5 => DriveScanError::permission(format!(
                "read journal requires elevated rights: {error}"
            )),
            1 | 50 | 87 | 1179 => {
                DriveScanError::unsupported(format!("read journal unsupported: {error}"))
            }
            _ => DriveScanError::other(format!("read journal failed: {error}")),
        }
    }

    fn read_first_timestamp(
        handle: &VolumeHandle,
        journal: &USN_JOURNAL_DATA_V0,
    ) -> Option<DateTime<Utc>> {
        let mut buffer = vec![0u8; READ_BUFFER_SIZE.min(128 * 1024)];
        let params = READ_USN_JOURNAL_DATA_V0 {
            StartUsn: journal.FirstUsn,
            ReasonMask: u32::MAX,
            ReturnOnlyOnClose: 0,
            Timeout: 0,
            BytesToWaitFor: 0,
            UsnJournalID: journal.UsnJournalID,
        };
        let bytes = read_journal_chunk(handle, &params, &mut buffer).ok()?;
        if bytes <= 8 {
            return None;
        }
        let (_, records) = parse_usn_buffer(&buffer[..bytes as usize]).ok()?;
        records.first().map(|record| record.timestamp_utc)
    }

    fn describe_reason(flags: ReasonFlags) -> &'static str {
        if flags.contains(ReasonFlags::FILE_DELETE) {
            "deleted"
        } else if flags.contains(ReasonFlags::RENAME_NEW_NAME)
            || flags.contains(ReasonFlags::RENAME_OLD_NAME)
        {
            "renamed"
        } else if flags.contains(ReasonFlags::FILE_CREATE) {
            "created"
        } else if flags.contains(ReasonFlags::DATA_OVERWRITE) {
            "overwrite"
        } else if flags.contains(ReasonFlags::DATA_EXTEND) {
            "extend"
        } else if flags.contains(ReasonFlags::STREAM_CHANGE) {
            "stream_change"
        } else {
            "changed"
        }
    }

    fn looks_like_minecraft_trace(path: &str) -> bool {
        let file = usn_file_name(path);
        is_minecraft_usn_log_name(file)
    }

    fn usn_file_name(path: &str) -> &str {
        path.rsplit(['\\', '/']).next().unwrap_or(path)
    }

    pub(super) fn is_minecraft_usn_log_name(file_name: &str) -> bool {
        let lower = file_name.to_ascii_lowercase();
        lower == "latest.log"
            || lower == "debug.log"
            || minecraft_rotated_log_name(&lower)
            || is_minecraft_dated_log_name(&lower)
    }

    fn minecraft_rotated_log_name(file_name_lower: &str) -> bool {
        if let Some(suffix) = file_name_lower.strip_prefix("latest.log.") {
            return !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit());
        }
        if let Some(suffix) = file_name_lower.strip_prefix("debug.log.") {
            return !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit());
        }
        false
    }

    pub(super) fn is_minecraft_dated_log_name(file_name: &str) -> bool {
        let lower = file_name.to_ascii_lowercase();
        if let Some(stem) = lower.strip_suffix(".log.gz") {
            return is_minecraft_dated_log_stem(stem);
        }
        if let Some(stem) = lower.strip_suffix(".log") {
            return is_minecraft_dated_log_stem(stem);
        }
        false
    }

    fn is_minecraft_dated_log_stem(stem: &str) -> bool {
        let mut parts = stem.split('-');
        let (Some(year), Some(month), Some(day), Some(index), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return false;
        };

        year.len() == 4
            && month.len() == 2
            && day.len() == 2
            && !index.is_empty()
            && year.chars().all(|ch| ch.is_ascii_digit())
            && month.chars().all(|ch| ch.is_ascii_digit())
            && day.chars().all(|ch| ch.is_ascii_digit())
            && index.chars().all(|ch| ch.is_ascii_digit())
    }

    fn format_utc(value: DateTime<Utc>) -> String {
        value
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    fn format_utc_date(value: DateTime<Utc>) -> String {
        value.with_timezone(&Local).format("%Y-%m-%d").to_string()
    }

    fn humanize_age_since(value: DateTime<Utc>) -> String {
        let delta = Utc::now().signed_duration_since(value);
        if delta.num_seconds() <= 30 {
            return "только что".to_string();
        }

        let total_minutes = delta.num_minutes().max(0);
        let days = total_minutes / (24 * 60);
        let hours = (total_minutes % (24 * 60)) / 60;
        let minutes = total_minutes % 60;

        if days > 0 {
            return format!("{days} д {hours} ч {minutes} мин назад");
        }
        if hours > 0 {
            return format!("{hours} ч {minutes} мин назад");
        }
        format!("{minutes} мин назад")
    }

    fn enumerate_ntfs_volumes() -> Result<Vec<VolumeInfo>, String> {
        let mut buffer = vec![0u16; 512];
        let mut needed = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) } as usize;
        if needed == 0 {
            return Err(format!(
                "GetLogicalDriveStringsW failed: {}",
                windows::core::Error::from_win32()
            ));
        }
        if needed > buffer.len() {
            buffer.resize(needed + 1, 0);
            needed = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) } as usize;
        }

        let mut volumes = Vec::new();
        let mut start = 0usize;
        while start < needed {
            let Some(end) = buffer[start..].iter().position(|value| *value == 0) else {
                break;
            };
            if end == 0 {
                break;
            }

            let root = String::from_utf16_lossy(&buffer[start..start + end]);
            if root.is_empty() {
                break;
            }

            let wide = to_wide_null(&root);
            let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };
            if drive_type == 0 || drive_type == 1 {
                start += end + 1;
                continue;
            }

            if is_ntfs(&wide)? {
                let name = root.trim_end_matches('\\').to_string();
                volumes.push(VolumeInfo {
                    device_path: format!(r"\\.\{}", name),
                    name,
                });
            }

            start += end + 1;
        }

        Ok(volumes)
    }

    fn is_ntfs(root_wide: &[u16]) -> Result<bool, String> {
        let mut fs_name = vec![0u16; 32];
        let mut serial = 0u32;
        let mut max_component = 0u32;
        let mut flags = 0u32;

        let result = unsafe {
            GetVolumeInformationW(
                PCWSTR(root_wide.as_ptr()),
                None,
                Some(&mut serial),
                Some(&mut max_component),
                Some(&mut flags),
                Some(fs_name.as_mut_slice()),
            )
        };

        if result.is_err() {
            return Ok(false);
        }

        let len = fs_name
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(fs_name.len());
        let fs = String::from_utf16_lossy(&fs_name[..len]);
        Ok(fs.eq_ignore_ascii_case("NTFS"))
    }

    fn open_volume(device_path: &str) -> Result<VolumeHandle, WinError> {
        let wide = to_wide_null(device_path);
        let attempts = [
            (GENERIC_READ.0, FILE_FLAGS_AND_ATTRIBUTES(0)),
            (FILE_READ_ATTRIBUTES.0, FILE_FLAG_BACKUP_SEMANTICS),
        ];

        let mut last_error = None::<WinError>;
        for (access, flags) in attempts {
            match unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    flags,
                    None,
                )
            } {
                Ok(handle) => return Ok(VolumeHandle { raw: handle }),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(WinError::from_win32))
    }

    fn query_journal(handle: &VolumeHandle) -> Result<USN_JOURNAL_DATA_V0, WinError> {
        let mut data = USN_JOURNAL_DATA_V0::default();
        let mut bytes = 0u32;
        unsafe {
            DeviceIoControl(
                handle.raw,
                FSCTL_QUERY_USN_JOURNAL,
                None,
                0,
                Some(&mut data as *mut _ as *mut c_void),
                mem::size_of::<USN_JOURNAL_DATA_V0>() as u32,
                Some(&mut bytes),
                None,
            )
        }?;

        Ok(data)
    }

    fn read_journal_chunk(
        handle: &VolumeHandle,
        params: &READ_USN_JOURNAL_DATA_V0,
        buffer: &mut [u8],
    ) -> Result<u32, WinError> {
        let mut bytes = 0u32;
        unsafe {
            DeviceIoControl(
                handle.raw,
                FSCTL_READ_USN_JOURNAL,
                Some(params as *const _ as *const c_void),
                mem::size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
                Some(buffer.as_mut_ptr() as *mut c_void),
                buffer.len() as u32,
                Some(&mut bytes),
                None,
            )
        }?;

        Ok(bytes)
    }

    fn to_wide_null(value: &str) -> Vec<u16> {
        let mut wide = value.encode_utf16().collect::<Vec<_>>();
        wide.push(0);
        wide
    }

    fn parse_usn_buffer(buffer: &[u8]) -> Result<(u64, Vec<ParsedUsnRecord>), String> {
        if buffer.len() < 8 {
            return Ok((0, Vec::new()));
        }

        let next_marker = read_u64(&buffer[0..8]);
        let mut offset = 8usize;
        let mut out = Vec::<ParsedUsnRecord>::new();

        while offset + 60 <= buffer.len() {
            let record_length = read_u32(&buffer[offset..offset + 4]) as usize;
            if record_length == 0 || offset + record_length > buffer.len() {
                break;
            }

            let major = read_u16(&buffer[offset + 4..offset + 6]);
            let (
                file_reference_offset,
                parent_reference_offset,
                timestamp_offset,
                reason_offset,
                file_attributes_offset,
                file_name_length_offset,
                file_name_offset_offset,
                id_length,
            ) = match major {
                2 => (
                    8usize, 16usize, 32usize, 40usize, 52usize, 56usize, 58usize, 8usize,
                ),
                3 => (
                    8usize, 24usize, 48usize, 56usize, 68usize, 72usize, 74usize, 16usize,
                ),
                _ => {
                    offset += record_length;
                    continue;
                }
            };

            let min_record_bytes = file_name_offset_offset + 2;
            if record_length < min_record_bytes || offset + min_record_bytes > buffer.len() {
                offset += record_length;
                continue;
            }

            let file_reference_number =
                read_file_reference_number(&buffer[offset + file_reference_offset..], id_length);
            let parent_file_reference_number =
                read_file_reference_number(&buffer[offset + parent_reference_offset..], id_length);
            let timestamp_raw =
                read_i64(&buffer[offset + timestamp_offset..offset + timestamp_offset + 8]);
            let reason = ReasonFlags::from_bits_truncate(read_u32(
                &buffer[offset + reason_offset..offset + reason_offset + 4],
            ));
            let file_attributes = read_u32(
                &buffer[offset + file_attributes_offset..offset + file_attributes_offset + 4],
            );
            let file_name_length = read_u16(
                &buffer[offset + file_name_length_offset..offset + file_name_length_offset + 2],
            ) as usize;
            let file_name_offset = read_u16(
                &buffer[offset + file_name_offset_offset..offset + file_name_offset_offset + 2],
            ) as usize;
            let name_start = offset + file_name_offset;
            let name_end = name_start.saturating_add(file_name_length);
            if name_end > buffer.len() {
                break;
            }

            let file_name = wide_to_string(&buffer[name_start..name_end])
                .unwrap_or_else(|| "<unknown>".to_string());

            out.push(ParsedUsnRecord {
                file_reference_number,
                parent_file_reference_number,
                timestamp_utc: filetime_to_datetime(timestamp_raw),
                reason,
                file_attributes,
                file_name,
            });

            offset += record_length;
        }

        Ok((next_marker, out))
    }

    fn read_file_reference_number(bytes: &[u8], id_length: usize) -> u64 {
        if bytes.len() < 8 {
            return 0;
        }
        if id_length == 8 {
            return read_u64(bytes);
        }
        // USN v3 keeps FILE_ID_128. For NTFS volumes we use the low 64 bits.
        read_u64(bytes)
    }

    fn frn_base(value: u64) -> u64 {
        value & 0x0000_FFFF_FFFF_FFFF
    }

    fn read_u16(bytes: &[u8]) -> u16 {
        let mut out = [0u8; 2];
        out.copy_from_slice(&bytes[0..2]);
        u16::from_le_bytes(out)
    }

    fn read_u32(bytes: &[u8]) -> u32 {
        let mut out = [0u8; 4];
        out.copy_from_slice(&bytes[0..4]);
        u32::from_le_bytes(out)
    }

    fn read_u64(bytes: &[u8]) -> u64 {
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes[0..8]);
        u64::from_le_bytes(out)
    }

    fn read_i64(bytes: &[u8]) -> i64 {
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes[0..8]);
        i64::from_le_bytes(out)
    }

    fn wide_to_string(bytes: &[u8]) -> Option<String> {
        if bytes.len() % 2 != 0 {
            return None;
        }
        let utf16 = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&utf16).ok()
    }

    fn filetime_to_datetime(filetime: i64) -> DateTime<Utc> {
        const WINDOWS_TO_UNIX_SECONDS: i64 = 11_644_473_600;
        let secs = filetime / 10_000_000;
        let nanos = ((filetime % 10_000_000) * 100).max(0) as u32;
        let unix_secs = secs.saturating_sub(WINDOWS_TO_UNIX_SECONDS);
        DateTime::<Utc>::from_timestamp(unix_secs, nanos)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("unix epoch exists"))
    }
}
