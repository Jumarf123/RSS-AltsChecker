#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "windows")]
    {
        if !webview2_guard::ensure_runtime_or_open_installer() {
            return;
        }
    }

    rss_altschecker_lib::run();
}

#[cfg(target_os = "windows")]
mod webview2_guard {
    use std::path::PathBuf;
    use windows::core::PCWSTR;
    use windows::Win32::UI::Controls::{
        TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TDF_SIZE_TO_CONTENT,
    };
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDOK, MB_ICONWARNING, MB_OKCANCEL, SW_SHOWNORMAL,
    };
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    const WEBVIEW2_GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    const WEBVIEW2_DOWNLOAD_URL: &str =
        "https://developer.microsoft.com/en-us/microsoft-edge/webview2/#download-section";
    const INSTALL_BUTTON_ID: i32 = 1001;
    const CLOSE_BUTTON_ID: i32 = 1002;

    pub fn ensure_runtime_or_open_installer() -> bool {
        if is_webview2_runtime_installed() {
            return true;
        }

        if show_install_prompt() {
            open_download_page();
        }

        false
    }

    fn is_webview2_runtime_installed() -> bool {
        registry_runtime_version_exists() || edge_webview_executable_exists()
    }

    fn registry_runtime_version_exists() -> bool {
        let registry_locations = [
            (
                HKEY_CURRENT_USER,
                format!(r"Software\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_GUID}"),
            ),
            (
                HKEY_LOCAL_MACHINE,
                format!(r"Software\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_GUID}"),
            ),
            (
                HKEY_LOCAL_MACHINE,
                format!(r"Software\WOW6432Node\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_GUID}"),
            ),
        ];

        registry_locations.iter().any(|(hive, path)| {
            RegKey::predef(*hive)
                .open_subkey(path)
                .ok()
                .and_then(|key| key.get_value::<String, _>("pv").ok())
                .is_some_and(|version| {
                    let version = version.trim();
                    !version.is_empty() && version != "0.0.0.0"
                })
        })
    }

    fn edge_webview_executable_exists() -> bool {
        candidate_edge_webview_dirs().into_iter().any(|root| {
            let app_dir = root.join(r"Microsoft\EdgeWebView\Application");
            std::fs::read_dir(app_dir).is_ok_and(|entries| {
                entries
                    .filter_map(Result::ok)
                    .any(|entry| entry.path().join("msedgewebview2.exe").is_file())
            })
        })
    }

    fn candidate_edge_webview_dirs() -> Vec<PathBuf> {
        ["ProgramFiles(x86)", "ProgramFiles"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect()
    }

    fn show_install_prompt() -> bool {
        let title = wide("RSS-AltsChecker");
        let instruction = wide("Microsoft Edge WebView2 Runtime не установлен");
        let content = wide(
            "RSS-AltsChecker использует WebView2 для интерфейса. Нажмите «Установить», \
             скачайте Evergreen Runtime с официального сайта Microsoft и после установки \
             запустите программу снова.",
        );
        let install = wide("Установить");
        let close = wide("Закрыть");
        let buttons = [
            TASKDIALOG_BUTTON {
                nButtonID: INSTALL_BUTTON_ID,
                pszButtonText: PCWSTR(install.as_ptr()),
            },
            TASKDIALOG_BUTTON {
                nButtonID: CLOSE_BUTTON_ID,
                pszButtonText: PCWSTR(close.as_ptr()),
            },
        ];

        let config = TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            dwFlags: TDF_SIZE_TO_CONTENT,
            pszWindowTitle: PCWSTR(title.as_ptr()),
            pszMainInstruction: PCWSTR(instruction.as_ptr()),
            pszContent: PCWSTR(content.as_ptr()),
            cButtons: buttons.len() as u32,
            pButtons: buttons.as_ptr(),
            nDefaultButton: INSTALL_BUTTON_ID,
            ..Default::default()
        };

        let mut selected_button = CLOSE_BUTTON_ID;
        let dialog_result =
            unsafe { TaskDialogIndirect(&config, Some(&mut selected_button), None, None) };

        if dialog_result.is_ok() {
            return selected_button == INSTALL_BUTTON_ID;
        }

        show_fallback_message_box()
    }

    fn show_fallback_message_box() -> bool {
        let title = wide("RSS-AltsChecker");
        let message = wide(
            "Microsoft Edge WebView2 Runtime не установлен.\n\n\
             Нажмите OK, чтобы открыть официальный сайт Microsoft для установки. \
             После установки запустите RSS-AltsChecker снова.",
        );
        let result = unsafe {
            MessageBoxW(
                None,
                PCWSTR(message.as_ptr()),
                PCWSTR(title.as_ptr()),
                MB_OKCANCEL | MB_ICONWARNING,
            )
        };
        result == IDOK
    }

    fn open_download_page() {
        let verb = wide("open");
        let url = wide(WEBVIEW2_DOWNLOAD_URL);
        unsafe {
            let _ = ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(url.as_ptr()),
                None,
                None,
                SW_SHOWNORMAL,
            );
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}
