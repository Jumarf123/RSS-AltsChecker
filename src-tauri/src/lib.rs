mod scanner;
mod usn_journal;
#[allow(dead_code)]
mod viewer;

use scanner::{ScanOptions, ScanReport, SteamCheckReport, SystemHwid};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tauri::Manager;

#[derive(Debug, Default)]
struct AppState {
    event_log: Mutex<Vec<String>>,
}

#[tauri::command]
async fn scan_alts(state: tauri::State<'_, AppState>) -> Result<ScanReport, String> {
    push_event(&state, "Запущен Alts Check");
    let report = tauri::async_runtime::spawn_blocking(move || {
        let options = ScanOptions {
            cancel_flag: Some(Arc::new(AtomicBool::new(false))),
            ..ScanOptions::default()
        };
        scanner::run_scan(&options)
    })
    .await
    .map_err(|error| error.to_string())??;
    push_event(
        &state,
        format!(
            "Alts Check завершен: Minecraft {}, Discord {}",
            report.minecraft_accounts.len(),
            report.discord_accounts.len()
        ),
    );
    for signal in &report.audit.signals {
        push_event(&state, signal.clone());
    }
    Ok(report)
}

#[tauri::command]
async fn scan_steam(state: tauri::State<'_, AppState>) -> Result<SteamCheckReport, String> {
    push_event(&state, "Запущен Steam Check");
    let report = tauri::async_runtime::spawn_blocking(move || {
        let options = ScanOptions {
            cancel_flag: Some(Arc::new(AtomicBool::new(false))),
            ..ScanOptions::default()
        };
        scanner::run_steam_check(&options)
    })
    .await
    .map_err(|error| error.to_string())??;
    push_event(
        &state,
        format!("Steam Check завершен: {}", report.steam_accounts.len()),
    );
    for signal in &report.audit.signals {
        push_event(&state, signal.clone());
    }
    Ok(report)
}

#[tauri::command]
async fn get_hwid(state: tauri::State<'_, AppState>) -> Result<SystemHwid, String> {
    let hwid = tauri::async_runtime::spawn_blocking(scanner::collect_system_hwid)
        .await
        .map_err(|error| error.to_string())?;
    push_event(&state, format!("HWID: {}", hwid.primary_hwid));
    Ok(hwid)
}

#[tauri::command]
fn open_external_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    tauri_plugin_opener::OpenerExt::opener(&app)
        .open_url(url, None::<String>)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn reanalyse_third_party(steam_id64: String) -> Vec<scanner::ThirdPartyCheck> {
    scanner::build_third_party_checks(&steam_id64)
}

#[tauri::command]
fn window_minimize(window: tauri::Window) -> Result<(), String> {
    window.minimize().map_err(|error| error.to_string())
}

#[tauri::command]
fn window_toggle_maximize(window: tauri::Window) -> Result<(), String> {
    let is_maximized = window.is_maximized().map_err(|error| error.to_string())?;
    if is_maximized {
        window.unmaximize().map_err(|error| error.to_string())
    } else {
        window.maximize().map_err(|error| error.to_string())
    }
}

#[tauri::command]
fn window_close(window: tauri::Window) -> Result<(), String> {
    window.close().map_err(|error| error.to_string())
}

fn push_event(state: &tauri::State<'_, AppState>, message: impl Into<String>) {
    let line = format!(
        "{}  {}",
        chrono::Local::now().format("%H:%M:%S"),
        message.into()
    );
    if let Ok(mut events) = state.event_log.lock() {
        events.push(line);
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            let state = app.state::<AppState>();
            push_event(&state, "Приложение запущено");
            let audit = scanner::startup_audit_check();
            for signal in &audit.signals {
                push_event(&state, signal.clone());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan_alts,
            scan_steam,
            get_hwid,
            open_external_url,
            reanalyse_third_party,
            window_minimize,
            window_toggle_maximize,
            window_close
        ])
        .run(tauri::generate_context!())
        .expect("error while running RSS-AltsChecker");
}
