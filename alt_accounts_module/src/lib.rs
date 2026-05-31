use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::path::PathBuf;

use serde::Serialize;

mod logging;
mod scanner;

#[derive(Clone, Debug, Serialize)]
struct ModuleDetection {
    category: String,
    name: String,
    source: String,
}

#[derive(Clone, Debug, Serialize)]
struct AltAccountEntry {
    name: String,
    source: String,
}

#[derive(Debug, Serialize)]
struct ModuleReport {
    module: String,
    detections: Vec<ModuleDetection>,
    accounts: Vec<AltAccountEntry>,
}

#[unsafe(no_mangle)]
pub extern "C" fn module_name() -> *const c_char {
    static NAME: &[u8] = b"alts\0";
    NAME.as_ptr() as *const c_char
}

#[unsafe(no_mangle)]
pub extern "C" fn module_run(output_dir: *const c_char) -> i32 {
    let output_dir = unsafe { cstr_to_path(output_dir) }.unwrap_or_else(|| default_output_dir());

    if let Err(err) = fs::create_dir_all(&output_dir) {
        logging::log_error(&format!("alts: create output dir failed: {err}"));
        return 1;
    }

    let accounts = scanner::detect_alt_accounts(&output_dir)
        .into_iter()
        .map(|entry| AltAccountEntry {
            name: entry.name,
            source: entry.source,
        })
        .collect::<Vec<_>>();

    let report = ModuleReport {
        module: "alts".to_string(),
        detections: Vec::new(),
        accounts,
    };

    let output_path = output_dir.join("alts.json");
    if let Err(err) = fs::write(&output_path, serde_json::to_string_pretty(&report).unwrap_or_default()) {
        logging::log_error(&format!("alts: write report failed: {err}"));
        return 2;
    }

    0
}

unsafe fn cstr_to_path(ptr: *const c_char) -> Option<PathBuf> {
    if ptr.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr.to_str().ok()?;
    Some(PathBuf::from(s))
}

fn default_output_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("output")
}
