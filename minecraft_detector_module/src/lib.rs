use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::path::PathBuf;

use serde::Serialize;

mod logging;
mod privilege;
mod detect;

#[derive(Clone, Debug, Serialize)]
struct ModuleDetection {
    category: String,
    name: String,
    source: String,
}

#[derive(Debug, Serialize)]
struct ModuleReport {
    module: String,
    detections: Vec<ModuleDetection>,
    minecraft: Vec<detect::MinecraftProcessInfo>,
}

#[unsafe(no_mangle)]
pub extern "C" fn module_name() -> *const c_char {
    static NAME: &[u8] = b"minecraft_detector\0";
    NAME.as_ptr() as *const c_char
}

#[unsafe(no_mangle)]
pub extern "C" fn module_run(output_dir: *const c_char) -> i32 {
    let output_dir = unsafe { cstr_to_path(output_dir) }
        .unwrap_or_else(|| default_output_dir());

    if let Err(err) = fs::create_dir_all(&output_dir) {
        logging::log_error(&format!("Failed to create output directory: {err}"));
        return 1;
    }

    if let Err(err) = privilege::enable_debug_privilege() {
        logging::log_error(&format!("Enable SeDebugPrivilege failed: {err}"));
    }

    let report = match std::panic::catch_unwind(|| detect::scan_minecraft_processes()) {
        Ok(Ok(minecraft)) => ModuleReport {
            module: "minecraft_detector".to_string(),
            detections: Vec::new(),
            minecraft,
        },
        Ok(Err(err)) => {
            logging::log_error(&format!("Minecraft scan failed: {err}"));
            ModuleReport {
                module: "minecraft_detector".to_string(),
                detections: Vec::new(),
                minecraft: Vec::new(),
            }
        }
        Err(_) => {
            logging::log_error("Minecraft scan panicked");
            ModuleReport {
                module: "minecraft_detector".to_string(),
                detections: Vec::new(),
                minecraft: Vec::new(),
            }
        }
    };

    let output_path = output_dir.join("minecraft_detector.json");
    if let Err(err) = fs::write(&output_path, serde_json::to_string_pretty(&report).unwrap_or_default()) {
        logging::log_error(&format!("Failed to write module report: {err}"));
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
