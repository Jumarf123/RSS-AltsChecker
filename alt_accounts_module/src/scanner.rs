use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::Result;
use flate2::read::GzDecoder;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use walkdir::WalkDir;

use crate::logging;

#[derive(Clone, Debug, Deserialize)]
struct MinecraftReport {
    minecraft: Vec<MinecraftProcEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct MinecraftProcEntry {
    is_minecraft: bool,
    game_dir: String,
}

#[derive(Clone, Debug)]
pub struct AltAccount {
    pub name: String,
    pub source: String,
}

pub fn detect_alt_accounts(output_dir: &Path) -> Vec<AltAccount> {
    let game_dirs = load_game_dirs(output_dir);
    if game_dirs.is_empty() {
        return Vec::new();
    }

    let mut seen = HashSet::new();
    let mut results = Vec::new();

    let patterns = build_regexes();

    for dir in game_dirs {
        scan_logs(&dir, &patterns, &mut seen, &mut results);
        scan_jsons(&dir, &mut seen, &mut results);
    }

    results
}

fn load_game_dirs(output_dir: &Path) -> Vec<PathBuf> {
    let path = output_dir.join("minecraft_detector.json");
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(_) => return Vec::new(),
    };
    let report: MinecraftReport = match serde_json::from_str(&contents) {
        Ok(report) => report,
        Err(_) => return Vec::new(),
    };

    let mut dirs = HashSet::new();
    for proc in report.minecraft {
        if !proc.is_minecraft {
            continue;
        }
        let game_dir = PathBuf::from(proc.game_dir);
        if game_dir.is_dir() {
            dirs.insert(game_dir.clone());
            if let Some(parent) = game_dir.parent() {
                if game_dir.file_name().and_then(|s| s.to_str()).unwrap_or("").eq_ignore_ascii_case("game") {
                    dirs.insert(parent.to_path_buf());
                }
            }
            let laby = game_dir.join("LabyMod");
            if laby.is_dir() {
                dirs.insert(laby);
            }
        }
    }

    dirs.into_iter().collect()
}

fn build_regexes() -> Vec<Regex> {
    vec![
        Regex::new(r"\[\d{2}:\d{2}:\d{2}\] \[Client thread/INFO\]: Setting user: (\S+)").unwrap(),
        Regex::new(r"\[LC\] Setting user: (\S+)").unwrap(),
        Regex::new(r"\[Authenticator\] Creating Minecraft session for (\S+)").unwrap(),
        Regex::new(r"displayName=([^\s,]+)").unwrap(),
    ]
}

fn scan_logs(base: &Path, patterns: &[Regex], seen: &mut HashSet<String>, out: &mut Vec<AltAccount>) {
    let logs_dir = base.join("logs");
    if !logs_dir.is_dir() {
        return;
    }

    let entries = match fs::read_dir(&logs_dir) {
        Ok(entries) => entries,
        Err(err) => {
            logging::log_error(&format!("alts: read logs dir failed: {err}"));
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        if !(name.ends_with(".log") || name.ends_with(".log.gz") || name.ends_with(".gz")) {
            continue;
        }

        if name.ends_with(".gz") {
            if let Err(err) = scan_gzip_file(&path, patterns, seen, out) {
                logging::log_error(&format!("alts: scan gzip failed {}: {err}", path.display()));
            }
        } else if let Err(err) = scan_text_file(&path, patterns, seen, out) {
            logging::log_error(&format!("alts: scan log failed {}: {err}", path.display()));
        }
    }
}

fn scan_text_file(path: &Path, patterns: &[Regex], seen: &mut HashSet<String>, out: &mut Vec<AltAccount>) -> Result<()> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.unwrap_or_default();
        extract_from_line(&line, patterns, seen, out, path);
    }
    Ok(())
}

fn scan_gzip_file(path: &Path, patterns: &[Regex], seen: &mut HashSet<String>, out: &mut Vec<AltAccount>) -> Result<()> {
    let file = fs::File::open(path)?;
    let decoder = GzDecoder::new(file);
    let reader = BufReader::new(decoder);
    for line in reader.lines() {
        let line = line.unwrap_or_default();
        extract_from_line(&line, patterns, seen, out, path);
    }
    Ok(())
}

fn extract_from_line(line: &str, patterns: &[Regex], seen: &mut HashSet<String>, out: &mut Vec<AltAccount>, source: &Path) {
    for re in patterns {
        if let Some(caps) = re.captures(line) {
            if let Some(name) = caps.get(1).map(|m| m.as_str().to_string()) {
                if let Some(clean) = normalize_username(&name) {
                    if seen.insert(clean.to_ascii_lowercase()) {
                        out.push(AltAccount {
                            name: clean,
                            source: source.to_string_lossy().to_string(),
                        });
                    }
                }
            }
        }
    }
}

fn scan_jsons(base: &Path, seen: &mut HashSet<String>, out: &mut Vec<AltAccount>) {
    for entry in WalkDir::new(base).max_depth(6).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("json") {
            continue;
        }
        if should_skip_json(path) {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                logging::log_error(&format!("alts: read json failed {}: {err}", path.display()));
                continue;
            }
        };
        let value: Value = match serde_json::from_str(&content) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let mut names = Vec::new();
        collect_names_from_json(&value, &mut names);
        for name in names {
            if let Some(clean) = normalize_username(&name) {
                if seen.insert(clean.to_ascii_lowercase()) {
                    out.push(AltAccount {
                        name: clean,
                        source: path.to_string_lossy().to_string(),
                    });
                }
            }
        }
    }
}

fn should_skip_json(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("\\versions\\") {
        return true;
    }
    let file = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
    if file.contains("fabric") && file.contains(".json") {
        return true;
    }
    false
}

fn collect_names_from_json(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let key_lower = key.to_ascii_lowercase();
                if matches!(key_lower.as_str(), "username" | "name" | "displayname") {
                    if let Value::String(s) = val {
                        out.push(s.to_string());
                    }
                }
                collect_names_from_json(val, out);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_names_from_json(v, out);
            }
        }
        _ => {}
    }
}

fn normalize_username(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'').trim_matches(',');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() < 3 || trimmed.len() > 32 {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some(trimmed.to_string())
    } else {
        None
    }
}
