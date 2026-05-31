use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;
use sysinfo::{Process, System};

#[derive(Clone, Debug, Serialize)]
pub struct MinecraftProcessInfo {
    pub pid: u32,
    pub exe_path: String,
    pub cmdline: String,
    pub parent_pid: u32,
    pub parent_exe: String,
    pub is_minecraft: bool,
    pub mc_version: String,
    pub version_id: String,
    pub version_jar: String,
    pub loader: String,
    pub launcher: String,
    pub game_dir: String,
    pub mods_dir: String,
    pub mods: Vec<ModEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ModEntry {
    pub name: String,
    pub size_bytes: u64,
    pub path: String,
}

pub fn scan_minecraft_processes() -> Result<Vec<MinecraftProcessInfo>> {
    let mut system = System::new_all();
    system.refresh_processes();

    let mut results = Vec::new();
    for process in system.processes().values() {
        if !process.name().eq_ignore_ascii_case("javaw.exe") {
            continue;
        }
        let info = analyze_process(process, &system);
        results.push(info);
    }

    Ok(results)
}

fn analyze_process(process: &Process, system: &System) -> MinecraftProcessInfo {
    let pid = process.pid().as_u32();
    let exe_path = process
        .exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let cmd_args = process.cmd().to_vec();
    let cmdline = if cmd_args.is_empty() {
        process
            .name()
            .to_string()
    } else {
        cmd_args.join(" ")
    };
    let cmdline_lower = cmdline.to_ascii_lowercase();

    let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
    let parent_exe = process
        .parent()
        .and_then(|p| system.process(p))
        .and_then(|p| p.exe().map(|e| e.to_string_lossy().to_string()))
        .unwrap_or_else(|| "Unknown".to_string());

    let indicators = detect_indicators(&cmd_args, &cmdline_lower);
    let is_minecraft = indicators.is_minecraft;

    let game_dir = detect_game_dir(&cmd_args, &cmdline_lower);
    let version_id = detect_version_id(&cmd_args, &cmdline_lower, game_dir.as_ref());
    let version = if version_id != "Unknown" {
        extract_mc_version(&version_id).unwrap_or_else(|| version_id.clone())
    } else {
        "Unknown".to_string()
    };
    let loader = detect_loader(&cmd_args, &cmdline_lower);
    let launcher = detect_launcher(&cmd_args, &cmdline_lower, &parent_exe);
    let version_jar = detect_version_jar(&cmd_args, &cmdline_lower, game_dir.as_ref(), &version_id);
    let mods_dir = detect_mods_dir(&game_dir, &loader, &launcher, &version);
    let mods = if is_minecraft {
        collect_mods(&mods_dir)
    } else {
        Vec::new()
    };

    MinecraftProcessInfo {
        pid,
        exe_path,
        cmdline,
        parent_pid,
        parent_exe,
        is_minecraft,
        mc_version: if is_minecraft { version } else { "Unknown".to_string() },
        version_id: if is_minecraft { version_id } else { "Unknown".to_string() },
        version_jar: if is_minecraft { version_jar } else { "Unknown".to_string() },
        loader: if is_minecraft { loader } else { "Unknown".to_string() },
        launcher: if is_minecraft { launcher } else { "Unknown".to_string() },
        game_dir: if is_minecraft {
            game_dir.unwrap_or_else(|| "Unknown".to_string())
        } else {
            "Unknown".to_string()
        },
        mods_dir: if is_minecraft { mods_dir } else { "Unknown".to_string() },
        mods: if is_minecraft { mods } else { Vec::new() },
    }
}

struct Indicators {
    is_minecraft: bool,
}

fn detect_indicators(args: &[String], cmdline_lower: &str) -> Indicators {
    let has_game_dir = arg_value(args, "--gameDir").is_some() || property_value(args, "-Dminecraft.gamedir").is_some();
    let has_assets = arg_value(args, "--assetsDir").is_some() || arg_value(args, "--assetIndex").is_some();
    let has_version = arg_value(args, "--version").is_some();
    let has_uuid = arg_value(args, "--uuid").is_some();
    let has_token = arg_value(args, "--accessToken").is_some();
    let has_user = arg_value(args, "--userType").is_some();

    let main_classes = [
        "net.minecraft.client.main.main",
        "net.fabricmc.loader.impl.launch.knot.knotclient",
        "net.fabricmc.loader.launch.knot.knotclient",
        "cpw.mods.modlauncher.launcher",
        "net.minecraft.launchwrapper.launch",
    ];
    let has_main = main_classes.iter().any(|m| cmdline_lower.contains(m));

    let strong_a = has_game_dir && has_assets;
    let strong_b = has_version && (has_uuid || has_token || has_user);
    let strong_c = has_main;

    Indicators {
        is_minecraft: strong_a || strong_b || strong_c,
    }
}

fn detect_version_id(args: &[String], cmdline_lower: &str, game_dir: Option<&String>) -> String {
    if let Some(value) = arg_value(args, "--version") {
        return value;
    }

    if let Some(value) = arg_value(args, "--fml.mcVersion") {
        return value;
    }

    if let Some(classpath) = arg_value(args, "-cp").or_else(|| arg_value(args, "-classpath")) {
        if let Some(id) = extract_version_from_classpath(&classpath) {
            return id;
        }
    }

    if let Some(dir) = game_dir {
        if let Some(id) = extract_version_from_cmdline(cmdline_lower) {
            return id;
        }
        if let Some(version) = read_version_json(dir) {
            return version;
        }
    }

    "Unknown".to_string()
}

fn detect_version_jar(
    args: &[String],
    cmdline_lower: &str,
    game_dir: Option<&String>,
    version_id: &str,
) -> String {
    if let Some(classpath) = arg_value(args, "-cp").or_else(|| arg_value(args, "-classpath")) {
        if let Some(path) = extract_version_jar_from_classpath(&classpath) {
            return path;
        }
    }

    if let Some(dir) = game_dir {
        if version_id != "Unknown" {
            let jar = Path::new(dir)
                .join("versions")
                .join(version_id)
                .join(format!("{version_id}.jar"));
            if jar.is_file() {
                return jar.to_string_lossy().to_string();
            }
        }
        if let Some(path) = extract_version_jar_from_cmdline(cmdline_lower) {
            return path;
        }
    }

    "Unknown".to_string()
}

fn detect_loader(args: &[String], cmdline_lower: &str) -> String {
    if cmdline_lower.contains("laby") || cmdline_lower.contains("labymod") {
        return "LabyMod".to_string();
    }
    if cmdline_lower.contains("fabric-loader") || cmdline_lower.contains("net.fabricmc") || cmdline_lower.contains("knotclient") {
        return "Fabric".to_string();
    }
    if cmdline_lower.contains("forge") || cmdline_lower.contains("fml") || cmdline_lower.contains("modlauncher") {
        return "Forge".to_string();
    }
    if cmdline_lower.contains("quilt") {
        return "Quilt".to_string();
    }

    if cmdline_lower.contains("net.minecraft.client.main.main") {
        return "Vanilla".to_string();
    }

    if args.iter().any(|a| a.contains("ForgeTweaker") || a.contains("FMLTweaker")) {
        return "Forge".to_string();
    }

    "Unknown".to_string()
}

fn detect_launcher(args: &[String], cmdline_lower: &str, parent_exe: &str) -> String {
    if let Some(value) = property_value(args, "-Dminecraft.launcher.brand") {
        return normalize_launcher(&value);
    }

    let parent_lower = parent_exe.to_ascii_lowercase();
    let legacy_markers = [
        "legacylauncher",
        "\\.tlauncher\\legacy",
        "\\tlauncher\\legacy",
        "/.tlauncher/legacy",
        "/tlauncher/legacy",
    ];
    if legacy_markers
        .iter()
        .any(|m| parent_lower.contains(m) || cmdline_lower.contains(m))
    {
        return "Legacy".to_string();
    }
    if parent_lower.contains("tlauncher") || cmdline_lower.contains("tlauncher") {
        return "TLauncher".to_string();
    }
    if parent_lower.contains("modrinth") || cmdline_lower.contains("modrinthapp") {
        return "Modrinth".to_string();
    }
    if parent_lower.contains("lunar") || cmdline_lower.contains(".lunarclient") {
        return "Lunar".to_string();
    }
    if parent_lower.contains("labymod") || cmdline_lower.contains("labymod") {
        return "LabyMod".to_string();
    }
    if parent_lower.contains("minecraftlauncher") {
        return "Official".to_string();
    }

    "Unknown".to_string()
}

fn detect_game_dir(args: &[String], cmdline_lower: &str) -> Option<String> {
    if let Some(value) = arg_value(args, "--gameDir") {
        return Some(value);
    }
    if let Some(value) = property_value(args, "-Dminecraft.gamedir") {
        return Some(value);
    }

    if let Some(path) = extract_instance_path(cmdline_lower, "modrinthapp\\profiles\\") {
        return Some(path);
    }
    if let Some(path) = extract_instance_path(cmdline_lower, ".lunarclient\\profiles\\") {
        return Some(path);
    }
    if let Some(path) = extract_instance_path(cmdline_lower, ".tlauncher\\profiles\\") {
        return Some(path);
    }

    if let Some(appdata) = std::env::var_os("APPDATA") {
        let default = PathBuf::from(appdata).join(".minecraft");
        return Some(default.to_string_lossy().to_string());
    }

    None
}

fn detect_mods_dir(game_dir: &Option<String>, loader: &str, launcher: &str, version: &str) -> String {
    let Some(dir) = game_dir else {
        return "Not found".to_string();
    };
    let base = PathBuf::from(dir);

    let has_laby = loader.eq_ignore_ascii_case("LabyMod")
        || launcher.eq_ignore_ascii_case("LabyMod")
        || base.join("LabyMod").is_dir()
        || base.join(".laby").is_dir();
    if has_laby {
        if let Some(path) = find_labymod_addons(&base, version) {
            return path.to_string_lossy().to_string();
        }
    }

    let mods = base.join("mods");
    if mods.is_dir() {
        return mods.to_string_lossy().to_string();
    }

    if launcher.eq_ignore_ascii_case("Lunar") {
        let lunar_mods = base.join(".lunarclient").join("mods");
        if lunar_mods.is_dir() {
            return lunar_mods.to_string_lossy().to_string();
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            let fallback = PathBuf::from(appdata).join(".lunarclient").join("mods");
            if fallback.is_dir() {
                return fallback.to_string_lossy().to_string();
            }
        }
    }

    "Not found".to_string()
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i].eq_ignore_ascii_case(flag) {
            return args.get(i + 1).cloned().map(|v| strip_quotes(&v));
        }
        if let Some(value) = args[i].strip_prefix(&(format!("{flag}="))) {
            return Some(strip_quotes(value));
        }
    }
    None
}

fn property_value(args: &[String], prefix: &str) -> Option<String> {
    for arg in args {
        if let Some(value) = arg.strip_prefix(prefix) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(strip_quotes(value));
            }
        }
        if let Some(value) = arg.strip_prefix(&format!("{prefix}=")) {
            return Some(strip_quotes(value));
        }
    }
    None
}

fn strip_quotes(value: &str) -> String {
    value.trim_matches('"').trim_matches('\'').to_string()
}

fn extract_version_from_classpath(classpath: &str) -> Option<String> {
    for entry in classpath.split(';') {
        let lower = entry.to_ascii_lowercase();
        if let Some(pos) = lower.find("\\versions\\") {
            let tail = &entry[pos + "\\versions\\".len()..];
            let mut parts = tail.split(['\\', '/']);
            if let Some(id) = parts.next() {
                if !id.is_empty() {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

fn extract_version_jar_from_classpath(classpath: &str) -> Option<String> {
    for entry in classpath.split(';') {
        if let Some(path) = extract_version_jar_path(entry) {
            return Some(path);
        }
    }
    None
}

fn extract_version_jar_from_cmdline(cmdline_lower: &str) -> Option<String> {
    let marker = "\\versions\\";
    let pos = cmdline_lower.find(marker)?;
    let tail = &cmdline_lower[pos + marker.len()..];
    let mut parts = tail.split(['\\', '/']);
    let folder = parts.next()?.trim_matches('"').trim_matches('\'');
    let file = parts.next()?.trim_matches('"').trim_matches('\'');
    let expect = format!("{folder}.jar");
    if !file.eq_ignore_ascii_case(&expect) {
        return None;
    }

    let before = &cmdline_lower[..pos];
    let drive = before.rfind(":\\")?;
    let start = drive.saturating_sub(1);
    let prefix = before[start..].trim_matches('"').trim_matches('\'');
    build_version_jar_path(prefix, folder)
}

fn extract_version_jar_path(entry: &str) -> Option<String> {
    let lower = entry.to_ascii_lowercase();
    let marker = "\\versions\\";
    let pos = lower.find(marker)?;
    let tail = &entry[pos + marker.len()..];
    let mut parts = tail.split(['\\', '/']);
    let folder = parts.next()?.trim_matches('"').trim_matches('\'');
    let file = parts.next()?.trim_matches('"').trim_matches('\'');
    let expect = format!("{folder}.jar");
    if !file.eq_ignore_ascii_case(&expect) {
        return None;
    }
    let prefix = entry[..pos].trim_matches('"').trim_matches('\'');
    build_version_jar_path(prefix, folder)
}

fn build_version_jar_path(prefix: &str, folder: &str) -> Option<String> {
    let mut base = PathBuf::from(prefix);
    base.push("versions");
    base.push(folder);
    base.push(format!("{folder}.jar"));
    let full = base.to_string_lossy().replace('/', "\\");
    if full.is_empty() {
        None
    } else {
        Some(full)
    }
}

fn extract_mc_version(id: &str) -> Option<String> {
    let cleaned = id.trim();
    let parts: Vec<&str> = cleaned.split('-').collect();
    for part in parts.iter().rev() {
        if is_mc_version(part) {
            return Some(part.to_string());
        }
    }
    if is_mc_version(cleaned) {
        return Some(cleaned.to_string());
    }
    None
}

fn is_mc_version(value: &str) -> bool {
    let mut dot = 0;
    let mut digits = 0;
    for c in value.chars() {
        if c == '.' {
            dot += 1;
        } else if c.is_ascii_digit() {
            digits += 1;
        } else {
            return false;
        }
    }
    digits >= 2 && dot >= 1
}

fn read_version_json(game_dir: &str) -> Option<String> {
    let version_dir = Path::new(game_dir).join("versions");
    if !version_dir.is_dir() {
        return None;
    }
    let entries = std::fs::read_dir(&version_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name()?.to_string_lossy().to_string();
        let json_path = path.join(format!("{name}.json"));
        if let Ok(contents) = std::fs::read_to_string(&json_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(id) = json.get("inheritsFrom").and_then(|v| v.as_str()) {
                    if let Some(v) = extract_mc_version(id) {
                        return Some(v);
                    }
                }
                if let Some(id) = json.get("id").and_then(|v| v.as_str()) {
                    if let Some(v) = extract_mc_version(id) {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

fn extract_version_from_cmdline(cmdline_lower: &str) -> Option<String> {
    if let Some(pos) = cmdline_lower.find("\\versions\\") {
        let tail = &cmdline_lower[pos + "\\versions\\".len()..];
        let mut parts = tail.split(['\\', '/']);
        if let Some(id) = parts.next() {
            return Some(id.to_string());
        }
    }
    None
}

fn normalize_launcher(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if lower.contains("tlauncher") {
        return "TLauncher".to_string();
    }
    if lower.contains("legacy") {
        return "Legacy".to_string();
    }
    if lower.contains("modrinth") {
        return "Modrinth".to_string();
    }
    if lower.contains("lunar") {
        return "Lunar".to_string();
    }
    if lower.contains("laby") {
        return "LabyMod".to_string();
    }
    if lower.contains("official") || lower.contains("minecraft") {
        return "Official".to_string();
    }
    value.to_string()
}

fn extract_instance_path(cmdline_lower: &str, marker: &str) -> Option<String> {
    let marker_lower = marker.to_ascii_lowercase();
    let pos = cmdline_lower.find(&marker_lower)?;
    let after = &cmdline_lower[pos + marker_lower.len()..];
    let mut parts = after.split(['\\', '/']);
    let profile = parts.next()?;
    if profile.is_empty() {
        return None;
    }
    let prefix = &cmdline_lower[..pos];
    let full = format!("{prefix}{marker}{profile}");
    Some(full.replace('/', "\\"))
}

fn find_labymod_addons(base: &Path, version: &str) -> Option<PathBuf> {
    let preferred = if version != "Unknown" {
        Some(format!("addons-{}", version))
    } else {
        None
    };

    let candidates = [
        base.join("LabyMod"),
        base.join(".laby"),
        base.to_path_buf(),
    ];

    for root in candidates {
        if let Some(pref) = &preferred {
            let path = root.join(pref);
            if path.is_dir() {
                return Some(path);
            }
        }
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if name.starts_with("addons-") && entry.path().is_dir() {
                    return Some(entry.path());
                }
            }
        }
    }

    None
}

fn collect_mods(mods_dir: &str) -> Vec<ModEntry> {
    let path = Path::new(mods_dir);
    if !path.is_dir() {
        return Vec::new();
    }
    let mut mods = Vec::new();
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return mods,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext = ext.to_ascii_lowercase();
            if ext != "jar" && ext != "zip" {
                continue;
            }
        } else {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
        mods.push(ModEntry {
            name,
            size_bytes,
            path: path.to_string_lossy().to_string(),
        });
    }

    mods.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
    mods
}
