use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::{Local, Utc};
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use walkdir::{DirEntry, WalkDir};

use crate::usn_journal;
use crate::viewer::{self, ParsedFileContent};

const APP_NAME: &str = "RSS-AltsChecker";
pub const SCAN_CANCELLED_MESSAGE: &str = "Сканирование остановлено пользователем";

const MAX_MINECRAFT_LOG_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MINECRAFT_JSON_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DISCORD_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DISCORD_CONTEXT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DISCORD_TEXT_BYTES: usize = 4_000_000;

const MINECRAFT_SCAN_MAX_DEPTH: usize = 10;
const DISCOVERY_SCAN_MAX_DEPTH: usize = 5;
const DISCOVERY_MAX_DIRS_PER_PROFILE: usize = 25_000;

const DISCORD_EPOCH_MS: u64 = 1_420_070_400_000;
const MAX_DISCORD_FUTURE_SKEW_MS: i64 = 1_577_000_000;

const MINECRAFT_ACCOUNT_FILE_NAMES: &[&str] = &[
    "accounts.json",
    "launcher_accounts.json",
    "launcher_accounts_microsoft_store.json",
    "launcher_msa_credentials.json",
    "launcher_profiles.json",
    "tlauncher_profiles.json",
    "tlauncherprofiles.json",
    "authenticationdatabase",
    "labymod_accounts.json",
];

const MINECRAFT_JSON_BLOCKLIST: &[&str] =
    &["usercache.json", "servers.json", "realms_persistence.json"];

const MINECRAFT_STRONG_NAME_KEYS: &[&str] = &[
    "username",
    "displayname",
    "display_name",
    "playername",
    "profile_name",
    "profilename",
    "lastusedname",
    "selecteduser",
    "ingamename",
    "ign",
];

const MINECRAFT_ACCOUNT_CONTEXT_KEYS: &[&str] = &[
    "account",
    "accounts",
    "authenticationdatabase",
    "accesstoken",
    "refreshtoken",
    "clienttoken",
    "uuid",
    "xuid",
    "profileid",
    "selecteduser",
    "minecraftprofile",
    "msa",
];

const MINECRAFT_STRUCTURE_BLACKLIST: &[&str] = &[
    "forge", "fabric", "vanilla", "optifine", "account", "accounts", "profile", "instance",
];

const ROAMING_LAUNCHER_DIRS: &[&str] = &[
    ".minecraft",
    ".lunarclient",
    ".tlauncher",
    "TLauncher",
    "Legacy Launcher",
    "LegacyLauncher",
    "PrismLauncher",
    "MultiMC",
    "PolyMC",
    "ModrinthApp",
    "AstralRinth",
    "gdlauncher_carbon",
    "GDLauncher Carbon",
    "CurseForge",
    "FTB App",
    "FTBApp",
    ".ftba",
    "HMCL",
    ".hmcl",
    "SKLauncher",
    ".sklauncher",
    "Salwyrr",
    ".salwyrr",
    "LabyMod",
    "Feather",
    "TechnicLauncher",
    ".technic",
];

const LOCAL_LAUNCHER_DIRS: &[&str] = &[
    "Packages\\Microsoft.4297127D64EC6_8wekyb3d8bbwe\\LocalCache\\Roaming\\.minecraft",
    "Packages\\Microsoft.4297127D64EC6_8wekyb3d8bbwe\\LocalCache\\Local\\.minecraft",
    "Packages\\MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang",
    "PrismLauncher",
    "ModrinthApp",
    "gdlauncher_carbon",
    "CurseForge",
];

const HOME_LAUNCHER_DIRS: &[&str] = &[
    ".minecraft",
    ".lunarclient",
    ".tlauncher",
    ".local/share/PrismLauncher",
    ".local/share/MultiMC",
    ".local/share/PolyMC",
    ".local/share/ModrinthApp",
    ".config/PrismLauncher",
    ".config/ModrinthApp",
    "Library/Application Support/minecraft",
    "Library/Application Support/PrismLauncher",
];

const DISCORD_CLIENT_NAMES: &[&str] = &["discord", "discordcanary", "discordptb"];

const BROWSER_USERDATA_DIRS: &[&str] = &[
    "Google\\Chrome\\User Data",
    "Microsoft\\Edge\\User Data",
    "BraveSoftware\\Brave-Browser\\User Data",
    "Vivaldi\\User Data",
    "Yandex\\YandexBrowser\\User Data",
];

const OPERA_LEVELDB_DIRS: &[&str] = &[
    "Opera Software\\Opera Stable\\Local Storage\\leveldb",
    "Opera Software\\Opera GX Stable\\Local Storage\\leveldb",
];

const BROWSER_DISCORD_CONTEXT_FILES: &[&str] = &["History", "Web Data", "Shortcuts"];

const SKIP_DIR_NAMES: &[&str] = &[
    "libraries",
    "assets",
    "runtime",
    "cache",
    "caches",
    "logs_cache",
    "natives",
    "node_modules",
    ".git",
    ".gradle",
    "program files",
    "program files (x86)",
    "windows",
    "$recycle.bin",
    "system volume information",
];

static MINECRAFT_LOG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\bsetting user:\s*([A-Za-z0-9_]{3,16})").expect("regex must compile"),
        Regex::new(r"(?i)\bcreating minecraft session for\s*([A-Za-z0-9_]{3,16})")
            .expect("regex must compile"),
        Regex::new(r"(?i)\blogged in as\s*([A-Za-z0-9_]{3,16})").expect("regex must compile"),
        Regex::new(r"(?i)\bgot lunar client token for\s*([A-Za-z0-9_]{3,16})")
            .expect("regex must compile"),
        Regex::new(r"(?i)\b--username\s+([A-Za-z0-9_]{3,16})").expect("regex must compile"),
    ]
});

static MINECRAFT_JSON_USERNAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\"(?:username|displayName|profileName|playerName|lastUsedName)\"\s*:\s*\"([A-Za-z0-9_]{3,16})\""#)
        .expect("regex must compile")
});

static MINECRAFT_DATED_LOG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^\d{4}-\d{2}-\d{2}-\d+\.log(?:\.gz)?$").expect("regex must compile")
});

static DISCORD_USER_ID_RE_A: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?s)\{[^{}]{0,1400}\"username\"\s*:\s*\"(?P<username>[A-Za-z0-9_.-]{2,64})\"[^{}]{0,1400}\"id\"\s*:\s*\"(?P<id>\d{17,20})\"[^{}]*\}"#,
    )
    .expect("regex must compile")
});

static DISCORD_USER_ID_RE_B: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?s)\{[^{}]{0,1400}\"id\"\s*:\s*\"(?P<id>\d{17,20})\"[^{}]{0,1400}\"username\"\s*:\s*\"(?P<username>[A-Za-z0-9_.-]{2,64})\"[^{}]*\}"#,
    )
    .expect("regex must compile")
});

static DISCORD_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([A-Za-z0-9_-]{23,28})\.([A-Za-z0-9_-]{6,8})\.([A-Za-z0-9_-]{20,110})")
        .expect("regex must compile")
});

static DISCORD_USER_PROFILE_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)discord(?:app)?\.com/users/(\d{17,20})"#).expect("regex must compile")
});

static DISCORD_ID_PARAM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:\bdiscord_id=)(\d{17,20})"#).expect("regex must compile"));

static DISCORD_ENCODED_USER_RE_A: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)%22id%22%3a%22(?P<id>\d{17,20})%22.{0,1200}?%22username%22%3a%22(?P<username>[A-Za-z0-9_.-]{2,64})%22"#,
    )
    .expect("regex must compile")
});

static DISCORD_ENCODED_USER_RE_B: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)%22username%22%3a%22(?P<username>[A-Za-z0-9_.-]{2,64})%22.{0,1200}?%22id%22%3a%22(?P<id>\d{17,20})%22"#,
    )
    .expect("regex must compile")
});

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub include_known_launcher_paths: bool,
    pub extra_minecraft_root: Option<PathBuf>,
    pub discord_leveldb_dir: Option<PathBuf>,
    pub cancel_flag: Option<Arc<AtomicBool>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            include_known_launcher_paths: true,
            extra_minecraft_root: None,
            discord_leveldb_dir: Some(default_discord_leveldb_path()),
            cancel_flag: None,
        }
    }
}

pub fn is_cancelled_error(message: &str) -> bool {
    message.trim() == SCAN_CANCELLED_MESSAGE
}

fn check_cancelled(options: &ScanOptions) -> Result<(), String> {
    if options
        .cancel_flag
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Relaxed))
    {
        Err(SCAN_CANCELLED_MESSAGE.to_string())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScanStats {
    pub minecraft_roots: usize,
    pub minecraft_files_scanned: usize,
    pub minecraft_log_files_scanned: usize,
    pub minecraft_json_files_scanned: usize,
    pub logs_directories_found: usize,
    pub discord_files_scanned: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MinecraftAlt {
    pub username: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscordAlt {
    pub username: String,
    pub id: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileLink {
    pub profile: String,
    pub minecraft_accounts: Vec<String>,
    pub discord_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub app: String,
    pub generated_at: String,
    pub report_file: String,
    pub minecraft_accounts: Vec<MinecraftAlt>,
    pub minecraft_detection_debug: Vec<MinecraftDetectionDebug>,
    pub discord_accounts: Vec<DiscordAlt>,
    pub profile_links: Vec<ProfileLink>,
    pub forensic_signals: Vec<String>,
    pub usn_journal: Option<usn_journal::UsnJournalReport>,
    pub scanned_locations: Vec<String>,
    pub warnings: Vec<String>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct MinecraftDetectionDebug {
    pub username: String,
    pub kept: bool,
    pub reason: String,
    pub source_count: usize,
    pub account_source_count: usize,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone)]
struct MinecraftCandidate {
    username: String,
    sources: BTreeSet<String>,
    profile_keys: BTreeSet<String>,
    account_hits: usize,
    log_hits: usize,
}

#[derive(Debug, Clone)]
struct DiscordCandidate {
    username: String,
    id: Option<String>,
    sources: BTreeSet<String>,
    profile_keys: BTreeSet<String>,
    evidence_hits: usize,
}

#[derive(Debug, Clone)]
struct MinecraftScanOutcome {
    accounts: Vec<MinecraftAlt>,
    debug: Vec<MinecraftDetectionDebug>,
    profile_accounts: HashMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone)]
struct DiscordScanOutcome {
    accounts: Vec<DiscordAlt>,
    profile_accounts: HashMap<String, BTreeSet<String>>,
    scanned_dirs: Vec<PathBuf>,
    scanned_context_files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct UserProfile {
    home: PathBuf,
    roaming: Option<PathBuf>,
    local: Option<PathBuf>,
}

pub fn default_discord_leveldb_path() -> PathBuf {
    if let Some(appdata) = env::var_os("APPDATA").map(PathBuf::from) {
        return appdata
            .join("discord")
            .join("Local Storage")
            .join("leveldb");
    }

    if let Some(home) = dirs::home_dir() {
        return home
            .join("AppData")
            .join("Roaming")
            .join("discord")
            .join("Local Storage")
            .join("leveldb");
    }

    PathBuf::from(r"C:\Users\Default\AppData\Roaming\discord\Local Storage\leveldb")
}

pub fn default_report_path() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("RSS-AltsChecker-results.json")
}

pub fn write_report(report: &ScanReport, path: &Path) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("Failed to serialize report: {error}"))?;
    fs::write(path, json).map_err(|error| format!("Failed to write {}: {error}", path.display()))
}

pub fn run_scan(options: &ScanOptions) -> Result<ScanReport, String> {
    let mut report = scan(options)?;
    let output_path = default_report_path();
    report.report_file = output_path.display().to_string();
    write_report(&report, &output_path)?;
    Ok(report)
}

pub fn scan(options: &ScanOptions) -> Result<ScanReport, String> {
    check_cancelled(options)?;

    let mut warnings = Vec::new();
    let mut stats = ScanStats::default();

    let profiles = collect_user_profiles(&mut warnings);

    let minecraft_roots = collect_minecraft_roots(&profiles, options, &mut warnings);
    stats.minecraft_roots = minecraft_roots.len();

    let minecraft_scan =
        scan_minecraft_accounts(&minecraft_roots, &mut stats, &mut warnings, options)?;
    check_cancelled(options)?;

    let discord_dirs = collect_discord_leveldb_dirs(&profiles, options, &mut warnings);
    let discord_context_files = collect_discord_context_files(&profiles, &mut warnings);
    let discord_scan = scan_discord_accounts(
        &discord_dirs,
        &discord_context_files,
        &mut stats,
        &mut warnings,
        options,
    )?;
    check_cancelled(options)?;

    let usn_scan = usn_journal::scan_for_minecraft_discord();
    check_cancelled(options)?;

    let mut forensic_signals = analyze_usn_forensic_signals(usn_scan.report.as_ref());
    warnings.extend(usn_scan.warnings.clone());

    if discord_scan.accounts.is_empty() {
        forensic_signals.push("Discord: аккаунты не обнаружены".to_string());
    }
    if minecraft_scan.accounts.is_empty() {
        forensic_signals.push("Minecraft: аккаунты не обнаружены".to_string());
    }

    let profile_links = build_profile_links(
        &minecraft_scan.profile_accounts,
        &discord_scan.profile_accounts,
    );

    let mut scanned_locations = Vec::<String>::new();
    scanned_locations.extend(
        minecraft_roots
            .iter()
            .map(|path| format!("minecraft_root: {}", path.display())),
    );
    scanned_locations.extend(
        discord_scan
            .scanned_dirs
            .iter()
            .map(|path| format!("discord_leveldb: {}", path.display())),
    );
    scanned_locations.extend(
        discord_scan
            .scanned_context_files
            .iter()
            .map(|path| format!("discord_context: {}", path.display())),
    );
    scanned_locations.extend(usn_scan.scanned_locations);

    scanned_locations.sort();
    scanned_locations.dedup();

    warnings.sort();
    warnings.dedup();
    forensic_signals.sort();
    forensic_signals.dedup();

    Ok(ScanReport {
        app: APP_NAME.to_string(),
        generated_at: Local::now().to_rfc3339(),
        report_file: String::new(),
        minecraft_accounts: minecraft_scan.accounts,
        minecraft_detection_debug: minecraft_scan.debug,
        discord_accounts: discord_scan.accounts,
        profile_links,
        forensic_signals,
        usn_journal: usn_scan.report,
        scanned_locations,
        warnings,
        stats,
    })
}

fn collect_user_profiles(warnings: &mut Vec<String>) -> Vec<UserProfile> {
    let mut profiles = Vec::<UserProfile>::new();
    let mut seen = HashSet::<String>::new();

    #[cfg(windows)]
    {
        let users_root = PathBuf::from(r"C:\Users");
        match fs::read_dir(&users_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let home = entry.path();
                    if !home.is_dir() {
                        continue;
                    }

                    if home
                        .file_name()
                        .and_then(|value| value.to_str())
                        .is_some_and(should_skip_windows_profile_name)
                    {
                        continue;
                    }

                    push_profile_if_unique(&mut profiles, &mut seen, home);
                }
            }
            Err(error) => warnings.push(format!(
                "Failed to enumerate Windows profiles in {}: {error}",
                users_root.display()
            )),
        }
    }

    if let Some(home) = dirs::home_dir() {
        push_profile_if_unique(&mut profiles, &mut seen, home);
    }

    profiles.sort_by(|left, right| {
        normalize_path_key(&left.home).cmp(&normalize_path_key(&right.home))
    });
    profiles
}

fn push_profile_if_unique(
    profiles: &mut Vec<UserProfile>,
    seen: &mut HashSet<String>,
    home: PathBuf,
) {
    if !home.is_dir() {
        return;
    }

    let key = normalize_path_key(&home);
    if !seen.insert(key) {
        return;
    }

    let roaming = home.join("AppData").join("Roaming");
    let local = home.join("AppData").join("Local");

    profiles.push(UserProfile {
        home,
        roaming: roaming.is_dir().then_some(roaming),
        local: local.is_dir().then_some(local),
    });
}

#[cfg(windows)]
fn should_skip_windows_profile_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "public" | "default" | "default user" | "all users" | "defaultapppool"
    )
}
fn collect_minecraft_roots(
    profiles: &[UserProfile],
    options: &ScanOptions,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut roots = Vec::<PathBuf>::new();
    let mut seen = HashSet::<String>::new();

    if options.include_known_launcher_paths {
        for profile in profiles {
            add_known_minecraft_paths_for_profile(profile, &mut roots, &mut seen);
            discover_portable_minecraft_roots(profile, &mut roots, &mut seen, warnings);
        }
    }

    if let Some(extra_root) = options.extra_minecraft_root.clone() {
        if extra_root.is_dir() {
            push_unique_dir(&mut roots, &mut seen, extra_root);
        } else {
            warnings.push(format!(
                "Extra Minecraft path is not a directory: {}",
                extra_root.display()
            ));
        }
    }

    roots.sort_by(|left, right| normalize_path_key(left).cmp(&normalize_path_key(right)));
    roots
}

fn add_known_minecraft_paths_for_profile(
    profile: &UserProfile,
    roots: &mut Vec<PathBuf>,
    seen: &mut HashSet<String>,
) {
    if let Some(roaming) = &profile.roaming {
        for relative in ROAMING_LAUNCHER_DIRS {
            push_unique_dir(roots, seen, roaming.join(relative));
        }
    }

    if let Some(local) = &profile.local {
        for relative in LOCAL_LAUNCHER_DIRS {
            push_unique_dir(roots, seen, local.join(relative));
        }

        for relative in BROWSER_USERDATA_DIRS {
            let user_data = local.join(relative);
            if !user_data.is_dir() {
                continue;
            }

            if let Ok(entries) = fs::read_dir(&user_data) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    let name = path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .map(|value| value.to_ascii_lowercase())
                        .unwrap_or_default();
                    if name == "default" || name == "guest profile" || name.starts_with("profile ")
                    {
                        let candidate = path.join("Local Storage").join("leveldb");
                        push_unique_dir(roots, seen, candidate);
                    }
                }
            }
        }
    }

    for relative in HOME_LAUNCHER_DIRS {
        push_unique_dir(roots, seen, profile.home.join(relative));
    }
}

fn discover_portable_minecraft_roots(
    profile: &UserProfile,
    roots: &mut Vec<PathBuf>,
    seen: &mut HashSet<String>,
    warnings: &mut Vec<String>,
) {
    let mut visited = 0usize;
    let walker = WalkDir::new(&profile.home)
        .max_depth(DISCOVERY_SCAN_MAX_DEPTH)
        .into_iter()
        .filter_entry(|entry| !should_skip_discovery_dir(entry));

    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_dir() {
            continue;
        }

        visited += 1;
        if visited > DISCOVERY_MAX_DIRS_PER_PROFILE {
            warnings.push(format!(
                "Portable Minecraft discovery limit reached for {}",
                profile.home.display()
            ));
            break;
        }

        let path = entry.path();
        let dir_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();

        if looks_like_minecraft_root_name(&dir_name) || has_minecraft_signature_files(path) {
            push_unique_dir(roots, seen, path.to_path_buf());
        }
    }
}

fn should_skip_discovery_dir(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }

    let name = entry
        .file_name()
        .to_str()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if SKIP_DIR_NAMES.contains(&name.as_str()) {
        return true;
    }

    name.starts_with('$')
}

fn looks_like_minecraft_root_name(dir_name_lower: &str) -> bool {
    [
        ".minecraft",
        "minecraft",
        "tlauncher",
        "lunarclient",
        "prismlauncher",
        "multimc",
        "polymc",
        "modrinth",
        "gdlauncher",
        "sklauncher",
        "salwyrr",
        "hmcl",
        "labymod",
        "curseforge",
        "technic",
    ]
    .iter()
    .any(|marker| dir_name_lower.contains(marker))
}

fn has_minecraft_signature_files(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }

    if path.join("logs").is_dir() {
        return true;
    }

    MINECRAFT_ACCOUNT_FILE_NAMES
        .iter()
        .any(|name| path.join(name).is_file())
}

fn scan_minecraft_accounts(
    roots: &[PathBuf],
    stats: &mut ScanStats,
    warnings: &mut Vec<String>,
    options: &ScanOptions,
) -> Result<MinecraftScanOutcome, String> {
    let mut map = HashMap::<String, MinecraftCandidate>::new();

    for root in roots {
        check_cancelled(options)?;

        if !root.is_dir() {
            continue;
        }

        let iterator = WalkDir::new(root)
            .max_depth(MINECRAFT_SCAN_MAX_DEPTH)
            .into_iter()
            .filter_entry(|entry| !should_skip_walk_dir_entry(entry));

        for entry in iterator.filter_map(Result::ok) {
            check_cancelled(options)?;

            let path = entry.path();
            if entry.file_type().is_dir() {
                if path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("logs"))
                {
                    stats.logs_directories_found += 1;
                }
                continue;
            }

            if !is_potential_minecraft_source_file(path) {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.len() == 0 {
                continue;
            }

            if should_scan_minecraft_log(path, metadata.len()) {
                stats.minecraft_files_scanned += 1;
                stats.minecraft_log_files_scanned += 1;

                let usernames = extract_minecraft_accounts_from_log_file(path, warnings);
                for username in usernames {
                    insert_minecraft_candidate(&mut map, &username, path, true);
                }
                continue;
            }

            if should_scan_minecraft_json(path, metadata.len()) {
                stats.minecraft_files_scanned += 1;
                stats.minecraft_json_files_scanned += 1;

                let usernames = extract_minecraft_accounts_from_json_file(path, warnings);
                for username in usernames {
                    insert_minecraft_candidate(&mut map, &username, path, false);
                }
            }
        }
    }

    let mut out = Vec::<MinecraftAlt>::new();
    let mut debug = Vec::<MinecraftDetectionDebug>::new();
    let mut profile_accounts = HashMap::<String, BTreeSet<String>>::new();

    for entry in map.into_values() {
        let (kept, reason, account_source_count) = classify_minecraft_candidate(&entry);
        let sources = entry.sources.into_iter().collect::<Vec<_>>();

        debug.push(MinecraftDetectionDebug {
            username: entry.username.clone(),
            kept,
            reason,
            source_count: sources.len(),
            account_source_count,
            sources: sources.clone(),
        });

        if !kept {
            continue;
        }

        for profile in &entry.profile_keys {
            profile_accounts
                .entry(profile.clone())
                .or_default()
                .insert(entry.username.clone());
        }

        out.push(MinecraftAlt {
            username: entry.username,
            sources,
        });
    }

    out.sort_by(|left, right| {
        left.username
            .to_ascii_lowercase()
            .cmp(&right.username.to_ascii_lowercase())
    });

    debug.sort_by(|left, right| {
        left.username
            .to_ascii_lowercase()
            .cmp(&right.username.to_ascii_lowercase())
            .then_with(|| left.source_count.cmp(&right.source_count))
    });

    Ok(MinecraftScanOutcome {
        accounts: out,
        debug,
        profile_accounts,
    })
}

fn should_skip_walk_dir_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }

    let name = entry
        .file_name()
        .to_str()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    SKIP_DIR_NAMES.contains(&name.as_str())
}

fn is_potential_minecraft_source_file(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if file_name.is_empty() {
        return false;
    }

    if file_name == "authenticationdatabase" {
        return true;
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if extension == "log" {
        return is_probable_minecraft_log_name(&file_name) || path_has_segment(path, "logs");
    }
    if extension == "gz" {
        return file_name.ends_with(".log.gz");
    }
    if extension != "json" {
        return false;
    }
    if MINECRAFT_JSON_BLOCKLIST.contains(&file_name.as_str()) {
        return false;
    }
    if MINECRAFT_ACCOUNT_FILE_NAMES.contains(&file_name.as_str()) {
        return true;
    }
    if !path_looks_minecraft_related(path) {
        return false;
    }

    ["account", "profile", "launcher", "auth", "minecraft"]
        .iter()
        .any(|hint| file_name.contains(hint))
}

fn should_scan_minecraft_log(path: &Path, file_size: u64) -> bool {
    if file_size > MAX_MINECRAFT_LOG_FILE_BYTES {
        return false;
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if extension != "log" && extension != "gz" {
        return false;
    }

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if extension == "gz" && !file_name.ends_with(".log.gz") {
        return false;
    }

    if is_probable_minecraft_log_name(&file_name) {
        return true;
    }

    path_has_segment(path, "logs") && file_name.ends_with(".log")
}

fn should_scan_minecraft_json(path: &Path, file_size: u64) -> bool {
    if file_size > MAX_MINECRAFT_JSON_FILE_BYTES {
        return false;
    }

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if MINECRAFT_JSON_BLOCKLIST
        .iter()
        .any(|blocked| *blocked == file_name)
    {
        return false;
    }

    let is_json = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));

    if !is_json && file_name != "authenticationdatabase" {
        return false;
    }

    if MINECRAFT_ACCOUNT_FILE_NAMES
        .iter()
        .any(|name| *name == file_name)
    {
        return true;
    }

    let has_hint = ["account", "profile", "launcher", "auth", "minecraft"]
        .iter()
        .any(|hint| file_name.contains(hint));

    has_hint && path_looks_minecraft_related(path)
}

fn is_probable_minecraft_log_name(file_name_lower: &str) -> bool {
    file_name_lower == "latest.log"
        || file_name_lower == "debug.log"
        || file_name_lower
            .strip_prefix("latest.log.")
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
            })
        || file_name_lower
            .strip_prefix("debug.log.")
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
            })
        || MINECRAFT_DATED_LOG_RE.is_match(file_name_lower)
}

fn extract_minecraft_accounts_from_log_file(
    path: &Path,
    warnings: &mut Vec<String>,
) -> BTreeSet<String> {
    let bytes = if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gz"))
    {
        match read_gzip_file(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                warnings.push(format!("Failed to decompress {}: {error}", path.display()));
                return BTreeSet::new();
            }
        }
    } else {
        match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                warnings.push(format!("Failed to read {}: {error}", path.display()));
                return BTreeSet::new();
            }
        }
    };

    let text = String::from_utf8_lossy(&bytes);
    let mut usernames = BTreeSet::<String>::new();

    for pattern in MINECRAFT_LOG_PATTERNS.iter() {
        for captures in pattern.captures_iter(&text) {
            if let Some(value) = captures.get(1).map(|value| value.as_str()) {
                if let Some(username) = normalize_minecraft_username(value) {
                    usernames.insert(username);
                }
            }
        }
    }

    usernames
}

fn extract_minecraft_accounts_from_json_file(
    path: &Path,
    warnings: &mut Vec<String>,
) -> BTreeSet<String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            warnings.push(format!("Failed to read {}: {error}", path.display()));
            return BTreeSet::new();
        }
    };

    let text = String::from_utf8_lossy(&bytes);
    let mut usernames = BTreeSet::<String>::new();

    let trusted_file = is_trusted_minecraft_account_file(path);
    if !trusted_file && !minecraft_json_likely_has_account_markers(&text) {
        return usernames;
    }

    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        collect_minecraft_names_from_json(&value, &mut usernames, trusted_file);
    } else {
        for captures in MINECRAFT_JSON_USERNAME_RE.captures_iter(&text) {
            if let Some(value) = captures.get(1).map(|capture| capture.as_str()) {
                if let Some(username) = normalize_minecraft_username(value) {
                    usernames.insert(username);
                }
            }
        }
    }

    usernames
}

fn minecraft_json_likely_has_account_markers(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("\"account")
        || lower.contains("\"accounts")
        || lower.contains("\"profile")
        || lower.contains("\"uuid")
        || lower.contains("\"xuid")
        || lower.contains("\"accesstoken")
        || lower.contains("\"refreshtoken")
        || lower.contains("launcher")
        || lower.contains("selecteduser")
}

fn collect_minecraft_names_from_json(
    value: &Value,
    output: &mut BTreeSet<String>,
    inherited_account_context: bool,
) {
    match value {
        Value::Object(map) => {
            let mut keys = HashSet::<String>::new();
            for key in map.keys() {
                keys.insert(key.to_ascii_lowercase());
            }

            let object_account_context = inherited_account_context
                || keys
                    .iter()
                    .any(|key| MINECRAFT_ACCOUNT_CONTEXT_KEYS.contains(&key.as_str()))
                || keys
                    .iter()
                    .any(|key| key.contains("token") || key.contains("account"));

            let identity_markers = json_object_has_identity_markers(&keys);

            for (key, child) in map {
                let key_lower = key.to_ascii_lowercase();

                if let Value::String(text) = child {
                    if let Some(username) = normalize_minecraft_username(text) {
                        let keep = if MINECRAFT_STRONG_NAME_KEYS.contains(&key_lower.as_str()) {
                            object_account_context
                        } else if key_lower == "name" {
                            object_account_context && identity_markers
                        } else {
                            false
                        };

                        if keep {
                            output.insert(username);
                        }
                    }
                }

                let child_context = object_account_context || key_looks_account_related(&key_lower);
                collect_minecraft_names_from_json(child, output, child_context);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_minecraft_names_from_json(child, output, inherited_account_context);
            }
        }
        _ => {}
    }
}

fn is_trusted_minecraft_account_file(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    MINECRAFT_ACCOUNT_FILE_NAMES
        .iter()
        .any(|name| *name == file_name)
}

fn json_object_has_identity_markers(keys: &HashSet<String>) -> bool {
    keys.iter().any(|key| {
        key == "id"
            || key == "uuid"
            || key == "xuid"
            || key == "profileid"
            || key == "selecteduser"
            || key == "accesstoken"
            || key == "refreshtoken"
    })
}

fn key_looks_account_related(key_lower: &str) -> bool {
    MINECRAFT_ACCOUNT_CONTEXT_KEYS.contains(&key_lower)
        || key_lower.contains("account")
        || key_lower.contains("profile")
        || key_lower.contains("token")
}

fn insert_minecraft_candidate(
    map: &mut HashMap<String, MinecraftCandidate>,
    username: &str,
    source_path: &Path,
    from_log: bool,
) {
    let Some(username) = normalize_minecraft_username(username) else {
        return;
    };

    let key = username.to_ascii_lowercase();
    let entry = map.entry(key).or_insert_with(|| MinecraftCandidate {
        username: username.clone(),
        sources: BTreeSet::new(),
        profile_keys: BTreeSet::new(),
        account_hits: 0,
        log_hits: 0,
    });

    entry.sources.insert(source_path.display().to_string());

    if let Some(profile) = profile_key_from_path(source_path) {
        entry.profile_keys.insert(profile);
    }

    if from_log {
        entry.log_hits += 1;
    } else {
        entry.account_hits += 1;
    }
}

fn classify_minecraft_candidate(entry: &MinecraftCandidate) -> (bool, String, usize) {
    let username_lower = entry.username.to_ascii_lowercase();

    if is_structural_minecraft_word(&username_lower) {
        return (
            false,
            "structural-word-filter".to_string(),
            entry.account_hits,
        );
    }

    if entry.account_hits > 0 {
        return (
            true,
            format!(
                "trusted-account-source:{};log:{}",
                entry.account_hits, entry.log_hits
            ),
            entry.account_hits,
        );
    }

    if is_placeholder_minecraft_username(&username_lower) {
        if entry.log_hits >= 3 {
            return (
                true,
                format!("placeholder-multi-log:{}", entry.log_hits),
                entry.account_hits,
            );
        }
        return (
            false,
            format!("placeholder-filtered:{}", entry.log_hits),
            entry.account_hits,
        );
    }

    if entry.log_hits >= 1 {
        return (
            true,
            format!("log-evidence:{}", entry.log_hits),
            entry.account_hits,
        );
    }

    (false, "no-usable-evidence".to_string(), entry.account_hits)
}

fn is_placeholder_minecraft_username(username_lower: &str) -> bool {
    if let Some(suffix) = username_lower.strip_prefix("player") {
        return !suffix.is_empty()
            && suffix.len() <= 5
            && suffix.chars().all(|ch| ch.is_ascii_digit());
    }
    false
}

fn is_structural_minecraft_word(username_lower: &str) -> bool {
    MINECRAFT_STRUCTURE_BLACKLIST.contains(&username_lower)
}
fn collect_discord_leveldb_dirs(
    profiles: &[UserProfile],
    options: &ScanOptions,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::<PathBuf>::new();
    let mut seen = HashSet::<String>::new();

    if let Some(path) = options.discord_leveldb_dir.clone() {
        push_unique_dir(&mut dirs, &mut seen, path);
    }

    if !options.include_known_launcher_paths {
        dirs.sort_by(|left, right| normalize_path_key(left).cmp(&normalize_path_key(right)));
        return dirs;
    }

    for profile in profiles {
        if let Some(roaming) = &profile.roaming {
            for client in DISCORD_CLIENT_NAMES {
                let path = roaming.join(client).join("Local Storage").join("leveldb");
                push_unique_dir(&mut dirs, &mut seen, path);
            }

            for relative in OPERA_LEVELDB_DIRS {
                push_unique_dir(&mut dirs, &mut seen, roaming.join(relative));
            }
        }

        if let Some(local) = &profile.local {
            for relative in BROWSER_USERDATA_DIRS {
                let user_data = local.join(relative);
                if !user_data.is_dir() {
                    continue;
                }

                let entries = match fs::read_dir(&user_data) {
                    Ok(entries) => entries,
                    Err(error) => {
                        warnings.push(format!(
                            "Failed to read browser profiles in {}: {error}",
                            user_data.display()
                        ));
                        continue;
                    }
                };

                for entry in entries.flatten() {
                    let profile_dir = entry.path();
                    if !profile_dir.is_dir() {
                        continue;
                    }

                    let name = profile_dir
                        .file_name()
                        .and_then(|value| value.to_str())
                        .map(|value| value.to_ascii_lowercase())
                        .unwrap_or_default();

                    if name == "default" || name == "guest profile" || name.starts_with("profile ")
                    {
                        let leveldb = profile_dir.join("Local Storage").join("leveldb");
                        push_unique_dir(&mut dirs, &mut seen, leveldb);
                    }
                }
            }
        }
    }

    dirs.sort_by(|left, right| normalize_path_key(left).cmp(&normalize_path_key(right)));
    dirs
}

fn collect_discord_context_files(
    profiles: &[UserProfile],
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut files = Vec::<PathBuf>::new();
    let mut seen = HashSet::<String>::new();

    for profile in profiles {
        let Some(local) = &profile.local else {
            continue;
        };

        for relative in BROWSER_USERDATA_DIRS {
            let user_data = local.join(relative);
            if !user_data.is_dir() {
                continue;
            }

            let entries = match fs::read_dir(&user_data) {
                Ok(entries) => entries,
                Err(error) => {
                    warnings.push(format!(
                        "Failed to read browser profiles in {}: {error}",
                        user_data.display()
                    ));
                    continue;
                }
            };

            for entry in entries.flatten() {
                let profile_dir = entry.path();
                if !profile_dir.is_dir() {
                    continue;
                }

                let name = profile_dir
                    .file_name()
                    .and_then(|value| value.to_str())
                    .map(|value| value.to_ascii_lowercase())
                    .unwrap_or_default();

                if name != "default" && name != "guest profile" && !name.starts_with("profile ") {
                    continue;
                }

                for file_name in BROWSER_DISCORD_CONTEXT_FILES {
                    push_unique_file(&mut files, &mut seen, profile_dir.join(file_name));
                }
            }
        }
    }

    files.sort_by(|left, right| normalize_path_key(left).cmp(&normalize_path_key(right)));
    files
}

fn scan_discord_accounts(
    leveldb_dirs: &[PathBuf],
    context_files: &[PathBuf],
    stats: &mut ScanStats,
    warnings: &mut Vec<String>,
    options: &ScanOptions,
) -> Result<DiscordScanOutcome, String> {
    let mut map = HashMap::<String, DiscordCandidate>::new();
    let mut scanned_dirs = Vec::<PathBuf>::new();
    let mut scanned_context_files = Vec::<PathBuf>::new();

    for leveldb_dir in leveldb_dirs {
        check_cancelled(options)?;

        if !leveldb_dir.exists() {
            continue;
        }
        if !leveldb_dir.is_dir() {
            warnings.push(format!(
                "Discord path is not a directory: {}",
                leveldb_dir.display()
            ));
            continue;
        }

        scanned_dirs.push(leveldb_dir.clone());
        scan_single_discord_leveldb_dir(leveldb_dir, &mut map, stats, warnings, options)?;
    }

    for file_path in context_files {
        check_cancelled(options)?;

        if !file_path.is_file() {
            continue;
        }

        let metadata = match fs::metadata(file_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                warnings.push(format!(
                    "Failed to read metadata for {}: {error}",
                    file_path.display()
                ));
                continue;
            }
        };

        if metadata.len() == 0 || metadata.len() > MAX_DISCORD_CONTEXT_FILE_BYTES {
            continue;
        }

        let bytes = match fs::read(file_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                warnings.push(format!("Failed to read {}: {error}", file_path.display()));
                continue;
            }
        };

        stats.discord_files_scanned += 1;
        scanned_context_files.push(file_path.clone());
        let source = file_path.display().to_string();
        extract_discord_accounts_from_context_bytes(&bytes, &source, &mut map);
    }

    let mut out = Vec::<DiscordAlt>::new();
    let mut profile_accounts = HashMap::<String, BTreeSet<String>>::new();

    for entry in map.into_values() {
        let Some(id) = entry.id.clone() else {
            continue;
        };

        let username = if entry.username == "unknown" {
            format!("id:{id}")
        } else {
            entry.username.clone()
        };

        for profile in &entry.profile_keys {
            profile_accounts
                .entry(profile.clone())
                .or_default()
                .insert(username.clone());
        }

        out.push(DiscordAlt {
            username,
            id: Some(id),
            sources: entry.sources.into_iter().collect(),
        });
    }

    out.sort_by(|left, right| {
        left.username
            .to_ascii_lowercase()
            .cmp(&right.username.to_ascii_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });

    Ok(DiscordScanOutcome {
        accounts: out,
        profile_accounts,
        scanned_dirs,
        scanned_context_files,
    })
}

fn scan_single_discord_leveldb_dir(
    leveldb_dir: &Path,
    map: &mut HashMap<String, DiscordCandidate>,
    stats: &mut ScanStats,
    warnings: &mut Vec<String>,
    options: &ScanOptions,
) -> Result<(), String> {
    check_cancelled(options)?;

    let mut parsed_via_viewer = false;

    match viewer::scan_target(leveldb_dir) {
        Ok(scan) => {
            for file in scan.files {
                check_cancelled(options)?;

                if !is_discord_leveldb_file(&file.path) {
                    continue;
                }

                parsed_via_viewer = true;
                stats.discord_files_scanned += 1;

                let source = file.path.display().to_string();
                match file.content {
                    ParsedFileContent::Ldb(ldb) => {
                        for entry in ldb.entries {
                            if !is_discord_owner_store_key(&entry.user_key) {
                                continue;
                            }
                            extract_discord_accounts_from_bytes(&entry.user_key, &source, map);
                            extract_discord_accounts_from_bytes(&entry.value, &source, map);
                        }
                    }
                    ParsedFileContent::Wal(wal) => {
                        for batch in wal.batches {
                            for operation in batch.operations {
                                if !is_discord_owner_store_key(&operation.key) {
                                    continue;
                                }
                                extract_discord_accounts_from_bytes(&operation.key, &source, map);
                                if let Some(value) = operation.value {
                                    extract_discord_accounts_from_bytes(&value, &source, map);
                                }
                            }
                        }
                    }
                    ParsedFileContent::TextLog(log) => {
                        let text = log.lines.join("\n");
                        extract_discord_accounts_from_text(&text, &source, map);
                    }
                    ParsedFileContent::Error(error) => {
                        warnings.push(format!("Discord parse error in {}: {error}", source));
                    }
                }
            }

            for warning in scan.warnings {
                warnings.push(format!(
                    "Discord LevelDB warning ({}): {warning}",
                    leveldb_dir.display()
                ));
            }
        }
        Err(error) => warnings.push(format!(
            "Discord LevelDB parse failed for {}: {error}",
            leveldb_dir.display()
        )),
    }

    if parsed_via_viewer {
        return Ok(());
    }

    let entries = match fs::read_dir(leveldb_dir) {
        Ok(entries) => entries,
        Err(error) => {
            warnings.push(format!(
                "Failed to read Discord LevelDB directory {}: {error}",
                leveldb_dir.display()
            ));
            return Ok(());
        }
    };

    for entry in entries.flatten() {
        check_cancelled(options)?;

        let path = entry.path();
        if !path.is_file() || !is_discord_leveldb_file(&path) {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.len() == 0 || metadata.len() > MAX_DISCORD_FILE_BYTES {
            continue;
        }

        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        if !discord_payload_looks_owner_related(&bytes) {
            continue;
        }

        stats.discord_files_scanned += 1;
        let source = path.display().to_string();
        extract_discord_accounts_from_bytes(&bytes, &source, map);
    }

    Ok(())
}

fn extract_discord_accounts_from_bytes(
    bytes: &[u8],
    source: &str,
    map: &mut HashMap<String, DiscordCandidate>,
) {
    if bytes.is_empty() {
        return;
    }

    if let Ok(text) = std::str::from_utf8(bytes) {
        extract_discord_accounts_from_text(text, source, map);
    } else {
        let lossy = String::from_utf8_lossy(bytes);
        extract_discord_accounts_from_text(&lossy, source, map);
    }

    for chunk in extract_printable_chunks(bytes, 80, 180) {
        extract_discord_accounts_from_text(&chunk, source, map);
    }
}

fn extract_discord_accounts_from_context_bytes(
    bytes: &[u8],
    source: &str,
    map: &mut HashMap<String, DiscordCandidate>,
) {
    if bytes.is_empty() {
        return;
    }

    for chunk in extract_printable_chunks(bytes, 72, 2_200) {
        if !discord_context_chunk_looks_relevant(&chunk) {
            continue;
        }
        extract_discord_accounts_from_context_text(&chunk, source, map);
    }
}

fn discord_context_chunk_looks_relevant(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let has_discord = lower.contains("discord");
    (has_discord
        && (lower.contains("discord.com/users/")
            || lower.contains("discordapp.com/users/")
            || (lower.contains("%22id%22%3a%22") && lower.contains("%22username%22%3a%22"))))
        || lower.contains("discord_id=")
}

fn extract_discord_accounts_from_context_text(
    text: &str,
    source: &str,
    map: &mut HashMap<String, DiscordCandidate>,
) {
    for captures in DISCORD_USER_PROFILE_URL_RE.captures_iter(text) {
        if let Some(id) = captures.get(1).map(|value| value.as_str()) {
            insert_discord_candidate(map, None, Some(id), source);
        }
    }

    for captures in DISCORD_ID_PARAM_RE.captures_iter(text) {
        if let Some(id) = captures.get(1).map(|value| value.as_str()) {
            insert_discord_candidate(map, None, Some(id), source);
        }
    }

    for captures in DISCORD_ENCODED_USER_RE_A.captures_iter(text) {
        if let (Some(username), Some(id)) = (
            captures.name("username").map(|value| value.as_str()),
            captures.name("id").map(|value| value.as_str()),
        ) {
            insert_discord_candidate(map, Some(username), Some(id), source);
        }
    }

    for captures in DISCORD_ENCODED_USER_RE_B.captures_iter(text) {
        if let (Some(username), Some(id)) = (
            captures.name("username").map(|value| value.as_str()),
            captures.name("id").map(|value| value.as_str()),
        ) {
            insert_discord_candidate(map, Some(username), Some(id), source);
        }
    }
}

fn extract_discord_accounts_from_text(
    text: &str,
    source: &str,
    map: &mut HashMap<String, DiscordCandidate>,
) {
    if text.is_empty() || text.len() > MAX_DISCORD_TEXT_BYTES {
        return;
    }

    extract_discord_accounts_from_text_variant(text, source, map);

    let normalized = normalize_escaped_json_text(text);
    if normalized != text {
        extract_discord_accounts_from_text_variant(&normalized, source, map);
    }
}

fn extract_discord_accounts_from_text_variant(
    text: &str,
    source: &str,
    map: &mut HashMap<String, DiscordCandidate>,
) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }

    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            collect_discord_accounts_from_json(&value, source, map, 0, false);
        }
    }

    for fragment in extract_json_fragments(trimmed, 220, 650_000) {
        if let Ok(value) = serde_json::from_str::<Value>(&fragment) {
            collect_discord_accounts_from_json(&value, source, map, 0, false);
        }
    }

    let lower = text.to_ascii_lowercase();

    for captures in DISCORD_USER_ID_RE_A.captures_iter(text) {
        if captures
            .get(0)
            .is_some_and(|whole| is_foreign_context_near_position(&lower, whole.start()))
        {
            continue;
        }

        if let (Some(username), Some(id)) = (
            captures.name("username").map(|value| value.as_str()),
            captures.name("id").map(|value| value.as_str()),
        ) {
            insert_discord_candidate(map, Some(username), Some(id), source);
        }
    }

    for captures in DISCORD_USER_ID_RE_B.captures_iter(text) {
        if captures
            .get(0)
            .is_some_and(|whole| is_foreign_context_near_position(&lower, whole.start()))
        {
            continue;
        }

        if let (Some(username), Some(id)) = (
            captures.name("username").map(|value| value.as_str()),
            captures.name("id").map(|value| value.as_str()),
        ) {
            insert_discord_candidate(map, Some(username), Some(id), source);
        }
    }

    extract_discord_ids_from_tokens(text, source, map);
}

fn collect_discord_accounts_from_json(
    value: &Value,
    source: &str,
    map: &mut HashMap<String, DiscordCandidate>,
    depth: usize,
    foreign_user_context: bool,
) {
    if depth > 20 {
        return;
    }

    match value {
        Value::Object(object) => {
            let username = object
                .get("username")
                .and_then(Value::as_str)
                .and_then(normalize_discord_username);
            let id = object.get("id").and_then(discord_id_from_value);

            let has_discord_markers = object.contains_key("discriminator")
                || object.contains_key("avatar")
                || object.contains_key("tokenStatus")
                || object.contains_key("global_name")
                || object.contains_key("globalName")
                || object.contains_key("flags");

            if !foreign_user_context {
                if let Some(id) = id {
                    if has_discord_markers || username.is_some() {
                        insert_discord_candidate(map, username.as_deref(), Some(&id), source);
                    }
                }
            }

            for (key, child) in object {
                let child_foreign_context =
                    foreign_user_context || is_foreign_discord_user_key(key);
                collect_discord_accounts_from_json(
                    child,
                    source,
                    map,
                    depth + 1,
                    child_foreign_context,
                );
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_discord_accounts_from_json(
                    child,
                    source,
                    map,
                    depth + 1,
                    foreign_user_context,
                );
            }
        }
        _ => {}
    }
}

fn is_foreign_discord_user_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower == "other_user"
        || lower == "otheruser"
        || lower == "recipient"
        || lower == "author"
        || lower == "sender"
        || lower == "member"
        || lower == "mentioned_users"
}

fn is_foreign_context_near_position(text_lower: &str, pos: usize) -> bool {
    let start = pos.saturating_sub(260);
    let prefix = &text_lower[start..pos];

    let foreign_pos = [
        prefix.rfind("\"other_user\""),
        prefix.rfind("\"otheruser\""),
        prefix.rfind("\"recipient\""),
        prefix.rfind("\"author\""),
        prefix.rfind("\"sender\""),
        prefix.rfind("\"member\""),
    ]
    .into_iter()
    .flatten()
    .max();

    let Some(foreign_pos) = foreign_pos else {
        return false;
    };

    let owner_pos = [
        prefix.rfind("\"current_user\""),
        prefix.rfind("\"currentuser\""),
        prefix.rfind("\"users\""),
        prefix.rfind("\"tokenstatus\""),
        prefix.rfind("\"multiaccountstore\""),
    ]
    .into_iter()
    .flatten()
    .max();

    if let Some(owner_pos) = owner_pos {
        if owner_pos > foreign_pos {
            return false;
        }
    }

    true
}

fn extract_discord_ids_from_tokens(
    text: &str,
    source: &str,
    map: &mut HashMap<String, DiscordCandidate>,
) {
    for captures in DISCORD_TOKEN_RE.captures_iter(text) {
        let Some(first_segment) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };

        if let Some(user_id) = decode_discord_token_user_id(first_segment) {
            insert_discord_candidate(map, None, Some(&user_id), source);
        }
    }
}

fn decode_discord_token_user_id(first_segment: &str) -> Option<String> {
    let bytes = decode_base64_url(first_segment)?;
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    normalize_discord_id(text)
}

fn decode_base64_url(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }

    let mut normalized = input.replace('-', "+").replace('_', "/");
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }

    let mut output = Vec::<u8>::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for byte in normalized.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };

        buffer = (buffer << 6) | u32::from(value);
        bits += 6;

        while bits >= 8 {
            bits -= 8;
            let out = ((buffer >> bits) & 0xff) as u8;
            output.push(out);
        }
    }

    Some(output)
}

fn insert_discord_candidate(
    map: &mut HashMap<String, DiscordCandidate>,
    username: Option<&str>,
    id: Option<&str>,
    source: &str,
) {
    let normalized_id = id.and_then(normalize_discord_id);
    let normalized_username = username.and_then(normalize_discord_username);

    let Some(normalized_id) = normalized_id else {
        return;
    };
    let key = format!("id:{normalized_id}");

    let entry = map.entry(key).or_insert_with(|| DiscordCandidate {
        username: normalized_username
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        id: Some(normalized_id.clone()),
        sources: BTreeSet::new(),
        profile_keys: BTreeSet::new(),
        evidence_hits: 0,
    });

    if entry.username == "unknown" {
        if let Some(username) = normalized_username {
            entry.username = username;
        }
    }

    entry.evidence_hits += 1;
    entry.sources.insert(source.to_string());

    if let Some(profile) = profile_key_from_path(Path::new(source)) {
        entry.profile_keys.insert(profile);
    }
}

fn normalize_discord_username(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'');
    if trimmed.len() < 2 || trimmed.len() > 64 {
        return None;
    }

    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
    {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn normalize_discord_id(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'');
    if trimmed.len() < 17 || trimmed.len() > 20 {
        return None;
    }

    if !trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    let parsed = trimmed.parse::<u64>().ok()?;
    if !is_valid_discord_snowflake(parsed) {
        return None;
    }

    Some(trimmed.to_string())
}

fn discord_id_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(id) => normalize_discord_id(id),
        Value::Number(number) => normalize_discord_id(&number.to_string()),
        _ => None,
    }
}

fn is_valid_discord_snowflake(id: u64) -> bool {
    let timestamp_ms = (id >> 22).saturating_add(DISCORD_EPOCH_MS);
    if timestamp_ms < DISCORD_EPOCH_MS {
        return false;
    }

    let now_ms = Utc::now().timestamp_millis();
    let timestamp_ms_i64 = i64::try_from(timestamp_ms).ok();
    let Some(timestamp_ms_i64) = timestamp_ms_i64 else {
        return false;
    };

    if timestamp_ms_i64 > now_ms.saturating_add(MAX_DISCORD_FUTURE_SKEW_MS) {
        return false;
    }

    if timestamp_ms_i64 < i64::try_from(DISCORD_EPOCH_MS).unwrap_or(0) {
        return false;
    }

    true
}

fn is_discord_owner_store_key(user_key: &[u8]) -> bool {
    let key_text = String::from_utf8_lossy(user_key).to_ascii_lowercase();
    key_text.contains("multiaccountstore")
        || key_text.contains("test/token")
        || key_text.contains("user_id_cache")
}

fn discord_payload_looks_owner_related(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    text.contains("multiaccountstore")
        || text.contains("test/token")
        || text.contains("user_id_cache")
}

fn is_discord_leveldb_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".ldb") {
                return true;
            }

            let Some((stem, ext)) = lower.rsplit_once('.') else {
                return false;
            };
            ext == "log" && stem.chars().all(|ch| ch.is_ascii_digit())
        })
}

fn build_profile_links(
    minecraft_profile_accounts: &HashMap<String, BTreeSet<String>>,
    discord_profile_accounts: &HashMap<String, BTreeSet<String>>,
) -> Vec<ProfileLink> {
    let mut keys = BTreeSet::<String>::new();
    keys.extend(minecraft_profile_accounts.keys().cloned());
    keys.extend(discord_profile_accounts.keys().cloned());

    let mut out = Vec::<ProfileLink>::new();

    for key in keys {
        let minecraft_accounts = minecraft_profile_accounts
            .get(&key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();

        let discord_accounts = discord_profile_accounts
            .get(&key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();

        if minecraft_accounts.is_empty() || discord_accounts.is_empty() {
            continue;
        }

        out.push(ProfileLink {
            profile: key,
            minecraft_accounts,
            discord_accounts,
        });
    }

    out
}
fn normalize_minecraft_username(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'');
    if trimmed.len() < 3 || trimmed.len() > 16 {
        return None;
    }

    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn path_looks_minecraft_related(path: &Path) -> bool {
    let lower = normalize_path_key(path);
    [
        "\\.minecraft",
        "\\minecraft",
        "\\tlauncher",
        "\\lunarclient",
        "\\prismlauncher",
        "\\multimc",
        "\\modrinth",
        "\\gdlauncher",
        "\\hmcl",
        "\\labymod",
        "\\sklauncher",
        "\\salwyrr",
        "\\curseforge",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn path_has_segment(path: &Path, expected_segment: &str) -> bool {
    let expected = expected_segment.to_ascii_lowercase();
    path.components().any(|component| match component {
        Component::Normal(value) => value.to_string_lossy().to_ascii_lowercase() == expected,
        _ => false,
    })
}

fn push_unique_dir(roots: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
    if !path.is_dir() {
        return;
    }
    let key = normalize_path_key(&path);
    if seen.insert(key) {
        roots.push(path);
    }
}

fn push_unique_file(files: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
    if !path.is_file() {
        return;
    }
    let key = normalize_path_key(&path);
    if seen.insert(key) {
        files.push(path);
    }
}

fn normalize_path_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn profile_key_from_path(path: &Path) -> Option<String> {
    let mut drive = String::new();
    let mut parts = Vec::<String>::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                drive = prefix.as_os_str().to_string_lossy().to_string();
            }
            Component::RootDir => {}
            Component::Normal(value) => {
                parts.push(value.to_string_lossy().to_string());
            }
            Component::CurDir | Component::ParentDir => {}
        }
    }

    for index in 0..parts.len() {
        if parts[index].eq_ignore_ascii_case("users") && index + 1 < parts.len() {
            let user = parts[index + 1].clone();
            if user.is_empty() {
                return None;
            }

            if drive.is_empty() {
                return Some(format!("Users\\{user}"));
            }
            return Some(format!(r"{drive}\Users\{user}"));
        }
    }

    None
}

fn read_gzip_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("Failed to open gzip {}: {error}", path.display()))?;
    let mut decoder = GzDecoder::new(file);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| format!("Failed to read gzip {}: {error}", path.display()))?;
    Ok(out)
}

fn extract_json_fragments(text: &str, max_fragments: usize, max_len: usize) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut fragments = Vec::new();
    let mut stack = Vec::<u8>::new();
    let mut start = None::<usize>;
    let mut in_string = false;
    let mut escaped = false;

    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match *byte {
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                if stack.is_empty() {
                    start = Some(index);
                }
                stack.push(*byte);
            }
            b'}' | b']' => {
                let Some(last) = stack.last().copied() else {
                    continue;
                };
                let is_match = (last == b'{' && *byte == b'}') || (last == b'[' && *byte == b']');
                if !is_match {
                    stack.clear();
                    start = None;
                    continue;
                }

                stack.pop();
                if stack.is_empty() {
                    if let Some(fragment_start) = start {
                        let fragment_end = index + 1;
                        let fragment_len = fragment_end.saturating_sub(fragment_start);
                        if fragment_len >= 8 && fragment_len <= max_len {
                            fragments.push(text[fragment_start..fragment_end].to_string());
                            if fragments.len() >= max_fragments {
                                break;
                            }
                        }
                    }
                    start = None;
                }
            }
            _ => {}
        }
    }

    fragments
}

fn extract_printable_chunks(bytes: &[u8], min_len: usize, max_chunks: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = Vec::<u8>::new();

    for byte in bytes {
        let printable = matches!(*byte, b'\n' | b'\r' | b'\t') || (32..=126).contains(byte);
        if printable {
            current.push(*byte);
        } else {
            if current.len() >= min_len {
                chunks.push(String::from_utf8_lossy(&current).to_string());
                if chunks.len() >= max_chunks {
                    return chunks;
                }
            }
            current.clear();
        }
    }

    if current.len() >= min_len && chunks.len() < max_chunks {
        chunks.push(String::from_utf8_lossy(&current).to_string());
    }

    chunks
}

fn normalize_escaped_json_text(text: &str) -> String {
    if !text.contains("\\\"")
        && !text.contains("\\n")
        && !text.contains("\\r")
        && !text.contains("\\t")
    {
        return text.to_string();
    }

    text.replace("\\\\\"", "\"")
        .replace("\\\"", "\"")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\\/", "/")
}

fn analyze_usn_forensic_signals(report: Option<&usn_journal::UsnJournalReport>) -> Vec<String> {
    let mut signals = Vec::<String>::new();

    let Some(report) = report else {
        return signals;
    };

    analyze_usn_event_group(
        "Minecraft",
        &report.minecraft_events,
        is_minecraft_log_trace,
        &mut signals,
    );

    analyze_usn_event_group(
        "Discord",
        &report.discord_events,
        is_discord_trace,
        &mut signals,
    );

    if signals.is_empty() {
        signals.push("USN: явных признаков чистки логов не обнаружено".to_string());
    }

    signals
}

fn analyze_usn_event_group(
    label: &str,
    events: &[usn_journal::UsnEvent],
    path_matcher: fn(&str) -> bool,
    signals: &mut Vec<String>,
) {
    let mut deleted = 0usize;
    let mut renamed = 0usize;
    let mut overwritten = 0usize;
    let mut matched = 0usize;
    let mut samples = Vec::<(String, String, String)>::new();

    for event in events {
        let path_lower = event.path.to_ascii_lowercase();
        if !path_matcher(&path_lower) {
            continue;
        }
        matched += 1;

        let reason = event.reason.to_ascii_lowercase();
        let suspicious = if reason.contains("deleted") || reason.contains("удален") {
            deleted += 1;
            true
        } else if reason.contains("renamed") || reason.contains("переимен") {
            renamed += 1;
            true
        } else if reason.contains("overwrite")
            || reason.contains("stream")
            || reason.contains("extend")
            || reason.contains("changed")
        {
            overwritten += 1;
            true
        } else {
            false
        };

        if suspicious && samples.len() < 8 {
            samples.push((
                event.timestamp_utc.clone(),
                event.reason.clone(),
                event.path.clone(),
            ));
        }
    }

    let suspicious_total = deleted + renamed + overwritten;
    if suspicious_total == 0 {
        if matched > 0 {
            signals.push(format!(
                "USN {label}: манипуляций не выявлено (событий: {matched})"
            ));
        }
        return;
    }

    signals.push(format!(
        "USN {label}: возможна манипуляция (удалено: {deleted}, переименовано: {renamed}, изменено: {overwritten})"
    ));

    for (timestamp, reason, path) in samples {
        signals.push(format!("USN {label}: [{reason}] {timestamp} | {path}"));
    }
}

fn is_minecraft_log_trace(path: &str) -> bool {
    let file = usn_file_name(path);
    let lower = file.to_ascii_lowercase();
    lower == "latest.log"
        || lower == "debug.log"
        || lower.strip_prefix("latest.log.").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
        })
        || lower.strip_prefix("debug.log.").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
        })
        || MINECRAFT_DATED_LOG_RE.is_match(&lower)
}

fn is_discord_trace(path: &str) -> bool {
    path.contains("discord")
        && (path.ends_with(".ldb")
            || path.ends_with(".log")
            || path.contains("local storage\\leveldb"))
}

fn usn_file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minecraft_name_normalization_works() {
        assert_eq!(
            normalize_minecraft_username("Alpha_01"),
            Some("Alpha_01".to_string())
        );
        assert_eq!(normalize_minecraft_username("ab"), None);
        assert_eq!(normalize_minecraft_username("bad-name"), None);
    }

    #[test]
    fn minecraft_json_context_filters_noise() {
        let sample = serde_json::json!({
            "displayName": "LooksLikeName",
            "title": "Player"
        });

        let mut out = BTreeSet::new();
        collect_minecraft_names_from_json(&sample, &mut out, false);
        assert!(out.is_empty());
    }

    #[test]
    fn minecraft_json_account_context_keeps_username() {
        let sample = serde_json::json!({
            "accounts": [{
                "username": "Novellisimo",
                "uuid": "ab"
            }]
        });

        let mut out = BTreeSet::new();
        collect_minecraft_names_from_json(&sample, &mut out, false);
        assert!(out.contains("Novellisimo"));
    }

    #[test]
    fn discord_snowflake_validation() {
        assert!(normalize_discord_id("698025508365008949").is_some());
        assert!(normalize_discord_id("123").is_none());
    }

    #[test]
    fn base64_url_decoder_decodes_ascii() {
        let decoded = decode_base64_url("MTIzNDU2").expect("must decode base64");
        assert_eq!(decoded, b"123456");
    }

    #[test]
    fn foreign_context_detector_marks_other_user() {
        let text = "\"other_user\":{\"id\":\"1388529174477672588\",\"username\":\"imsandy.dll\"}";
        let lower = text.to_ascii_lowercase();
        let pos = lower
            .find("\"username\":\"imsandy.dll\"")
            .expect("must contain username");
        assert!(is_foreign_context_near_position(&lower, pos));
    }

    #[test]
    fn foreign_context_detector_keeps_current_user_when_closer() {
        let text = "\"other_user\":{\"id\":\"1388529174477672588\"},\"current_user\":{\"id\":\"698025508365008949\",\"username\":\"jumarf\"}";
        let lower = text.to_ascii_lowercase();
        let pos = lower
            .find("\"username\":\"jumarf\"")
            .expect("must contain username");
        assert!(!is_foreign_context_near_position(&lower, pos));
    }

    #[test]
    fn profile_key_extraction_from_windows_path() {
        let path = Path::new(r"C:\Users\jumarf\AppData\Roaming\.minecraft\launcher_accounts.json");
        assert_eq!(
            profile_key_from_path(path),
            Some(r"C:\Users\jumarf".to_string())
        );
    }

    #[test]
    fn minecraft_placeholder_requires_multiple_logs() {
        let mut candidate = MinecraftCandidate {
            username: "Player123".to_string(),
            sources: BTreeSet::new(),
            profile_keys: BTreeSet::new(),
            account_hits: 0,
            log_hits: 1,
        };

        let (kept, _, _) = classify_minecraft_candidate(&candidate);
        assert!(!kept);

        candidate.log_hits = 3;
        let (kept, _, _) = classify_minecraft_candidate(&candidate);
        assert!(kept);
    }

    #[test]
    fn discord_candidate_requires_id() {
        let mut map = HashMap::<String, DiscordCandidate>::new();
        insert_discord_candidate(&mut map, Some("jumarf"), None, "src");
        assert!(map.is_empty());

        insert_discord_candidate(&mut map, Some("jumarf"), Some("698025508365008949"), "src");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn discord_owner_store_key_filter_is_strict() {
        assert!(is_discord_owner_store_key(
            b"_https://discord.com MultiAccountStore"
        ));
        assert!(is_discord_owner_store_key(b"test/token"));
        assert!(is_discord_owner_store_key(b"user_id_cache"));
        assert!(!is_discord_owner_store_key(b"redux-storage"));
        assert!(!is_discord_owner_store_key(
            b"_https://example.com SelectedChannelStore"
        ));
    }

    #[test]
    fn discord_context_profile_url_keeps_id_only_account() {
        let mut map = HashMap::<String, DiscordCandidate>::new();
        extract_discord_accounts_from_context_text(
            "https://discord.com/users/1394584725926187069",
            "ctx",
            &mut map,
        );
        assert!(map.contains_key("id:1394584725926187069"));
    }

    #[test]
    fn discord_context_encoded_user_extracts_username_and_id() {
        let mut map = HashMap::<String, DiscordCandidate>::new();
        extract_discord_accounts_from_context_text(
            "%22id%22%3A%221394584725926187069%22%2C%22username%22%3A%22mini_pekka123123%22",
            "ctx",
            &mut map,
        );

        let entry = map
            .get("id:1394584725926187069")
            .expect("must contain parsed id");
        assert_eq!(entry.username, "mini_pekka123123");
    }
}
