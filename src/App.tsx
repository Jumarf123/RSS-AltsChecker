import { invoke } from "@tauri-apps/api/core";
import { useMemo, useState } from "react";
import type { ReactNode } from "react";

type Confidence = "max" | "low";
type Tab = "home" | "alts" | "steam" | "hwid";
type LoadingKind = "alts" | "steam" | "hwid" | null;
type WindowControl = "minimize" | "maximize" | "close";

type MinecraftAlt = {
  username: string;
  confidence: Confidence;
  sources: string[];
};

type DiscordAlt = {
  username: string;
  id?: string | null;
  confidence: Confidence;
  sources: string[];
};

type SteamBanStatus = {
  vac_banned?: boolean | null;
  number_of_vac_bans?: number | null;
  number_of_game_bans?: number | null;
  days_since_last_ban?: number | null;
  community_banned?: boolean | null;
  notes: string[];
};

type ThirdPartyCheck = {
  service: string;
  status: string;
  label: string;
  detail: string;
  url: string;
  checked_at: string;
  bot_check_required: boolean;
  raw_available: boolean;
};

type SteamAlt = {
  steam_id64: string;
  account_name?: string | null;
  persona_name?: string | null;
  avatar_url?: string | null;
  profile_url: string;
  bans: SteamBanStatus;
  third_party: ThirdPartyCheck[];
  confidence: Confidence;
  sources: string[];
};

type AuditReport = {
  signals: string[];
  registry_path?: string | null;
  minecraft_file_path?: string | null;
  manifest_file_path?: string | null;
};

type ScanReport = {
  minecraft_accounts: MinecraftAlt[];
  discord_accounts: DiscordAlt[];
  steam_accounts: SteamAlt[];
  forensic_signals: string[];
  warnings: string[];
  audit: AuditReport;
};

type SteamCheckReport = {
  steam_accounts: SteamAlt[];
  forensic_signals: string[];
  scanned_locations: string[];
  warnings: string[];
  audit: AuditReport;
};

type SystemHwid = {
  primary_hwid: string;
  raw: string;
  md5: string;
  sha256: string;
  motherboard_uuid?: string | null;
  bios_serial?: string | null;
  disk_serial?: string | null;
  machine_guid?: string | null;
  mac_address?: string | null;
  computer_name?: string | null;
  user_name?: string | null;
  warnings: string[];
};

type TauriWindow = Window & {
  __TAURI_INTERNALS__?: {
    invoke?: (command: string, args?: Record<string, unknown>, options?: unknown) => Promise<unknown>;
  };
};

const asset = (name: string) => `/assets/${name}`;

const tabs: Array<{ id: Tab; label: string; icon: string }> = [
  { id: "home", label: "Home", icon: asset("Home.png") },
  { id: "alts", label: "Alts", icon: asset("alts.png") },
  { id: "steam", label: "Steam", icon: asset("steam.png") },
  { id: "hwid", label: "HWID", icon: asset("HWID.png") },
];

const serviceLogo: Record<string, string> = {
  CSGOBans: asset("CSGOBans.png"),
  BanSearch: asset("BanSearch.png"),
};

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("home");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [loading, setLoading] = useState<LoadingKind>(null);
  const [altsReport, setAltsReport] = useState<ScanReport | null>(null);
  const [steamReport, setSteamReport] = useState<SteamCheckReport | null>(null);
  const [hwid, setHwid] = useState<SystemHwid | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const steamAccounts = steamReport?.steam_accounts ?? altsReport?.steam_accounts ?? [];

  const showToast = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 1400);
  };

  const copy = async (text: string, label = "Скопировано") => {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    showToast(label);
  };

  const fallbackForCommand = (command: string) => {
    if (command === "scan_alts") {
      return {
        minecraft_accounts: [],
        discord_accounts: [],
        steam_accounts: [],
        forensic_signals: [],
        warnings: [],
        audit: {
          signals: [],
          registry_path: null,
          minecraft_file_path: null,
          manifest_file_path: null,
        },
      } satisfies ScanReport;
    }
    if (command === "scan_steam") {
      return {
        steam_accounts: [],
        forensic_signals: [],
        scanned_locations: [],
        warnings: [],
        audit: {
          signals: [],
          registry_path: null,
          minecraft_file_path: null,
          manifest_file_path: null,
        },
      } satisfies SteamCheckReport;
    }
    if (command === "get_hwid") {
      return {
        primary_hwid: "",
        raw: "",
        md5: "",
        sha256: "",
        motherboard_uuid: null,
        bios_serial: null,
        disk_serial: null,
        machine_guid: null,
        mac_address: null,
        computer_name: null,
        user_name: null,
        warnings: [],
      } satisfies SystemHwid;
    }
    return null;
  };

  const runCommand = async <T,>(kind: LoadingKind, tab: Tab, command: string) => {
    setActiveTab(tab);
    const tauriInvoke = (window as TauriWindow).__TAURI_INTERNALS__?.invoke;
    if (!tauriInvoke) {
      return fallbackForCommand(command) as T;
    }
    setLoading(kind);
    setError(null);
    try {
      return await invoke<T>(command);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      throw err;
    } finally {
      setLoading(null);
    }
  };

  const scanAlts = async () => {
    const report = await runCommand<ScanReport>("alts", "alts", "scan_alts");
    setAltsReport(report);
  };

  const scanSteam = async () => {
    const report = await runCommand<SteamCheckReport>("steam", "steam", "scan_steam");
    setSteamReport(report);
  };

  const getHwid = async () => {
    const value = await runCommand<SystemHwid>("hwid", "hwid", "get_hwid");
    setHwid(value);
  };

  const openExternal = async (url: string) => {
    const tauriInvoke = (window as TauriWindow).__TAURI_INTERNALS__?.invoke;
    if (!tauriInvoke) {
      window.open(url, "_blank", "noopener,noreferrer");
      return;
    }
    await invoke("open_external_url", { url });
  };

  const controlWindow = async (action: WindowControl) => {
    try {
      if (action === "minimize") {
        await invoke("window_minimize");
        return;
      }
      if (action === "maximize") {
        await invoke("window_toggle_maximize");
        return;
      }
      await invoke("window_close");
    } catch (error) {
      console.warn("Window control failed", error);
    }
  };

  const reanalyseThirdParty = async (steamId64: string) => {
    const checks = await invoke<ThirdPartyCheck[]>("reanalyse_third_party", {
      steamId64,
    });
    setSteamReport((prev) =>
      prev
        ? {
            ...prev,
            steam_accounts: prev.steam_accounts.map((account) =>
              account.steam_id64 === steamId64
                ? { ...account, third_party: checks }
                : account,
            ),
          }
        : prev,
    );
    showToast("Reanalyse готов");
  };

  const discordBulkText = useMemo(() => {
    return (altsReport?.discord_accounts ?? [])
      .map((account) =>
        [account.username, account.id ?? "unknown", account.confidence].join(" | "),
      )
      .join("\n");
  }, [altsReport]);

  return (
    <div className={`app ${theme}`}>
      <header className="topbar">
        <div className="titlebar-drag-region" data-tauri-drag-region aria-hidden="true" />
        <a
          className="brand"
          href="https://discord.gg/residencescreenshare"
          onClick={(event) => {
            event.preventDefault();
            void openExternal("https://discord.gg/residencescreenshare");
          }}
          aria-label="RSS-AltsChecker Discord"
        >
          <img src={asset("logotip.png")} alt="RSS-AltsChecker" />
        </a>
        <nav>
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`${activeTab === tab.id ? "active" : ""} image-button tab-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
              aria-label={tab.label}
              title={tab.label}
            >
              <img className="tab-icon" src={tab.icon} alt="" />
            </button>
          ))}
        </nav>
        <div className="topbar-actions">
          <button
            className="theme-toggle"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label="Переключить тему"
            title={theme === "dark" ? "Light theme" : "Dark theme"}
          >
            <img src={theme === "dark" ? asset("day.png") : asset("night.png")} alt="" />
          </button>
          <div className="window-controls" aria-label="Window controls">
            <button
              className="window-control"
              onMouseDown={(event) => event.stopPropagation()}
              onClick={() => void controlWindow("minimize")}
              aria-label="Свернуть"
              title="Свернуть"
            >
              <img src={asset("Свернуть.png")} alt="" />
            </button>
            <button
              className="window-control"
              onMouseDown={(event) => event.stopPropagation()}
              onClick={() => void controlWindow("maximize")}
              aria-label="Развернуть или вернуть в окно"
              title="Развернуть или вернуть в окно"
            >
              <img src={asset("Свернуть_в_окно.png")} alt="" />
            </button>
            <button
              className="window-control close"
              onMouseDown={(event) => event.stopPropagation()}
              onClick={() => void controlWindow("close")}
              aria-label="Закрыть"
              title="Закрыть"
            >
              <img src={asset("Close.png")} alt="" />
            </button>
          </div>
        </div>
      </header>

      <main>
        {error && <div className="error">{error}</div>}
        {activeTab === "home" && (
          <HomeView scanAlts={scanAlts} scanSteam={scanSteam} getHwid={getHwid} />
        )}
        {activeTab === "alts" && (
          <AltsView
            report={altsReport}
            scanAlts={scanAlts}
            copy={copy}
            discordBulkText={discordBulkText}
          />
        )}
        {activeTab === "steam" && (
          <SteamView
            accounts={steamAccounts}
            scanSteam={scanSteam}
            copy={copy}
            openExternal={openExternal}
            warnings={steamReport?.warnings ?? []}
          />
        )}
        {activeTab === "hwid" && <HwidView hwid={hwid} getHwid={getHwid} copy={copy} />}
      </main>

      {loading && <LoadingOverlay label={loading === "steam" ? "Steam Check" : loading === "alts" ? "Alts Check" : "HWID Check"} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function HomeView({
  scanAlts,
  scanSteam,
  getHwid,
}: {
  scanAlts: () => void;
  scanSteam: () => void;
  getHwid: () => void;
}) {
  return (
    <section className="home">
      <div className="home-card">
        <button className="primary wide action-button" onClick={scanAlts}>
          Alts Check
        </button>
        <div className="home-actions">
          <button className="action-button" onClick={scanSteam}>
            Steam Check
          </button>
          <button className="action-button" onClick={getHwid}>
            HWID Check
          </button>
        </div>
      </div>
    </section>
  );
}

function AltsView({
  report,
  scanAlts,
  copy,
  discordBulkText,
}: {
  report: ScanReport | null;
  scanAlts: () => void;
  copy: (text: string, label?: string) => void;
  discordBulkText: string;
}) {
  return (
    <section className="workspace">
      <div className="toolbar">
        <button className="primary action-button" onClick={scanAlts}>
          Alts Check
        </button>
        <button onClick={() => copy(discordBulkText, "Discord скопирован")}>
          Copy Discord
        </button>
      </div>
      {!report ? (
        <Empty title="Alts Check ещё не запускался" />
      ) : (
        <div className="two-columns">
          <AccountColumn title={`Minecraft (${report.minecraft_accounts.length})`}>
            {report.minecraft_accounts.map((account) => (
              <details className="account-details" key={account.username}>
                <summary>{account.username}</summary>
                <Field label="nick" value={account.username} copy={copy} />
                <SourceList sources={account.sources} copy={copy} />
                <ConfidenceLine confidence={account.confidence} />
              </details>
            ))}
          </AccountColumn>
          <AccountColumn title={`Discord (${report.discord_accounts.length})`}>
            {report.discord_accounts.map((account) => (
              <details className="account-details" key={`${account.username}-${account.id}`}>
                <summary>{account.username}</summary>
                <Field label="nick" value={account.username} copy={copy} />
                <Field label="ID" value={account.id ?? "unknown"} copy={copy} mono />
                <SourceList sources={account.sources} copy={copy} />
                <ConfidenceLine confidence={account.confidence} />
              </details>
            ))}
          </AccountColumn>
        </div>
      )}
    </section>
  );
}

function SteamView({
  accounts,
  scanSteam,
  copy,
  openExternal,
  warnings,
}: {
  accounts: SteamAlt[];
  scanSteam: () => void;
  copy: (text: string, label?: string) => void;
  openExternal: (url: string) => void;
  warnings: string[];
}) {
  return (
    <section className="workspace">
      <div className="toolbar">
        <button className="primary action-button" onClick={scanSteam}>
          Steam Check
        </button>
        <span className="muted">{pluralizeRu(accounts.length, "аккаунт", "аккаунта", "аккаунтов")}</span>
      </div>
      {warnings.length > 0 && (
        <div className="warning-list">
          {warnings.map((warning) => (
            <span key={warning}>{warning}</span>
          ))}
        </div>
      )}
      {accounts.length === 0 ? (
        <Empty title="Steam Check ещё не запускался или аккаунты не найдены" />
      ) : (
        <div className="steam-grid">
          {accounts.map((account) => (
            <SteamCard
              key={account.steam_id64}
              account={account}
              copy={copy}
              openExternal={openExternal}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function SteamCard({
  account,
  copy,
  openExternal,
}: {
  account: SteamAlt;
  copy: (text: string, label?: string) => void;
  openExternal: (url: string) => void;
}) {
  const name = account.persona_name ?? account.account_name ?? account.steam_id64;
  const externalChecks = account.third_party.filter((check) =>
    check.service === "CSGOBans" || check.service === "BanSearch",
  );
  const hasSteamBan =
    account.bans.vac_banned === true || (account.bans.number_of_game_bans ?? 0) > 0;
  const lastBan =
    !hasSteamBan
      ? "Never"
      : account.bans.days_since_last_ban == null
        ? "unknown"
        : pluralizeRu(account.bans.days_since_last_ban, "день", "дня", "дней");
  return (
    <article className="steam-card">
      <div className="steam-head">
        <button
          className="avatar-link"
          onClick={() => openExternal(account.profile_url)}
          aria-label="Open Steam profile"
          title="Open Steam profile"
        >
          <Avatar url={account.avatar_url ?? undefined} />
          <span className="open-corner" aria-hidden="true">↗</span>
        </button>
        <div className="steam-title">
          <button className="value title-value" onClick={() => copy(name)}>
            {name}
          </button>
          <table className="steam-meta">
            <tbody>
              <tr>
                <th>SteamID64</th>
                <td>
                  <button className="value mono steam-id-value" onClick={() => copy(account.steam_id64)}>
                    {account.steam_id64}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <ConfidenceLine confidence={account.confidence} />
      </div>

      <div className="ban-grid">
        <StatusTile label="VAC" value={yesNo(account.bans.vac_banned)} status={statusFromBool(account.bans.vac_banned)} />
        <StatusTile label="Game bans" value={String(account.bans.number_of_game_bans ?? "unknown")} status={statusFromCount(account.bans.number_of_game_bans)} />
        <StatusTile label="Community" value={yesNo(account.bans.community_banned)} status={statusFromBool(account.bans.community_banned)} />
        <StatusTile label="Last ban" value={lastBan} status={hasSteamBan ? "warning" : "clean"} />
      </div>

      <div className="service-grid">
        {externalChecks.map((check) => (
          <button
            className={`service image-button ${check.status}`}
            key={check.service}
            onClick={() => {
              if (check.service === "CSGOBans") {
                copy(account.steam_id64, "SteamID скопирован");
              }
              openExternal(check.url);
            }}
            title={check.detail}
            aria-label={check.service}
          >
            {serviceLogo[check.service] ? <img className="service-logo" src={serviceLogo[check.service]} alt="" /> : "?"}
            <span className="open-corner" aria-hidden="true">↗</span>
          </button>
        ))}
      </div>
    </article>
  );
}

function HwidView({
  hwid,
  getHwid,
  copy,
}: {
  hwid: SystemHwid | null;
  getHwid: () => void;
  copy: (text: string, label?: string) => void;
}) {
  const emptyHwid: SystemHwid = {
    primary_hwid: "",
    raw: "",
    md5: "",
    sha256: "",
    motherboard_uuid: null,
    bios_serial: null,
    disk_serial: null,
    machine_guid: null,
    mac_address: null,
    computer_name: null,
    user_name: null,
    warnings: [],
  };
  const current = hwid ?? emptyHwid;
  const hasHwid = Boolean(
    current.primary_hwid || current.raw || current.sha256 || current.md5,
  );

  return (
    <section className="center-view">
      <div className="hwid-card">
        <button className="primary action-button hwid-trigger" onClick={getHwid}>
          HWID Check
        </button>
        {!hasHwid ? (
          <Empty title="HWID ещё не проверялся" />
        ) : (
          <div className="hwid-layout">
            <table className="hwid-table">
              <tbody>
                <HwidRow label="HWID" value={current.primary_hwid} copy={copy} mono />
                <HwidRow label="SHA-256" value={current.sha256} copy={copy} mono />
                <HwidRow label="MD5" value={current.md5} copy={copy} mono />
                <HwidRow label="RAW" value={current.raw} copy={copy} mono wrap />
                {current.motherboard_uuid && <HwidRow label="MB UUID" value={current.motherboard_uuid} copy={copy} mono />}
                {current.bios_serial && <HwidRow label="BIOS" value={current.bios_serial} copy={copy} mono />}
                {current.disk_serial && <HwidRow label="Disk" value={current.disk_serial} copy={copy} mono />}
                {current.machine_guid && <HwidRow label="MachineGuid" value={current.machine_guid} copy={copy} mono />}
                {current.mac_address && <HwidRow label="MAC" value={current.mac_address} copy={copy} mono />}
                {current.computer_name && <HwidRow label="Computer" value={current.computer_name} copy={copy} />}
                {current.user_name && <HwidRow label="User" value={current.user_name} copy={copy} />}
              </tbody>
            </table>
            {current.warnings.length > 0 && (
              <div className="warning-list">
                {current.warnings.map((warning) => (
                  <span key={warning}>{warning}</span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function AccountColumn({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="panel">
      <h2>{title}</h2>
      <div className="stack">{children}</div>
    </div>
  );
}

function Field({
  label,
  value,
  copy,
  mono = false,
}: {
  label: string;
  value: string;
  copy: (text: string, label?: string) => void;
  mono?: boolean;
}) {
  return (
    <div className="field">
      <span>{label}:</span>
      <button className={`value ${mono ? "mono" : ""}`} onClick={() => copy(value)}>
        {value}
      </button>
    </div>
  );
}

function HwidRow({
  label,
  value,
  copy,
  mono = false,
  wrap = false,
}: {
  label: string;
  value: string;
  copy: (text: string, label?: string) => void;
  mono?: boolean;
  wrap?: boolean;
}) {
  return (
    <tr className={wrap ? "wrap" : ""}>
      <th>{label}</th>
      <td>
        <button className={`value ${mono ? "mono" : ""} hwid-value ${wrap ? "wrap" : ""}`} onClick={() => copy(value)}>
          {value}
        </button>
      </td>
    </tr>
  );
}

function SourceList({
  sources,
  copy,
}: {
  sources: string[];
  copy: (text: string, label?: string) => void;
}) {
  return (
    <div className="sources">
      <span>source:</span>
      {sources.map((source) => (
        <button className="source-path" key={source} onClick={() => copy(source, "Source скопирован")}>
          {source}
        </button>
      ))}
    </div>
  );
}

function ConfidenceLine({ confidence }: { confidence: Confidence }) {
  return (
    <div className="confidence-line">
      <span>confidence:</span>
      <b className={`confidence ${confidence}`}>{confidence}</b>
    </div>
  );
}

function StatusTile({
  label,
  value,
  status,
}: {
  label: string;
  value: string;
  status: "clean" | "warning" | "banned" | "unknown";
}) {
  return (
    <div className={`status-tile ${status}`}>
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function Avatar({ url }: { url?: string }) {
  const [failed, setFailed] = useState(false);
  const highQualityUrl = url
    ?.replace("_medium.", "_full.")
    .replace("_medium/", "_full/");
  if (!highQualityUrl || failed) {
    return <div className="avatar fallback">?</div>;
  }
  return <img className="avatar" src={highQualityUrl} alt="Steam avatar" onError={() => setFailed(true)} />;
}

function Empty({ title }: { title: string }) {
  return <div className="empty">{title}</div>;
}

function LoadingOverlay({ label }: { label: string }) {
  return (
    <div className="loading">
      <div className="loader-card">
        <div className="spinner" />
        <h2>{label}</h2>
        <p>Идёт сканирование, подождите...</p>
      </div>
    </div>
  );
}

function yesNo(value?: boolean | null) {
  if (value == null) return "unknown";
  return value ? "Yes" : "No";
}

function statusFromBool(value?: boolean | null): "clean" | "banned" | "unknown" {
  if (value == null) return "unknown";
  return value ? "banned" : "clean";
}

function statusFromCount(value?: number | null): "clean" | "banned" | "unknown" {
  if (value == null) return "unknown";
  return value > 0 ? "banned" : "clean";
}

function pluralizeRu(count: number, one: string, few: string, many: string) {
  const abs = Math.abs(count);
  const mod10 = abs % 10;
  const mod100 = abs % 100;
  const word = mod10 === 1 && mod100 !== 11
    ? one
    : mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)
      ? few
      : many;
  return `${count} ${word}`;
}

export default App;
