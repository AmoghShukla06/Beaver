import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import {
  Activity,
  AppWindow,
  ArrowDown,
  ArrowUp,
  Bell,
  Check,
  ChevronRight,
  CircleAlert,
  Database,
  Download,
  Globe2,
  LayoutDashboard,
  Leaf,
  LockKeyhole,
  Network,
  Radio,
  RefreshCw,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  X,
} from "lucide-react";
import { bytes, desktop, isStale, request, when } from "./api";
import {
  AppTable,
  Brand,
  Confirm,
  Empty,
  EvidenceItem,
  Panel,
  RiskBadge,
  Search,
  Toggle,
  TrafficChart,
  type Confirmation,
} from "./components";
import Connections from "./Connections";
import Investigation from "./Investigation";
import Protection from "./Protection";
import type { ObservedApp, Snapshot } from "./types";
const WorldMap = lazy(() => import("./WorldMap"));
const pages = [
  {
    id: "overview",
    title: "Overview",
    icon: LayoutDashboard,
    heading: "Network overview",
    description: "Know what connects. Understand what matters.",
  },
  {
    id: "protection",
    title: "Remote shield",
    icon: ShieldAlert,
    heading: "Remote access & data-theft shield",
    description: "Make sure no one else is controlling your computer or taking your data.",
  },
  {
    id: "applications",
    title: "Applications",
    icon: AppWindow,
    heading: "Applications",
    description:
      "Every observable connection, with the context to investigate.",
  },
  {
    id: "connections",
    title: "Connections",
    icon: Network,
    heading: "Live connections",
    description: "Search every observable socket by address, domain, port or country.",
  },
  {
    id: "map",
    title: "World map",
    icon: Globe2,
    heading: "Your global connections",
    description: "Explore where your network reaches. Keep your data here.",
  },
  {
    id: "alerts",
    title: "Alerts",
    icon: Bell,
    heading: "Threat alerts",
    description: "Evidence you can inspect. Decisions you control.",
  },
  {
    id: "firewall",
    title: "Firewall",
    icon: ShieldCheck,
    heading: "Network controls",
    description: "Manage native firewall rules and your trusted exceptions.",
  },
  {
    id: "settings",
    title: "Settings",
    icon: Settings2,
    heading: "Settings",
    description: "Make Beaver work the way you do.",
  },
];
export default function App() {
  const [page, setPage] = useState("overview");
  const [data, setData] = useState<Snapshot | null>(null);
  const [error, setError] = useState("");
  const [now, setNow] = useState(Date.now());
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [appPage, setAppPage] = useState(0);
  const [selected, setSelected] = useState<ObservedApp | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [failure, setFailure] = useState("");
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [retry, setRetry] = useState(0);
  const [alertFilter, setAlertFilter] = useState("Unreviewed");
  const [target, setTarget] = useState<{ page: string; app_id?: string } | null>(null);
  const refresh = useCallback(async () => {
    const value = await request<Snapshot>("snapshot");
    setData(value);
    setError("");
  }, []);
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    // A minimized or covered window stops polling entirely; the tray and notifications keep working.
    const poll = async () => {
      clearTimeout(timer);
      if (document.hidden) return;
      try {
        const value = await request<Snapshot>("snapshot");
        if (active) {
          setData(value);
          setError("");
        }
      } catch (e) {
        if (active) setError((e as Error).message);
      }
      if (active) timer = setTimeout(poll, 2000);
    };
    poll();
    document.addEventListener("visibilitychange", poll);
    return () => {
      active = false;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", poll);
    };
  }, [retry]);
  useEffect(() => window.beaver?.on_navigate((value) => setTarget(value)), []);
  useEffect(() => {
    if (!target || !data) return;
    setPage(pages.some((p) => p.id === target.page) ? target.page : "overview");
    const app = target.app_id && data.apps.find((a) => a.id === target.app_id);
    setSelected(app || null);
    setTarget(null);
  }, [target, data]);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const currentPage = pages.find((item) => item.id === page)!;
  useEffect(() => {
    document.title = "Beaver · " + currentPage.heading;
  }, [currentPage.heading]);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(""), 6000);
    return () => clearTimeout(timer);
  }, [notice]);
  const navigate = (id: string) => {
    setPage(id);
    setSelected(null);
  };
  const perform = async (fn: () => Promise<any>, message: string) => {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const result = await fn();
      if (!result?.cancelled) setNotice(message);
      await refresh();
    } catch (e) {
      setFailure((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const block = (kind: "application" | "endpoint", target: string) =>
    setConfirmation({
      title:
        kind === "application"
          ? "Block this application?"
          : "Block this remote endpoint?",
      description:
        target +
        (kind === "application"
          ? " will be blocked for inbound and outbound traffic at this exact executable path. Other versions at different paths are unaffected."
          : " will be blocked for inbound and outbound traffic across all applications. Shared services may be interrupted.") +
        " The operating system will request authorization. You can remove the rule in Firewall.",
      label: "Block " + (kind === "application" ? "application" : "endpoint"),
      run: () => request("block", { kind, target }),
    });
  const allow = (
    kind: "application" | "endpoint",
    target: string,
    enabled: boolean,
  ) =>
    setConfirmation({
      title: enabled
        ? "Allowlist this " + kind + "?"
        : "Remove allowlist exception?",
      description:
        target +
        (enabled
          ? " will be excluded from behavioral heuristics. Fresh threat-feed matches still raise alerts. This does not remove firewall blocks or create an OS allow rule."
          : " will be assessed by behavioral heuristics again."),
      label: enabled ? "Allowlist" : "Remove exception",
      run: () => request("allowlist", { kind, target, enabled }),
    });
  const update = (patch: object) =>
    perform(() => request("settings", { patch }), "Settings saved.");
  const stale = isStale(data, now) || Boolean(error);
  const selectedApp =
    data?.apps.find((app) => app.id === selected?.id) || selected;
  const filtered =
    data?.apps.filter(
      (app) =>
        (filter === "All" || app.risk.level === filter) &&
        (app.name + " " + app.path + " " + app.pids.join(" "))
          .toLowerCase()
          .includes(search.toLowerCase()),
    ) || [];
  const unreviewed = data?.alerts.filter((a) => !a.acknowledged).length || 0;
  const levels = (level: string) =>
    data?.apps.filter((a) => a.risk.level === level).length || 0;
  const remoteLive =
    data?.apps.filter((a) =>
      a.risk.evidence.some((e) => e.category === "remote" && e.points >= 30),
    ) || [];
  const visibleAlerts =
    data?.alerts.filter((a) =>
      alertFilter === "All"
        ? true
        : alertFilter === "Unreviewed"
          ? !a.acknowledged
          : a.level === alertFilter,
    ) || [];
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <nav aria-label="Main navigation">
          {pages.map((item) => (
            <button
              key={item.id}
              className={"nav-item " + (page === item.id ? "active" : "")}
              aria-current={page === item.id ? "page" : undefined}
              title={item.title}
              onClick={() => navigate(item.id)}
            >
              <item.icon size={20} />
              <span>{item.title}</span>
              {item.id === "alerts" && unreviewed > 0 && (
                <b className="nav-count">{unreviewed}</b>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <Leaf size={21} />
          <div>
            <strong>Local-first privacy</strong>
            <small>Your data stays on this device.</small>
          </div>
        </div>
        <span className="version">BEAVER / 1.0.0</span>
      </aside>
      <main>
        <header className="page-header">
          <div>
            <h1>{currentPage.heading}</h1>
            <p>{currentPage.description}</p>
          </div>
          <div className={"live-status " + (stale ? "stale" : "")}>
            <span>
              <i />
              {stale
                ? data
                  ? "Monitoring needs attention"
                  : "Connecting to your device"
                : "Live monitoring"}
            </span>
            <small>
              {data?.sampled_at
                ? "Last sample " +
                  new Date(data.sampled_at * 1000).toLocaleTimeString()
                : "Starting local telemetry"}
            </small>
          </div>
        </header>
        {!desktop && (
          <div className="preview-note">
            <LockKeyhole size={15} />
            Live, read-only browser preview. Open the desktop app to manage
            rules and settings.
          </div>
        )}
        {error && (
          <div className="error-banner" role="alert">
            <CircleAlert size={18} />
            <span>{error}</span>
            <button onClick={() => setRetry((x) => x + 1)}>
              Retry connection
            </button>
          </div>
        )}
        {failure && (
          <div className="error-banner" role="alert">
            <CircleAlert size={18} />
            <span>{failure}</span>
            <button
              className="icon-button"
              aria-label="Dismiss action error"
              onClick={() => setFailure("")}
            >
              <X size={16} />
            </button>
          </div>
        )}
        {data?.coverage.inventory_error && (
          <div className="error-banner" role="alert">
            {data.coverage.inventory_error}. Displayed data may be stale.
          </div>
        )}
        {!data ? (
          <div className="loading-surface" role="status">
            <RefreshCw className="spinner" />
            <h2>Connecting to your network</h2>
            <p>Reading observable connections from the operating system.</p>
          </div>
        ) : (
          <>
            {selectedApp ? (
              <Investigation
                key={selectedApp.id}
                app={selectedApp}
                data={data}
                onClose={() => setSelected(null)}
                block={block}
                allow={allow}
                perform={perform}
                busy={busy}
                confirm={setConfirmation}
              />
            ) : (
              <>
                {page === "overview" && (
                  <>
                    <div
                      className={
                        "protection-band " + (unreviewed ? "attention" : "")
                      }
                    >
                      <div className="protection-icon">
                        {unreviewed ? (
                          <CircleAlert size={36} />
                        ) : (
                          <ShieldCheck size={40} />
                        )}
                      </div>
                      <div>
                        <h2>
                          {stale
                            ? "Waiting for a fresh network sample"
                            : remoteLive.length
                              ? "Remote access detected: " +
                                remoteLive
                                  .map((a) => a.risk.remote_tool || a.name)
                                  .join(", ")
                              : unreviewed
                                ? unreviewed +
                                  " alert" +
                                  (unreviewed === 1 ? "" : "s") +
                                  " ready for review"
                                : "Monitoring your network"}
                        </h2>
                        <p>
                          {stale
                            ? "Coverage is limited until the local service responds."
                            : remoteLive.length
                              ? "If you did not start this session yourself, end it now from the Remote shield."
                              : `${data.coverage.intel.entries.toLocaleString()} threat indicators · ${levels("High")} high and ${levels("Medium")} medium-risk apps · explainable detections, you stay in control.`}
                        </p>
                      </div>
                      <button
                        className="text-button"
                        onClick={() =>
                          navigate(
                            remoteLive.length
                              ? "protection"
                              : unreviewed
                                ? "alerts"
                                : "settings",
                          )
                        }
                      >
                        {remoteLive.length
                          ? "Open Remote shield"
                          : unreviewed
                            ? "Review alerts"
                            : "View coverage"}
                        <ChevronRight size={16} />
                      </button>
                    </div>
                    <div className="risk-strip" aria-label="Applications by risk level">
                      {(["High", "Medium", "Low", "Unknown"] as const).map(
                        (level) => (
                          <button
                            key={level}
                            className={
                              "risk-count risk-" +
                              (levels(level) || level === "Low"
                                ? level.toLowerCase()
                                : "unknown")
                            }
                            onClick={() => {
                              setFilter(level);
                              setAppPage(0);
                              navigate("applications");
                            }}
                          >
                            <strong>{levels(level)}</strong>
                            <span>{level} risk</span>
                          </button>
                        ),
                      )}
                    </div>
                    <div className="metrics">
                      <button
                        className="metric"
                        onClick={() => navigate("applications")}
                      >
                        <Network />
                        <span>
                          <small>Active connections</small>
                          <strong>
                            {data.connections
                              .filter(
                                (c) =>
                                  c.remote_ip &&
                                  ![
                                    "TIME_WAIT",
                                    "CLOSE",
                                    "CLOSE_WAIT",
                                    "FIN_WAIT1",
                                    "FIN_WAIT2",
                                    "LAST_ACK",
                                    "CLOSING",
                                  ].includes(c.status),
                              )
                              .length.toLocaleString()}
                          </strong>
                          <em>
                            {
                              data.connections.filter((c) => !c.remote_ip)
                                .length
                            }{" "}
                            listening or unconnected sockets
                          </em>
                        </span>
                        <ChevronRight size={16} />
                      </button>
                      <button
                        className="metric"
                        onClick={() => navigate("applications")}
                      >
                        <AppWindow />
                        <span>
                          <small>Observed applications</small>
                          <strong>
                            {data.apps
                              .filter((a) => a.id !== "unattributed")
                              .length.toLocaleString()}
                          </strong>
                          <em>
                            {
                              data.apps.filter(
                                (a) => a.risk.level === "Unknown",
                              ).length
                            }{" "}
                            awaiting risk assessment
                          </em>
                        </span>
                        <ChevronRight size={16} />
                      </button>
                      <div className="metric">
                        <Activity />
                        <span>
                          <small>Network throughput</small>
                          <strong>
                            {bytes(
                              data.download_bps == null ||
                                data.upload_bps == null
                                ? null
                                : data.download_bps + data.upload_bps,
                              true,
                            )}
                          </strong>
                          <em>
                            ↓ {bytes(data.download_bps, true)} · ↑{" "}
                            {bytes(data.upload_bps, true)}
                          </em>
                        </span>
                      </div>
                    </div>
                    <div className="overview-grid">
                      <TrafficChart points={data.traffic} />
                      <Panel title="Monitoring coverage">
                        <div className="coverage-list">
                          <Coverage
                            icon={Network}
                            title="Connections"
                            text="Operating-system socket inventory"
                            status={stale ? "Limited" : "Active"}
                            good={!stale}
                          />
                          <Coverage
                            icon={Radio}
                            title="Packet capture"
                            text={
                              data.coverage.capture.active
                                ? "Attributing observed IP-layer bytes"
                                : data.coverage.capture.error
                                  ? "Capture unavailable on this device"
                                  : "Enable for application traffic speeds"
                            }
                            status={
                              data.coverage.capture.active
                                ? "Active"
                                : data.settings.capture
                                  ? "Unavailable"
                                  : "Off"
                            }
                            good={data.coverage.capture.active}
                          />
                          <Coverage
                            icon={Database}
                            title="Threat intelligence"
                            text={
                              data.coverage.intel.fresh
                                ? data.coverage.intel.entries +
                                  " fresh local indicators"
                                : "Download the latest threat feed"
                            }
                            status={
                              data.coverage.intel.fresh
                                ? "Current"
                                : data.coverage.intel.updated
                                  ? "Stale"
                                  : "Not loaded"
                            }
                            good={data.coverage.intel.fresh}
                          />
                          <Coverage
                            icon={ShieldAlert}
                            title="Remote access shield"
                            text={
                              remoteLive.length
                                ? remoteLive.length + " active remote-access signal(s)"
                                : data.rules.some((r) => r.kind === "ports")
                                  ? "Lockdown on · watching remote-control tools"
                                  : "Watching remote-control tools and logins"
                            }
                            status={remoteLive.length ? "Attention" : "Active"}
                            good={!remoteLive.length}
                          />
                        </div>
                        <button
                          className="coverage-link text-button"
                          onClick={() => navigate("settings")}
                        >
                          Manage coverage
                          <ChevronRight size={14} />
                        </button>
                      </Panel>
                    </div>
                    <div className="overview-grid lower">
                      <Panel
                        title="Observed applications"
                        action={
                          <button
                            className="text-button"
                            onClick={() => navigate("applications")}
                          >
                            View all
                            <ChevronRight size={15} />
                          </button>
                        }
                      >
                        <AppTable
                          apps={data.apps}
                          onSelect={setSelected}
                          compact
                        />
                      </Panel>
                      <Panel
                        title="Recent alerts"
                        action={
                          <button
                            className="text-button"
                            onClick={() => navigate("alerts")}
                          >
                            View all
                          </button>
                        }
                      >
                        {data.alerts.length ? (
                          <div className="recent-alerts">
                            {data.alerts.slice(0, 3).map((alert) => (
                              <button
                                key={alert.id}
                                onClick={() => navigate("alerts")}
                              >
                                <CircleAlert size={20} />
                                <span>
                                  <strong>{alert.app_name}</strong>
                                  <small>{alert.title}</small>
                                </span>
                                <ChevronRight size={15} />
                              </button>
                            ))}
                          </div>
                        ) : (
                          <div className="empty alert-empty">
                            <Bell size={36} />
                            <h3>No alerts recorded</h3>
                            <p>
                              {data.coverage.intel.fresh
                                ? "New high-risk detections will appear here."
                                : "Load threat intelligence to assess known malicious endpoints."}
                            </p>
                            <span className="subtle-tag">
                              Visibility is not a safety guarantee
                            </span>
                          </div>
                        )}
                      </Panel>
                    </div>
                  </>
                )}
                {page === "applications" && (
                  <>
                    <div className="toolbar">
                      <Search
                        value={search}
                        onChange={(value) => {
                          setSearch(value);
                          setAppPage(0);
                        }}
                      />
                      <label className="select-label">
                        Risk{" "}
                        <select
                          value={filter}
                          onChange={(e) => {
                            setFilter(e.target.value);
                            setAppPage(0);
                          }}
                        >
                          {["All", "High", "Medium", "Low", "Unknown"].map(
                            (level) => (
                              <option key={level}>{level}</option>
                            ),
                          )}
                        </select>
                      </label>
                    </div>
                    <Panel
                      title="Network-active applications"
                      action={
                        <span className="muted">
                          {filtered.length} observed
                        </span>
                      }
                    >
                      <AppTable
                        apps={filtered}
                        onSelect={setSelected}
                        page={appPage}
                        onPage={setAppPage}
                      />
                    </Panel>
                    <div className="info-line">
                      <CircleAlert size={16} />
                      <span>
                        Process visibility depends on OS permissions.
                        Short-lived connections may be missed between two-second
                        samples. Application speeds require packet capture.
                      </span>
                    </div>
                  </>
                )}
                {page === "protection" && (
                  <Protection
                    data={data}
                    busy={busy}
                    confirm={setConfirmation}
                    onSelect={setSelected}
                    update={update}
                    block={block}
                    allow={allow}
                  />
                )}
                {page === "connections" && (
                  <Connections data={data} onSelect={setSelected} />
                )}
                {page === "map" && (
                  <Suspense
                    fallback={
                      <div className="loading-surface">
                        Loading the offline map…
                      </div>
                    }
                  >
                    <WorldMap
                      data={data}
                      onSettings={() => navigate("settings")}
                    />
                  </Suspense>
                )}
                {page === "alerts" && (
                  <>
                    <div className="info-line">
                      <Shield size={17} />
                      <span>
                        High and Medium detections are preserved locally. The
                        same evidence from the same application is recorded once
                        every 12 hours; new evidence raises a new alert.
                        Acknowledging does not change evidence or unblock
                        traffic.
                      </span>
                    </div>
                    <div className="toolbar">
                      <div className="segmented" aria-label="Alert filter">
                        {["Unreviewed", "High", "Medium", "All"].map((f) => (
                          <button
                            key={f}
                            aria-pressed={alertFilter === f}
                            onClick={() => setAlertFilter(f)}
                          >
                            {f}
                          </button>
                        ))}
                      </div>
                      <button
                        disabled={busy || !desktop || !unreviewed}
                        onClick={() =>
                          perform(
                            () => request("acknowledge", { id: "*" }),
                            "All alerts acknowledged.",
                          )
                        }
                      >
                        <Check size={15} />
                        Acknowledge all
                      </button>
                    </div>
                    <Panel
                      title="Detection timeline"
                      action={
                        <span className="muted">
                          {unreviewed} unreviewed · latest 200 retained alerts
                        </span>
                      }
                    >
                      {visibleAlerts.length ? (
                        <div className="alert-list">
                          {visibleAlerts.map((alert) => (
                            <article
                              key={alert.id}
                              className={
                                "alert-item " +
                                (alert.acknowledged ? "reviewed" : "") +
                                " level-" +
                                alert.level.toLowerCase()
                              }
                            >
                              <div className="alert-item-title">
                                <CircleAlert />
                                <div>
                                  <h3>{alert.app_name}</h3>
                                  <p>
                                    {alert.title} · {when(alert.created)}
                                    {alert.endpoint &&
                                      " · " +
                                        (alert.endpoint.domain ||
                                          alert.endpoint.ip) +
                                        (alert.endpoint.country
                                          ? " (" + alert.endpoint.country + ")"
                                          : "")}
                                  </p>
                                </div>
                                <RiskBadge level={alert.level} />
                              </div>
                              {alert.response && (
                                <p
                                  className={
                                    alert.response.action === "terminated"
                                      ? "inline-note"
                                      : "inline-error"
                                  }
                                >
                                  {alert.response.action === "terminated"
                                    ? "Active protection stopped this program at " +
                                      when(alert.response.at)
                                    : "Active protection could not stop this program: " +
                                      alert.response.error}
                                </p>
                              )}
                              {alert.risk.evidence
                                .filter((evidence) => evidence.points > 0)
                                .map((evidence) => (
                                  <EvidenceItem
                                    key={evidence.rule + evidence.endpoint}
                                    evidence={evidence}
                                  />
                                ))}
                              <div className="action-row">
                                <button
                                  disabled={
                                    busy || !desktop || alert.acknowledged
                                  }
                                  onClick={() =>
                                    perform(
                                      () =>
                                        request("acknowledge", {
                                          id: alert.id,
                                        }),
                                      "Alert acknowledged.",
                                    )
                                  }
                                >
                                  {alert.acknowledged ? (
                                    <>
                                      <Check size={15} />
                                      Acknowledged
                                    </>
                                  ) : (
                                    "Acknowledge"
                                  )}
                                </button>
                                {data.apps.some(
                                  (a) => a.id === alert.app_id,
                                ) && (
                                  <button
                                    onClick={() =>
                                      setSelected(
                                        data.apps.find(
                                          (a) => a.id === alert.app_id,
                                        )!,
                                      )
                                    }
                                  >
                                    Investigate application
                                  </button>
                                )}
                              </div>
                            </article>
                          ))}
                        </div>
                      ) : data.alerts.length ? (
                        <Empty title="Nothing in this view">
                          Choose All to see reviewed alerts.
                        </Empty>
                      ) : (
                        <Empty title="No threat alerts recorded">
                          {data.coverage.intel.fresh
                            ? "Beaver will record high-risk signals here as they are detected."
                            : "Enable or refresh threat intelligence in Settings to check known command-and-control endpoints."}
                        </Empty>
                      )}
                    </Panel>
                  </>
                )}
                {page === "firewall" && (
                  <>
                    <div className="info-line">
                      <LockKeyhole size={17} />
                      <span>
                        Beaver only manages its own rules. Rules persist after
                        Beaver exits. Endpoint rules affect all applications.
                        Beaver checks its rules against the OS firewall at
                        startup and when you choose Verify; a rule removed
                        outside Beaver is marked missing.
                      </span>
                    </div>
                    <Panel
                      title="Native firewall rules"
                      action={
                        <div className="map-tools">
                          <span className="subtle-tag">
                            {data.firewall.platform === "Windows"
                              ? "Windows Defender Firewall"
                              : "nftables"}
                          </span>
                          <button
                            disabled={busy || !desktop || !data.rules.length}
                            onClick={() =>
                              perform(async () => {
                                const result = await request<{
                                  verified: boolean;
                                  note?: string;
                                }>("verify_rules");
                                if (!result.verified) throw new Error(result.note);
                                return result;
                              }, "Firewall rules verified against the operating system.")
                            }
                          >
                            <RefreshCw size={15} />
                            Verify
                          </button>
                        </div>
                      }
                    >
                      {data.rules.length ? (
                        <div className="rule-list">
                          {data.rules.map((rule) => (
                            <div className="rule-row" key={rule.id}>
                              <Shield
                                size={22}
                                className={rule.state === "applied" ? "" : "danger-text"}
                              />
                              <div>
                                <strong className="break-word">
                                  {rule.kind === "ports"
                                    ? (rule.target === data.firewall.lockdown
                                        ? "Remote access lockdown · "
                                        : "Inbound TCP ports ") + rule.target
                                    : rule.target}
                                </strong>
                                <small>
                                  {rule.kind === "ports" ? "inbound ports" : rule.kind}{" "}
                                  · {rule.state} · last verified{" "}
                                  {when(rule.verified_at)}
                                </small>
                                <span className="mono small">{rule.id}</span>
                              </div>
                              <button
                                disabled={busy || !desktop}
                                onClick={() =>
                                  setConfirmation({
                                    title: "Remove this firewall rule?",
                                    description:
                                      rule.target +
                                      " will no longer be blocked by this Beaver rule. Other firewall policies still apply.",
                                    label: "Remove block",
                                    run: () =>
                                      request("unblock", { id: rule.id }),
                                  })
                                }
                              >
                                Unblock
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <Empty title="No Beaver firewall rules">
                          Inspect an application or remote connection to add a
                          native block. Beaver never blocks automatically.
                        </Empty>
                      )}
                    </Panel>
                    <Panel
                      title="Allowlist exceptions"
                      className="spaced-panel"
                    >
                      {data.allowlist.length ? (
                        <div className="rule-list">
                          {data.allowlist.map((entry) => (
                            <div className="rule-row" key={entry.id}>
                              <Check size={21} />
                              <div>
                                <strong className="break-word">
                                  {entry.target}
                                </strong>
                                <small>
                                  {entry.kind} · behavioral heuristics only;
                                  threat matches still evaluated
                                </small>
                              </div>
                              <button
                                disabled={busy || !desktop}
                                onClick={() =>
                                  allow(
                                    entry.kind as "application" | "endpoint",
                                    entry.target,
                                    false,
                                  )
                                }
                              >
                                Remove exception
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <Empty title="No allowlist exceptions">
                          Add an exception from an investigation when you
                          understand the application's behavior. Allowlisting
                          never overrides firewall blocks.
                        </Empty>
                      )}
                    </Panel>
                  </>
                )}
                {page === "settings" && (
                  <div className="settings-grid">
                    <div>
                      <Panel title="Detection & notifications">
                        <div className="panel-body">
                          <Toggle
                            label="Native desktop notifications"
                            description="Notify on new high-risk and remote-access detections, including while Beaver runs in the tray."
                            checked={data.settings.notifications}
                            disabled={busy || !desktop}
                            onChange={() =>
                              update({
                                notifications: !data.settings.notifications,
                              })
                            }
                          />
                          <Toggle
                            label="Also notify for Medium risk"
                            description="Medium alerts are always recorded. Turn this on to be notified about them too."
                            checked={data.settings.notify_medium}
                            disabled={busy || !desktop || !data.settings.notifications}
                            onChange={() =>
                              update({
                                notify_medium: !data.settings.notify_medium,
                              })
                            }
                          />
                          {data.settings.snoozed_until * 1000 > now && (
                            <div className="inline-note">
                              Notifications are paused until{" "}
                              {new Date(
                                data.settings.snoozed_until * 1000,
                              ).toLocaleTimeString()}
                              .{" "}
                              <button
                                className="link-button"
                                disabled={busy || !desktop}
                                onClick={() => update({ snoozed_until: 0 })}
                              >
                                Resume now
                              </button>
                            </div>
                          )}
                          <button
                            disabled={busy || !desktop}
                            onClick={() =>
                              perform(
                                () => request("test_notification"),
                                "Test notification requested. Check your operating system notification settings if it does not appear.",
                              )
                            }
                          >
                            <Bell size={15} />
                            Send test notification
                          </button>
                          <Toggle
                            label="Automatic threat-feed updates"
                            description="Download enabled threat feeds when they are due (hourly for botnet C2, twice a day for the rest). Observed IPs, domains and application data are never uploaded."
                            checked={data.settings.feed_updates}
                            disabled={busy || !desktop}
                            onChange={() =>
                              update({
                                feed_updates: !data.settings.feed_updates,
                              })
                            }
                          />
                          <div className="feed-list">
                            {data.coverage.intel.feeds.map((feed) => (
                              <label key={feed.id} className="feed-row">
                                <input
                                  type="checkbox"
                                  checked={feed.enabled}
                                  disabled={busy || !desktop}
                                  onChange={() =>
                                    update({
                                      disabled_feeds: feed.enabled
                                        ? [...data.settings.disabled_feeds, feed.id]
                                        : data.settings.disabled_feeds.filter(
                                            (id) => id !== feed.id,
                                          ),
                                    })
                                  }
                                />
                                <span>
                                  <strong>{feed.name}</strong>
                                  <small>
                                    {feed.category} ·{" "}
                                    {feed.entries.toLocaleString()} entries ·{" "}
                                    {feed.points >= 80 ? "can raise High" : "raises Medium"}
                                    {feed.error ? " · " + feed.error : ""}
                                  </small>
                                </span>
                                <i
                                  className={
                                    "feed-state " +
                                    (feed.fresh ? "good" : feed.enabled && feed.updated ? "stale" : "")
                                  }
                                >
                                  {!feed.enabled
                                    ? "Off"
                                    : feed.fresh
                                      ? "Current"
                                      : feed.updated
                                        ? "Stale"
                                        : "Not loaded"}
                                </i>
                              </label>
                            ))}
                          </div>
                          <div className="feed-details">
                            <span>
                              {data.coverage.intel.entries.toLocaleString()} current indicators ·{" "}
                              {data.coverage.intel.fresh
                                ? "Current"
                                : "Not current"}
                            </span>
                            <small>
                              Last successful update:{" "}
                              {when(data.coverage.intel.updated)}
                            </small>
                            <button
                              className="primary"
                              disabled={busy || !desktop}
                              onClick={() =>
                                perform(
                                  () => request("refresh_feed"),
                                  "Threat intelligence updated. Risk assessments refresh on the next sample.",
                                )
                              }
                            >
                              <RefreshCw size={15} />
                              {busy
                                ? "Working…"
                                : "Refresh threat intelligence"}
                            </button>
                          </div>
                          <p className="small muted">
                            Sources: abuse.ch Feodo Tracker, Spamhaus DROP,
                            HaGeZi Threat Intelligence, Emerging Threats and
                            IPsum. Matching is entirely local. Stale feeds stop
                            producing detections. Provider terms apply.
                          </p>
                        </div>
                      </Panel>
                      <Panel
                        title="Network visibility"
                        className="spaced-panel"
                      >
                        <div className="panel-body">
                          <Toggle
                            label="Packet metadata capture"
                            description="Measure attributable application traffic and observe plaintext DNS. Requires Npcap on Windows or packet-capture permissions on Linux. Payloads are never stored."
                            checked={data.settings.capture}
                            disabled={busy || !desktop}
                            onChange={() =>
                              update({ capture: !data.settings.capture })
                            }
                          />
                          <div className="inline-note">
                            {data.coverage.capture.active
                              ? data.coverage.capture.packets.toLocaleString() +
                                " packets observed · " +
                                data.coverage.capture.attributed.toLocaleString() +
                                " attributed to applications. Capture covers interfaces available when enabled."
                              : data.coverage.capture.error ||
                                "Capture is off. Socket inventory and aggregate interface traffic remain available."}
                          </div>
                          <p className="small muted">
                            {data.coverage.inventory} {data.coverage.domains}{" "}
                            OS-level restrictions can limit visibility even when
                            capture is enabled.
                          </p>
                        </div>
                      </Panel>
                    </div>
                    <div>
                      <Panel title="Local geolocation">
                        <div className="panel-body">
                          <div className="setting-symbol">
                            <Globe2 size={28} />
                          </div>
                          <h3>Put your connections on the map</h3>
                          <p>
                            Choose a local MaxMind-compatible City .mmdb
                            database. No connection addresses leave your device.
                          </p>
                          <p className="path-label mono">
                            {data.settings.geoip_path ||
                              "No local database configured"}
                          </p>
                          {data.coverage.geo.error && (
                            <p className="inline-error">
                              {data.coverage.geo.error}
                            </p>
                          )}
                          <button
                            disabled={busy || !desktop}
                            onClick={() =>
                              perform(
                                () => request("pick_geoip"),
                                "Geolocation database updated.",
                              )
                            }
                          >
                            <Database size={15} />
                            Choose local database
                          </button>
                          <button className="primary geo-download" disabled={busy || !desktop} onClick={() => perform(() => request("download_geoip"), "Offline City database downloaded and configured.")}><Download size={15}/>{busy ? "Working…" : "Download free City database"}</button>
                          <p className="small muted">Downloads the monthly DB-IP City Lite database (CC BY 4.0; may use up to 150 MB). No observed IP addresses are sent. <a href="https://db-ip.com/" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</a>.</p>
                          {data.settings.geoip_path && (
                            <button
                              className="text-button"
                              disabled={busy || !desktop}
                              onClick={() => update({ geoip_path: "" })}
                            >
                              Remove database
                            </button>
                          )}
                          <p className="small muted">
                            Obtain a City database from your preferred licensed
                            provider. Approximate geolocation never contributes
                            to risk.
                          </p>
                        </div>
                      </Panel>
                      <Panel title="Privacy & desktop" className="spaced-panel">
                        <div className="panel-body">
                          <Toggle
                            label="Start Beaver when I sign in"
                            description="Start monitoring in the tray at sign-in without opening a window."
                            checked={data.settings.start_at_login}
                            disabled={busy || !desktop}
                            onChange={() =>
                              update({
                                start_at_login: !data.settings.start_at_login,
                              })
                            }
                          />
                          <Toggle
                            label="Close to system tray"
                            description="Keep monitoring when the window closes. The window is fully unloaded to save memory. Choose Quit Beaver from the tray to stop."
                            checked={data.settings.close_to_tray}
                            disabled={busy || !desktop}
                            onChange={() =>
                              update({
                                close_to_tray: !data.settings.close_to_tray,
                              })
                            }
                          />
                          <label className="setting-select" htmlFor="retention">
                            Local history retention
                            <select
                              id="retention"
                              value={data.settings.retention_days}
                              disabled={busy || !desktop}
                              onChange={(event) =>
                                update({
                                  retention_days: Number(event.target.value),
                                })
                              }
                            >
                              {[1, 3, 7, 14, 30].map((day) => (
                                <option key={day} value={day}>
                                  {day} day{day === 1 ? "" : "s"}
                                </option>
                              ))}
                            </select>
                          </label>
                          <p className="small muted">
                            Expired history is pruned within a minute. Storage
                            is bounded to 100,000 connection records and 10,000
                            alerts.
                          </p>
                          <label className="small muted">
                            Local data directory
                          </label>
                          <p className="path-label mono">{data.data_path}</p>
                          <div className="privacy-note">
                            <Leaf size={17} />
                            <span>
                              No analytics. No cloud account. No payload
                              storage.
                            </span>
                          </div>
                        </div>
                      </Panel>
                    </div>
                  </div>
                )}
              </>
            )}
            <footer className="footer">
              <span>
                <Wifi size={13} />
                {data.coverage.platform} · Local telemetry
              </span>
              <span>
                {data.coverage.elevated
                  ? "Elevated service"
                  : "Standard user session"}{" "}
                ·{" "}
                {data.coverage.capture.active
                  ? "Packet capture active"
                  : "Socket monitoring"}
              </span>
            </footer>
          </>
        )}
      </main>
      <Confirm
        action={confirmation}
        busy={busy}
        onClose={() => setConfirmation(null)}
        onConfirm={() => {
          if (confirmation)
            void perform(async () => {
              const result = await confirmation.run();
              setConfirmation(null);
              return result;
            }, "Network control updated.");
        }}
      />
      {notice && (
        <div className="toast" role="status">
          <Check size={18} />
          <span>{notice}</span>
          <button
            className="icon-button"
            aria-label="Dismiss notification"
            onClick={() => setNotice("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}
function Coverage({
  icon: Icon,
  title,
  text,
  status,
  good,
}: {
  icon: typeof Network;
  title: string;
  text: string;
  status: string;
  good: boolean;
}) {
  return (
    <div className="coverage-row">
      <span className={"coverage-icon " + (good ? "good" : "")}>
        <Icon size={22} />
      </span>
      <div>
        <strong>{title}</strong>
        <small>{text}</small>
      </div>
      <span className={"coverage-state " + (good ? "good" : "")}>
        <i />
        {status}
      </span>
    </div>
  );
}
