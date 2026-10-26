import {
  Check,
  CircleAlert,
  FileWarning,
  Lock,
  MonitorSmartphone,
  PhoneOff,
  ShieldAlert,
  ShieldCheck,
  Unplug,
  Zap,
} from "lucide-react";
import { desktop, request } from "./api";
import { Empty, Panel, RiskBadge, Toggle, type Confirmation } from "./components";
import type { ObservedApp, Snapshot } from "./types";

const has = (app: ObservedApp, rule: string) =>
  app.risk.evidence.some((e) => e.rule === rule);

export default function Protection({
  data,
  busy,
  confirm,
  onSelect,
  update,
  block,
  allow,
}: {
  data: Snapshot;
  busy: boolean;
  confirm: (action: Confirmation) => void;
  onSelect: (app: ObservedApp) => void;
  update: (patch: object) => void;
  block: (kind: "application" | "endpoint", target: string) => void;
  allow: (kind: "application" | "endpoint", target: string, enabled: boolean) => void;
}) {
  const remote = data.apps.filter((a) => a.risk.remote_tool);
  const connected = remote.filter((a) => has(a, "remote-access-tool"));
  const inbound = data.apps.filter((a) => has(a, "inbound-remote-login"));
  const exposed = [
    ...new Set(
      data.apps.flatMap(
        (a) => a.risk.evidence.find((e) => e.rule === "exposed-remote-service")?.ports || [],
      ),
    ),
  ].sort((a, b) => a - b);
  const shells = data.apps.filter((a) => has(a, "reverse-shell") || has(a, "raw-network-tool"));
  const theft = data.apps.filter((a) =>
    a.risk.evidence.some(
      (e) => e.category === "exfil" || ["upload-volume", "document-spawned"].includes(e.rule),
    ),
  );
  const lockdown = data.rules.find(
    (r) => r.kind === "ports" && r.target === data.firewall.lockdown,
  );
  const threats = connected.length + inbound.length + shells.length + theft.length;
  const endSession = (app: ObservedApp) =>
    confirm({
      title: "End " + (app.risk.remote_tool || app.name) + "?",
      description:
        "Beaver will stop every running " +
        app.name +
        " process (PID " +
        app.pids.join(", ") +
        "). Anyone connected through it is disconnected immediately. Unsaved work in that program is lost. If the program runs as a system service, block it in Firewall as well.",
      label: "End session",
      run: () => request("terminate", { app_id: app.id }),
    });
  const toggleLockdown = () =>
    confirm(
      lockdown
        ? {
            title: "Turn off remote access lockdown?",
            description:
              "Incoming connections to Remote Desktop, VNC, Telnet, WinRM and TeamViewer direct ports will be allowed again by Beaver. Other firewall policies still apply.",
            label: "Turn off lockdown",
            run: () => request("unblock", { id: lockdown.id }),
          }
        : {
            title: "Enable remote access lockdown?",
            description:
              "Beaver will add one inbound firewall rule blocking TCP ports " +
              data.firewall.lockdown.replace(/,/g, ", ") +
              " (Telnet, Remote Desktop, VNC, TeamViewer direct, WinRM) from every network. Outgoing connections and SSH are not affected. The operating system will ask for authorization.",
            label: "Enable lockdown",
            run: () => request("block", { kind: "ports", target: data.firewall.lockdown }),
          },
    );
  return (
    <>
      <div className={"protection-band " + (threats ? "attention" : "")}>
        <div className="protection-icon">
          {threats ? <ShieldAlert size={36} /> : <ShieldCheck size={40} />}
        </div>
        <div>
          <h2>
            {threats
              ? threats + " remote-access or data-theft signal" + (threats === 1 ? "" : "s") + " active"
              : "No one appears to be controlling this computer"}
          </h2>
          <p>
            {threats
              ? "Review each item below. If you did not expect it, end the session first, then investigate."
              : "Beaver watches for remote-control software, internet logins, reverse shells and data being sent to theft channels."}
          </p>
        </div>
      </div>
      <div className="shield-grid">
        <Panel
          title="Remote control"
          action={<span className="muted">{remote.length} tool{remote.length === 1 ? "" : "s"} running</span>}
        >
          {remote.length ? (
            <div className="rule-list">
              {remote.map((app) => (
                <div className="rule-row" key={app.id}>
                  <MonitorSmartphone size={22} className={has(app, "remote-access-tool") ? "danger-text" : ""} />
                  <div>
                    <button className="link-button" onClick={() => onSelect(app)}>
                      <strong>{app.risk.remote_tool}</strong>
                    </button>
                    <small>
                      {app.name} ·{" "}
                      {has(app, "remote-access-tool")
                        ? "connected to the internet"
                        : app.risk.allowlisted
                          ? "allowlisted by you"
                          : "running, no internet session observed"}
                    </small>
                  </div>
                  <div className="row-actions">
                    <button className="danger-button" disabled={busy || !desktop} onClick={() => endSession(app)}>
                      <PhoneOff size={15} />
                      End session
                    </button>
                    {app.path && data.firewall.application && (
                      <button disabled={busy || !desktop} onClick={() => block("application", app.path!)}>
                        Block
                      </button>
                    )}
                    {app.path && (
                      <button
                        disabled={busy || !desktop}
                        onClick={() => allow("application", app.path!, !app.risk.allowlisted)}
                      >
                        {app.risk.allowlisted ? "Stop trusting" : "I use this"}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <Empty title="No remote-control software running">
              AnyDesk, TeamViewer, Quick Assist, ScreenConnect, NetSupport and 30 other remote-access tools are recognized.
            </Empty>
          )}
        </Panel>
        <Panel
          title="Incoming remote access"
          action={
            <span className={"subtle-tag " + (lockdown ? "good-tag" : "")}>
              {lockdown ? "Lockdown on" : "Lockdown off"}
            </span>
          }
        >
          <div className="panel-body">
            {inbound.map((app) => (
              <div className="inline-error" key={app.id}>
                <CircleAlert size={15} /> {app.risk.evidence.find((e) => e.rule === "inbound-remote-login")?.title}:{" "}
                {app.risk.evidence.find((e) => e.rule === "inbound-remote-login")?.endpoint}{" "}
                <button className="link-button" onClick={() => onSelect(app)}>
                  Investigate
                </button>
              </div>
            ))}
            <p>
              {exposed.length
                ? "Reachable remote-login services on this computer: " + exposed.join(", ") + "."
                : "No remote-login service (RDP, VNC, Telnet, WinRM, SSH) is listening on a network address."}
            </p>
            <p className="small muted">
              Lockdown blocks incoming Remote Desktop, VNC, Telnet, WinRM and TeamViewer direct connections from every network with a single firewall rule. It does not
              stop support tools that connect outward through a relay, which is why those are listed separately.
            </p>
            <button
              className={lockdown ? "" : "primary"}
              disabled={busy || !desktop || !data.firewall.ports}
              onClick={toggleLockdown}
            >
              <Lock size={15} />
              {lockdown ? "Turn off lockdown" : "Enable remote access lockdown"}
            </button>
            {lockdown?.state === "missing" && (
              <p className="inline-error">The lockdown rule is missing from the OS firewall. Turn it off and on again to restore it.</p>
            )}
          </div>
        </Panel>
        <Panel title="Data theft and hijacked shells">
          {theft.length || shells.length ? (
            <div className="rule-list">
              {[...shells, ...theft].map((app) => (
                <div className="rule-row" key={app.id}>
                  <FileWarning size={22} className="danger-text" />
                  <div>
                    <button className="link-button" onClick={() => onSelect(app)}>
                      <strong>{app.name}</strong>
                    </button>
                    <small>
                      {app.risk.evidence
                        .filter((e) => ["remote", "exfil"].includes(e.category || "") || e.rule === "upload-volume")
                        .map((e) => e.title)
                        .join(" · ")}
                    </small>
                  </div>
                  <RiskBadge level={app.risk.level} />
                </div>
              ))}
            </div>
          ) : (
            <Empty title="No data-theft signals">
              Beaver flags uploads to Telegram bots and anonymous file-sharing services, command shells connected to the internet, and lopsided upload volume.
              {!data.coverage.capture.active && !data.coverage.dns_cache.names
                ? " Enable packet capture to see domain-based signals."
                : ""}
            </Empty>
          )}
        </Panel>
        <Panel title="Active protection">
          <div className="panel-body">
            <Toggle
              label="Stop confirmed threats automatically"
              description="When an unsigned program shows a reverse shell, process impersonation, fileless execution, a tampered signature, a threat-feed match or a data-theft channel at High risk, Beaver ends it immediately and tells you. Signed and operating-system programs are never stopped automatically."
              checked={data.settings.active_protection}
              disabled={busy || !desktop}
              onChange={() => update({ active_protection: !data.settings.active_protection })}
            />
            <Toggle
              label="Always notify about remote access"
              description="Show a notification whenever remote-control software connects or someone logs in from the internet, even if Medium-risk notifications are off."
              checked={data.settings.remote_alerts}
              disabled={busy || !desktop}
              onChange={() => update({ remote_alerts: !data.settings.remote_alerts })}
            />
          </div>
        </Panel>
      </div>
      <Panel title="If you think someone has access to your computer" className="spaced-panel">
        <ol className="steps">
          <li>
            <Unplug size={18} />
            <span>
              <strong>Disconnect first.</strong> End the remote session above, or turn off Wi-Fi and unplug the network cable.
            </span>
          </li>
          <li>
            <PhoneOff size={18} />
            <span>
              <strong>Hang up.</strong> Real banks, Microsoft and support companies never call to ask you to install remote-access software or pay with gift cards.
            </span>
          </li>
          <li>
            <Zap size={18} />
            <span>
              <strong>Change passwords from another device</strong>, starting with email and banking, and turn on two-factor authentication.
            </span>
          </li>
          <li>
            <Check size={18} />
            <span>
              <strong>Uninstall tools you did not install yourself</strong>, then contact your bank if you shared payment details.
            </span>
          </li>
        </ol>
      </Panel>
    </>
  );
}
