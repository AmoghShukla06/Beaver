import { useEffect, useState } from "react";
import { Bug, Copy, ExternalLink, FolderOpen, RefreshCw, Rocket } from "lucide-react";
import { desktop, request, when } from "./api";
import { Panel } from "./components";
import type { AppInfo, UpdateState } from "./types";

const REPO = "https://github.com/AmoghShukla06/Beaver";

export function useAppInfo() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  useEffect(() => {
    if (!desktop) return;
    request<AppInfo>("app_info").then(setInfo).catch(() => {});
    return window.beaver?.on_update((update) => setInfo((i) => (i ? { ...i, update } : i)));
  }, []);
  return [info, setInfo] as const;
}

function status(update: UpdateState) {
  switch (update.state) {
    case "checking":
      return "Checking for updates…";
    case "downloading":
      return `Downloading ${update.version} (${update.percent ?? 0}%)`;
    case "ready":
      return `Version ${update.version} is ready to install`;
    case "latest":
      return "Up to date · checked " + when(update.checked_at);
    case "error":
      return "Couldn't check for updates · " + when(update.checked_at);
    case "off":
      return "Automatic updates are off";
    case "disabled":
      return "Updates are available in installed builds";
    default:
      return "Checks automatically every 6 hours";
  }
}

export default function About({ info }: { info: AppInfo | null }) {
  const [message, setMessage] = useState("");
  const run = (fn: () => Promise<unknown>, done: string) =>
    fn()
      .then(() => done && setMessage(done))
      .catch((e) => setMessage(e.message));
  return (
    <Panel title="About Beaver" className="spaced-panel">
      <div className="panel-body about">
        <div className="about-version">
          <strong>Beaver {info?.version ?? ""}</strong>
          <small>{info ? status(info.update) : "Browser preview"}</small>
        </div>
        <div className="action-row">
          {info?.update.state === "ready" ? (
            <button className="primary" onClick={() => run(() => request("restart_update"), "")}>
              <Rocket size={15} />
              Restart to update
            </button>
          ) : (
            <button
              disabled={!info?.packaged || info.update.state === "checking" || info.update.state === "downloading"}
              onClick={() => run(() => request("check_updates"), "")}
            >
              <RefreshCw size={15} />
              Check for updates
            </button>
          )}
          <button disabled={!desktop} onClick={() => run(() => request("copy_diagnostics"), "Diagnostics copied. Paste them into a GitHub issue.")}>
            <Copy size={15} />
            Copy diagnostics
          </button>
          <button disabled={!desktop} onClick={() => run(() => request("open_logs"), "")}>
            <FolderOpen size={15} />
            Open logs
          </button>
        </div>
        {message && <p className="small muted">{message}</p>}
        <p className="about-links">
          <a href={REPO + "/releases"} target="_blank" rel="noreferrer">
            Release notes <ExternalLink size={12} />
          </a>
          <a href={REPO + "/issues/new"} target="_blank" rel="noreferrer">
            <Bug size={12} /> Report a problem
          </a>
          <a href={REPO} target="_blank" rel="noreferrer">
            Source code
          </a>
          <a href={REPO + "/blob/main/THIRD_PARTY_NOTICES.md"} target="_blank" rel="noreferrer">
            Licenses
          </a>
        </p>
        <p className="small muted">Apache-2.0 · Diagnostics hide usernames and IP addresses.</p>
      </div>
    </Panel>
  );
}
