import { useEffect, useState } from "react";
import { ArrowLeft, Copy, Download, ExternalLink, OctagonX, Shield, X } from "lucide-react";
import { bytes, desktop, request, when } from "./api";
import {
  Empty,
  EvidenceItem,
  Panel,
  RiskBadge,
  SignatureBadge,
  type Confirmation,
} from "./components";
import type { Connection, ObservedApp, Snapshot } from "./types";
export default function Investigation({
  app,
  data,
  onClose,
  block,
  allow,
  perform,
  busy,
  confirm,
}: {
  confirm: (action: Confirmation) => void;
  app: ObservedApp;
  data: Snapshot;
  onClose: () => void;
  block: (kind: "application" | "endpoint", target: string) => void;
  allow: (
    kind: "application" | "endpoint",
    target: string,
    enabled: boolean,
  ) => void;
  perform: (fn: () => Promise<unknown>, message: string) => Promise<void>;
  busy: boolean;
}) {
  const [history, setHistory] = useState<Connection[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const live = data.connections.filter((c) => c.app_id === app.id);
  useEffect(() => {
    let valid = true;
    setLoading(true);
    setError("");
    request<{ items: Connection[]; total: number }>("history", {
      app_id: app.id,
      offset,
    })
      .then((r) => {
        if (valid) {
          setHistory(r.items);
          setTotal(r.total);
        }
      })
      .catch((e) => {
        if (valid) setError(e.message);
      })
      .finally(() => {
        if (valid) setLoading(false);
      });
    return () => {
      valid = false;
    };
  }, [app.id, offset]);
  return (
    <aside className="investigation" aria-label={"Investigation: " + app.name}>
      <div className="investigation-header">
        <button className="text-button" onClick={onClose}>
          <ArrowLeft size={16} />
          All applications
        </button>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label="Close investigation"
        >
          <X size={20} />
        </button>
      </div>
      <div className="investigation-title">
        <span className="app-avatar large">{app.name[0]?.toUpperCase()}</span>
        <div>
          <h2>{app.name}</h2>
          <RiskBadge level={app.risk.level} />
        </div>
        <div className="risk-score">
          <strong>{app.risk.score ?? "—"}</strong>
          <small>risk / 100</small>
        </div>
      </div>
      <p className="path-label mono">
        {app.path || "Executable path unavailable"}
      </p>
      <div className="action-row">
        <button
          className="danger-button"
          disabled={busy || !desktop || !app.path || !data.firewall.application}
          onClick={() => app.path && block("application", app.path)}
        >
          <Shield size={15} />
          Block application
        </button>
        <button
          disabled={busy || !desktop || !app.path}
          onClick={() =>
            app.path && allow("application", app.path, !app.risk.allowlisted)
          }
        >
          {app.risk.allowlisted ? "Remove allowlist" : "Allowlist application"}
        </button>
        <button
          disabled={busy || !desktop || !app.pids.length}
          onClick={() =>
            confirm({
              title: "End " + app.name + "?",
              description:
                "Beaver will stop " +
                app.pids.length +
                " running process" +
                (app.pids.length === 1 ? "" : "es") +
                " (PID " +
                app.pids.join(", ") +
                "). Unsaved work in this program is lost and its network connections close. Core Windows processes are refused.",
              label: "End process",
              run: () => request("terminate", { app_id: app.id }),
            })
          }
        >
          <OctagonX size={15} />
          End process
        </button>
        <button
          disabled={busy || !desktop}
          onClick={() =>
            perform(
              () => request("export_history", { app_id: app.id }),
              "History export finished.",
            )
          }
        >
          <Download size={15} />
          Export history
        </button>
      </div>
      {!data.firewall.application && (
        <p className="inline-note">
          Executable-path blocking is unavailable on Linux. You can block a
          remote endpoint below; that rule affects all applications.
        </p>
      )}
      <div className="detail-stats">
        <div>
          <small>Observed connections</small>
          <strong>{live.length}</strong>
        </div>
        <div>
          <small>Captured upload</small>
          <strong>{bytes(app.uploaded)}</strong>
        </div>
        <div>
          <small>Captured download</small>
          <strong>{bytes(app.downloaded)}</strong>
        </div>
      </div>
      <Panel title="Executable">
        <dl className="facts">
          <div>
            <dt>Signature</dt>
            <dd>
              {app.binary?.signature === null || !data.coverage.binaries.signatures
                ? "Authenticode checks are Windows-only"
                : <SignatureBadge app={app} />}
            </dd>
          </div>
          <div>
            <dt>Location</dt>
            <dd>
              {{
                system: "Installed program location",
                user: "User profile folder",
                staging: "Temporary or download folder",
                memory: "Shared memory",
              }[app.binary?.location || "user"] || "Unknown"}
            </dd>
          </div>
          <div>
            <dt>Started by</dt>
            <dd>{app.parent || "Unavailable"}</dd>
          </div>
          <div>
            <dt>First seen by Beaver</dt>
            <dd>{when(app.binary?.first_seen)}</dd>
          </div>
          <div className="wide">
            <dt>SHA-256</dt>
            <dd className="mono break-word">
              {app.binary?.sha256 || (app.binary?.state === "pending" ? "Hashing…" : "Unavailable")}
              {app.binary?.sha256 && (
                <span className="inline-actions">
                  <button
                    className="icon-button"
                    aria-label="Copy SHA-256"
                    onClick={() => void navigator.clipboard?.writeText(app.binary!.sha256!)}
                  >
                    <Copy size={14} />
                  </button>
                  <a
                    href={"https://www.virustotal.com/gui/file/" + app.binary.sha256}
                    target="_blank"
                    rel="noreferrer"
                    title="Opens VirusTotal in your browser. Only the hash is sent, and only when you click."
                  >
                    Look up on VirusTotal <ExternalLink size={12} />
                  </a>
                </span>
              )}
            </dd>
          </div>
        </dl>
      </Panel>
      <Panel title="Why this risk level?">
        <div className="panel-body">
          <p>{app.risk.reason}</p>
          {app.risk.allowlisted && (
            <p className="inline-note">
              Heuristic signals are suppressed by your allowlist. Fresh threat
              intelligence can still raise an alert.
            </p>
          )}
          {app.risk.evidence.length ? (
            app.risk.evidence.map((item) => (
              <EvidenceItem key={item.rule + item.endpoint} evidence={item} />
            ))
          ) : (
            <p className="muted">
              No scored signals in this sample. Limited visibility and missing
              intelligence are not proof of safety.
            </p>
          )}
        </div>
      </Panel>
      <Panel title="Current connections">
        <ConnectionTable
          connections={live.slice(0, 100)}
          block={block}
          allow={allow}
          data={data}
          busy={busy}
        />
        {live.length > 100 && (
          <p className="panel-body muted">
            Showing 100 of {live.length}. Export history for the complete
            retained record.
          </p>
        )}
      </Panel>
      <Panel
        title="Connection history"
        action={<span className="muted">{total} records</span>}
      >
        {loading ? (
          <div className="empty" role="status">
            Loading connection history…
          </div>
        ) : error ? (
          <p className="inline-error">{error}</p>
        ) : (
          <>
            <ConnectionTable
              connections={history}
              block={block}
              allow={allow}
              data={data}
              busy={busy}
              historical
            />
            <div className="pagination">
              <span>
                {total ? offset + 1 : 0}–{Math.min(offset + 50, total)} of{" "}
                {total}
              </span>
              <div>
                <button
                  disabled={!offset}
                  onClick={() => setOffset((o) => Math.max(0, o - 50))}
                >
                  Previous
                </button>
                <button
                  disabled={offset + 50 >= total}
                  onClick={() => setOffset((o) => o + 50)}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
      <p className="muted small">
        PIDs: {app.pids.join(", ") || "Unavailable"}. Byte totals are captured
        IP-layer traffic during this session. DNS names are observed answers,
        not verified endpoint identities.
      </p>
    </aside>
  );
}
function ConnectionTable({
  connections,
  block,
  allow,
  data,
  busy,
  historical = false,
}: {
  connections: Connection[];
  block: (kind: "application" | "endpoint", target: string) => void;
  allow: (
    kind: "application" | "endpoint",
    target: string,
    enabled: boolean,
  ) => void;
  data: Snapshot;
  busy: boolean;
  historical?: boolean;
}) {
  return connections.length ? (
    <div className="table-scroll">
      <table className="connection-table">
        <thead>
          <tr>
            <th>Remote endpoint / domain</th>
            <th>Protocol / state</th>
            <th>Local address</th>
            <th>{historical ? "Last observed" : "Location"}</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {connections.map((c) => {
            const rule = data.rules.find(
              (r) => r.kind === "endpoint" && r.target === c.remote_ip,
            );
            const allowed = data.allowlist.some(
              (r) => r.kind === "endpoint" && r.target === c.remote_ip,
            );
            return (
              <tr key={c.id}>
                <td>
                  <strong className="mono">
                    {c.remote_ip
                      ? c.remote_ip + ":" + c.remote_port
                      : "Listening / unconnected"}
                  </strong>
                  <small className={c.threat ? "danger-text" : ""}>
                    {c.domain || "Domain not observed"}
                    {c.threat ? " · " + (c.threat.name || "Threat feed") + " match" : ""}
                  </small>
                </td>
                <td>
                  {c.protocol}
                  <small>{c.status}</small>
                </td>
                <td className="mono">
                  {c.local_ip}:{c.local_port}
                </td>
                <td>
                  {historical
                    ? when(c.last_seen)
                    : c.geo?.country || "Unlocated"}
                  <small>
                    {historical
                      ? c.ended
                        ? "Ended " + when(c.ended)
                        : "Last observed active"
                      : c.source}
                  </small>
                </td>
                <td>
                  {c.remote_ip && !/^(127\.|::1$|::ffff:127\.|0\.0\.0\.0$|::$)/.test(c.remote_ip) && (
                    <div className="endpoint-actions">
                      <button
                        disabled={
                          busy ||
                          !desktop ||
                          !data.firewall.endpoint ||
                          Boolean(rule)
                        }
                        onClick={() => block("endpoint", c.remote_ip!)}
                      >
                        {rule ? "Rule recorded" : "Block IP"}
                      </button>
                      <button
                        disabled={busy || !desktop}
                        onClick={() =>
                          allow("endpoint", c.remote_ip!, !allowed)
                        }
                      >
                        {allowed ? "Remove allowlist" : "Allowlist IP"}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty title="No connections in this view">
      New observable activity will appear as it is sampled.
    </Empty>
  );
}
