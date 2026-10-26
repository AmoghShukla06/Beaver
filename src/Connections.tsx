import { useMemo, useState } from "react";
import { CircleAlert } from "lucide-react";
import { when } from "./api";
import { Empty, Panel, Search } from "./components";
import type { ObservedApp, Snapshot } from "./types";

const CLOSED = new Set(["TIME_WAIT", "CLOSE", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"]);
const PRIVATE = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:|fc|fd)/i;
const filters = ["All", "Internet", "Established", "Listening", "Threat matches"] as const;
const SIZE = 50;

export default function Connections({
  data,
  onSelect,
}: {
  data: Snapshot;
  onSelect: (app: ObservedApp) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<(typeof filters)[number]>("Internet");
  const [page, setPage] = useState(0);
  const apps = useMemo(() => new Map(data.apps.map((a) => [a.id, a])), [data.apps]);
  const rows = data.connections.filter((c) => {
    if (filter === "Internet" && (!c.remote_ip || PRIVATE.test(c.remote_ip))) return false;
    if (filter === "Established" && (!c.remote_ip || CLOSED.has(c.status))) return false;
    if (filter === "Listening" && c.status !== "LISTEN") return false;
    if (filter === "Threat matches" && !c.threat) return false;
    if (!query) return true;
    const app = apps.get(c.app_id);
    return [app?.name, c.remote_ip, c.remote_port, c.local_port, c.domain, c.geo?.country, c.protocol, c.status]
      .join(" ")
      .toLowerCase()
      .includes(query.toLowerCase());
  });
  rows.sort((a, b) => Number(Boolean(b.threat)) - Number(Boolean(a.threat)) || a.first_seen - b.first_seen);
  const safe = Math.min(page, Math.max(0, Math.ceil(rows.length / SIZE) - 1));
  return (
    <>
      <div className="toolbar">
        <Search
          value={query}
          onChange={(value) => {
            setQuery(value);
            setPage(0);
          }}
          placeholder="Search IPs, domains, ports, countries or applications"
        />
        <div className="segmented" aria-label="Connection filter">
          {filters.map((f) => (
            <button
              key={f}
              aria-pressed={filter === f}
              onClick={() => {
                setFilter(f);
                setPage(0);
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>
      <Panel title="Live connections" action={<span className="muted">{rows.length} shown</span>}>
        {rows.length ? (
          <div className="table-scroll">
            <table className="connection-table">
              <thead>
                <tr>
                  <th>Application</th>
                  <th>Remote endpoint / domain</th>
                  <th>Location</th>
                  <th>Protocol / state</th>
                  <th>Observed since</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(safe * SIZE, (safe + 1) * SIZE).map((c) => {
                  const app = apps.get(c.app_id);
                  return (
                    <tr key={c.id} className={c.threat ? "threat-row" : ""}>
                      <td>
                        {app ? (
                          <button className="link-button" onClick={() => onSelect(app)}>
                            {app.name}
                          </button>
                        ) : (
                          "—"
                        )}
                        <small>{c.pid ? "PID " + c.pid : c.source}</small>
                      </td>
                      <td>
                        <strong className="mono">
                          {c.remote_ip ? c.remote_ip + ":" + c.remote_port : "Listening on " + c.local_ip + ":" + c.local_port}
                        </strong>
                        <small>
                          {c.threat ? (
                            <span className="danger-text">
                              <CircleAlert size={12} /> {c.threat.name || "Threat feed"}: {c.threat.category || c.threat.malware}
                            </span>
                          ) : (
                            c.domain || (c.remote_ip ? "Domain not observed" : "")
                          )}
                        </small>
                      </td>
                      <td>
                        {c.geo ? c.geo.country : c.remote_ip && PRIVATE.test(c.remote_ip) ? "Local network" : "Unlocated"}
                        <small>{c.geo?.city || ""}</small>
                      </td>
                      <td>
                        {c.protocol}
                        <small>{c.status}</small>
                      </td>
                      <td>{when(c.first_seen)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No matching connections">Try another filter or search.</Empty>
        )}
        <div className="pagination">
          <span>
            {rows.length ? safe * SIZE + 1 : 0}–{Math.min((safe + 1) * SIZE, rows.length)} of {rows.length}
          </span>
          <div>
            <button disabled={!safe} onClick={() => setPage(safe - 1)}>
              Previous
            </button>
            <button disabled={(safe + 1) * SIZE >= rows.length} onClick={() => setPage(safe + 1)}>
              Next
            </button>
          </div>
        </div>
      </Panel>
    </>
  );
}
