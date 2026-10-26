import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ArrowDown,
  ArrowUp,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  CircleHelp,
  Search as SearchIcon,
  Shield,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  X,
} from "lucide-react";
import { bytes } from "./api";
import type { Evidence, ObservedApp, RiskLevel, TrafficPoint } from "./types";
export function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <Shield size={32} strokeWidth={2.4} />
        <span className="brand-teeth">▰</span>
      </span>
      <span>
        Beaver<span className="brand-dot">.</span>
      </span>
    </div>
  );
}
export function Panel({
  title,
  action,
  children,
  className = "",
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={"panel " + className}>
      <div className="panel-heading">
        <h2>{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <CircleHelp size={28} />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={"risk risk-" + level.toLowerCase()}>
      <span className="risk-dot" />
      {level} risk
    </span>
  );
}
export function techniqueUrl(id: string) {
  const [base, sub] = id.split(".");
  return "https://attack.mitre.org/techniques/" + base + "/" + (sub ? sub + "/" : "");
}
export function EvidenceItem({ evidence }: { evidence: Evidence }) {
  return (
    <div className={"evidence evidence-" + (evidence.category || "behavior")}>
      <div>
        <strong>{evidence.title}</strong>
        <span>
          {evidence.points > 0 ? "+" : ""}
          {evidence.points}
        </span>
      </div>
      <p>{evidence.detail}</p>
      <small className="source">
        {evidence.technique && (
          <a href={techniqueUrl(evidence.technique)} target="_blank" rel="noreferrer">
            MITRE ATT&CK {evidence.technique}
          </a>
        )}
        {evidence.technique && evidence.source && " · "}
        {evidence.source && (
          <a href={evidence.source} target="_blank" rel="noreferrer">
            {new URL(evidence.source).hostname}
          </a>
        )}
      </small>
    </div>
  );
}
export function SignatureBadge({ app }: { app: ObservedApp }) {
  const sig = app.binary?.signature;
  if (!app.binary || sig === null || sig === undefined)
    return app.binary?.state === "pending" ? (
      <span className="sig sig-pending">Checking…</span>
    ) : null;
  const Icon = sig === "valid" ? ShieldCheck : sig === "unsigned" || sig === "unknown" ? ShieldQuestion : ShieldX;
  const label =
    sig === "valid"
      ? app.binary.publisher || "Signed"
      : sig === "unsigned"
        ? "Unsigned"
        : sig === "tampered"
          ? "Signature broken"
          : sig === "untrusted"
            ? "Untrusted signer"
            : "Signature unknown";
  return (
    <span className={"sig sig-" + sig} title={app.binary.signature_status || label}>
      <Icon size={13} />
      {label}
    </span>
  );
}
type SortKey = "risk" | "name" | "connections" | "traffic";
export function Search({
  value,
  onChange,
  placeholder = "Search applications, paths, or process IDs",
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <div className="search">
      <SearchIcon size={17} />
      <input
        ref={ref}
        aria-label={placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      {value && (
        <button
          className="icon-button"
          aria-label="Clear search"
          onClick={() => {
            onChange("");
            ref.current?.focus();
          }}
        >
          <X size={16} />
        </button>
      )}
    </div>
  );
}
export function AppTable({
  apps,
  onSelect,
  compact = false,
  page = 0,
  onPage,
}: {
  apps: ObservedApp[];
  onSelect: (app: ObservedApp) => void;
  compact?: boolean;
  page?: number;
  onPage?: (page: number) => void;
}) {
  const size = compact ? 5 : 20;
  const [sort, setSort] = useState<{ key: SortKey; down: boolean }>({
    key: "risk",
    down: true,
  });
  const sorted = useMemo(() => {
    const value = (a: ObservedApp): number | string =>
      sort.key === "name"
        ? a.name.toLowerCase()
        : sort.key === "connections"
          ? a.connections
          : sort.key === "traffic"
            ? (a.download_bps || 0) + (a.upload_bps || 0)
            : (a.risk.score ?? -1) * 1000 + a.connections;
    return [...apps].sort((a, b) => {
      const x = value(a), y = value(b);
      return (x < y ? -1 : x > y ? 1 : 0) * (sort.down ? -1 : 1);
    });
  }, [apps, sort]);
  const safePage = Math.min(
    page,
    Math.max(0, Math.ceil(apps.length / size) - 1),
  );
  const slice = (compact ? apps : sorted).slice(safePage * size, (safePage + 1) * size);
  const header = (key: SortKey, label: string) =>
    compact ? (
      label
    ) : (
      <button
        className="sort-button"
        aria-label={"Sort by " + label}
        onClick={() =>
          setSort((s) => ({ key, down: s.key === key ? !s.down : key !== "name" }))
        }
      >
        {label}
        {sort.key === key ? (
          sort.down ? <ArrowDown size={13} /> : <ArrowUp size={13} />
        ) : (
          <ChevronsUpDown size={13} />
        )}
      </button>
    );
  return (
    <>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th aria-sort={sort.key === "name" && !compact ? (sort.down ? "descending" : "ascending") : undefined}>{header("name", "Application")}</th>
              <th>{header("connections", "Connections")}</th>
              <th>{header("risk", "Risk assessment")}</th>
              <th>{header("traffic", "↓ Download / ↑ Upload")}</th>
              <th>
                <span className="sr-only">Investigate</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {slice.map((app) => (
              <tr key={app.id}>
                <td>
                  <button className="app-name" onClick={() => onSelect(app)}>
                    <span className="app-avatar">
                      {app.name.slice(0, 1).toUpperCase()}
                    </span>
                    <span>
                      <strong>{app.name}</strong>
                      <small>
                        {app.pids.length
                          ? "PID " +
                            app.pids.slice(0, 3).join(", ") +
                            (app.pids.length > 3 ? "…" : "")
                          : "Owner unavailable"}
                        {!compact && <SignatureBadge app={app} />}
                      </small>
                    </span>
                  </button>
                </td>
                <td className="numeric">{app.connections}</td>
                <td>
                  <RiskBadge level={app.risk.level} />
                  {app.risk.score != null && app.risk.score > 0 && (
                    <span className="score-chip">{app.risk.score}</span>
                  )}
                </td>
                <td className="traffic-cell">
                  <span>{bytes(app.download_bps, true)}</span>
                  <span>{bytes(app.upload_bps, true)}</span>
                </td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={"Investigate " + app.name}
                    onClick={() => onSelect(app)}
                  >
                    <ChevronRight size={16} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!slice.length && (
        <Empty title="No matching applications">
          Try a different search, or wait for the next network sample.
        </Empty>
      )}
      {!compact && (
        <div className="pagination">
          <span>
            {apps.length ? safePage * size + 1 : 0}–
            {Math.min((safePage + 1) * size, apps.length)} of {apps.length}{" "}
            applications
          </span>
          <div>
            <button
              className="icon-button"
              aria-label="Previous page"
              disabled={!safePage}
              onClick={() => onPage?.(safePage - 1)}
            >
              <ChevronLeft size={18} />
            </button>
            <button
              className="icon-button"
              aria-label="Next page"
              disabled={(safePage + 1) * size >= apps.length}
              onClick={() => onPage?.(safePage + 1)}
            >
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      )}
    </>
  );
}
export function TrafficChart({ points }: { points: TrafficPoint[] }) {
  const [range, setRange] = useState(60);
  const end = points.at(-1)?.time || Date.now() / 1000;
  const values = points.filter((point) => point.time >= end - range);
  const maximum = Math.max(
    1024,
    ...values.flatMap((p) => [p.upload || 0, p.download || 0]),
  );
  const x = (t: number) => 50 + ((t - (end - range)) / range) * 680;
  const y = (v: number) => 205 - (v / maximum) * 180;
  const line = (key: "upload" | "download") => {
    let gap = true;
    return values
      .map((p) => {
        if (p[key] == null) {
          gap = true;
          return "";
        }
        const result =
          (gap ? "M" : "L") +
          x(p.time).toFixed(1) +
          "," +
          y(p[key]!).toFixed(1);
        gap = false;
        return result;
      })
      .join(" ");
  };
  return (
    <Panel
      title="Live network traffic"
      className="traffic-panel"
      action={
        <div className="segmented" aria-label="Traffic time range">
          {[
            [60, "1 min"],
            [300, "5 min"],
            [3600, "1 hour"],
          ].map(([value, label]) => (
            <button
              key={value}
              aria-pressed={range === value}
              onClick={() => setRange(Number(value))}
            >
              {label}
            </button>
          ))}
        </div>
      }
    >
      <div className="chart-legend">
        <span>
          <i className="download-dot" />
          Download
        </span>
        <span>
          <i className="upload-dot" />
          Upload
        </span>
        <span className="muted">All non-loopback interfaces</span>
      </div>
      <svg
        className="traffic-chart"
        viewBox="0 0 750 245"
        role="img"
        aria-label={
          "Actual interface traffic over the last " +
          range +
          " seconds; maximum " +
          bytes(maximum, true)
        }
      >
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <g key={f}>
            <line
              x1="50"
              y1={y(maximum * f)}
              x2="730"
              y2={y(maximum * f)}
              className="chart-grid"
            />
            <text x="42" y={y(maximum * f) + 4} textAnchor="end">
              {bytes(maximum * f)}
            </text>
          </g>
        ))}
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <g key={f}>
            <line
              x1={50 + f * 680}
              x2={50 + f * 680}
              y1="25"
              y2="205"
              className="chart-grid vertical"
            />
            <text x={50 + f * 680} y="230" textAnchor="middle">
              {new Date((end - range + range * f) * 1000).toLocaleTimeString(
                [],
                {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: range === 60 ? "2-digit" : undefined,
                },
              )}
            </text>
          </g>
        ))}
        <path d={line("download")} className="chart-line download" />
        <path d={line("upload")} className="chart-line upload" />
        {values.length < 2 && (
          <text x="390" y="120" textAnchor="middle">
            Collecting real traffic samples…
          </text>
        )}
      </svg>
      <div className="chart-bottom">
        <span>
          <ArrowDown size={14} />
          {bytes(values.at(-1)?.download, true)}
        </span>
        <span>
          <ArrowUp size={14} />
          {bytes(values.at(-1)?.upload, true)}
        </span>
        <small>
          VPN and virtual interfaces can count traffic more than once.
        </small>
      </div>
    </Panel>
  );
}
export interface Confirmation {
  title: string;
  description: string;
  label: string;
  run: () => Promise<unknown>;
}
export function Confirm({
  action,
  onClose,
  onConfirm,
  busy,
}: {
  action: Confirmation | null;
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (action && !ref.current?.open) ref.current?.showModal();
    if (!action && ref.current?.open) ref.current.close();
  }, [action]);
  return (
    <dialog
      ref={ref}
      aria-labelledby="confirm-title"
      aria-describedby="confirm-description"
      onCancel={(event) => {
        if (busy) event.preventDefault();
        else onClose();
      }}
    >
      <div className="dialog-content">
        <Shield size={30} />
        <h2 id="confirm-title">{action?.title}</h2>
        <p id="confirm-description">{action?.description}</p>
        <div className="dialog-actions">
          <button autoFocus onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="danger-button" disabled={busy} onClick={onConfirm}>
            {busy ? "Applying…" : action?.label}
          </button>
        </div>
      </div>
    </dialog>
  );
}
export function Toggle({
  label,
  description,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  disabled?: boolean;
  onChange: () => void;
}) {
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        <p>{description}</p>
      </div>
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        className={"toggle " + (checked ? "on" : "")}
        onClick={onChange}
      >
        <span>{checked && <Check size={12} />}</span>
      </button>
    </div>
  );
}
