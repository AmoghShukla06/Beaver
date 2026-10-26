export type RiskLevel = "Low" | "Medium" | "High" | "Unknown" | "Info";
export interface Evidence {
  rule: string;
  points: number;
  title: string;
  detail: string;
  source?: string;
  endpoint?: string;
  category?: "intel" | "identity" | "behavior" | "remote" | "exfil" | "trust";
  technique?: string | null;
  ports?: number[];
}
export interface Risk {
  level: RiskLevel;
  score: number | null;
  reason: string;
  evidence: Evidence[];
  allowlisted: boolean;
  remote_tool?: string | null;
}
export interface BinaryInfo {
  path: string;
  state: "pending" | "inspected" | "unavailable";
  location: "system" | "user" | "staging" | "memory";
  sha256?: string | null;
  size?: number;
  signature?: "valid" | "unsigned" | "tampered" | "untrusted" | "unknown" | null;
  signature_status?: string;
  publisher?: string | null;
  os_binary?: boolean;
  first_seen?: number;
}
export interface ObservedApp {
  id: string;
  name: string;
  path: string | null;
  pids: number[];
  connections: number;
  listening?: number;
  parent?: string | null;
  binary?: BinaryInfo | null;
  risk: Risk;
  upload_bps: number | null;
  download_bps: number | null;
  uploaded: number | null;
  downloaded: number | null;
}
export interface Geo {
  country: string;
  code: string;
  lat: number;
  lon: number;
  city: string | null;
  accuracy_km: number | null;
}
export interface Connection {
  id: string;
  app_id: string;
  pid: number | null;
  local_ip: string;
  local_port: number;
  remote_ip: string | null;
  remote_port: number | null;
  protocol: string;
  status: string;
  source: string;
  first_seen: number;
  last_seen: number;
  ended?: number | null;
  domain: string | null;
  geo: Geo | null;
  threat: {
    malware: string;
    source: string;
    name?: string;
    category?: string;
    points?: number;
  } | null;
}
export interface Alert {
  id: string;
  app_id: string;
  app_name: string;
  created: number;
  acknowledged: boolean;
  title: string;
  level: RiskLevel;
  risk: Risk;
  path?: string | null;
  endpoint?: {
    ip: string;
    port: number;
    domain: string | null;
    country: string | null;
  } | null;
  response?: { action: string; at: number; error?: string } | null;
  kind?: "new-app";
  publisher?: string | null;
  signature?: string | null;
}
export interface Rule {
  id: string;
  kind: "application" | "endpoint" | "ports";
  target: string;
  created: number;
  verified_at: number | null;
  state: string;
}
export interface Settings {
  notifications: boolean;
  feed_updates: boolean;
  capture: boolean;
  retention_days: number;
  geoip_path: string;
  close_to_tray: boolean;
  notify_medium: boolean;
  remote_alerts: boolean;
  active_protection: boolean;
  start_at_login: boolean;
  snoozed_until: number;
  disabled_feeds: string[];
  notify_new_apps: boolean;
  onboarded: boolean;
  auto_update: boolean;
}
export interface Feed {
  id: string;
  name: string;
  kind: "ip" | "cidr" | "domain";
  category: string;
  home: string;
  points: number;
  entries: number;
  updated: number | null;
  fresh: boolean;
  enabled: boolean;
  error: string | null;
}
export interface TrafficPoint {
  time: number;
  upload: number | null;
  download: number | null;
}
export interface Snapshot {
  ready: boolean;
  sampled_at: number | null;
  started: number;
  apps: ObservedApp[];
  connections: Connection[];
  traffic: TrafficPoint[];
  upload_bps: number | null;
  download_bps: number | null;
  alerts: Alert[];
  rules: Rule[];
  settings: Settings;
  allowlist: { id: string; kind: string; target: string }[];
  data_path: string;
  firewall: {
    platform: string;
    endpoint: boolean;
    application: boolean;
    ports: boolean;
    lockdown: string;
    elevation: string;
    note: string;
  };
  coverage: {
    platform: string;
    elevated: boolean;
    inventory_error: string | null;
    inventory: string;
    domains: string;
    capture: {
      active: boolean;
      enabled: boolean;
      error: string | null;
      packets: number;
      attributed: number;
      method: string;
      available?: boolean;
      interfaces?: number;
      server_names?: number;
    };
    intel: {
      source: string;
      url: string;
      updated: number | null;
      entries: number;
      fresh: boolean;
      error: string | null;
      refreshing: boolean;
      feeds: Feed[];
    };
    dns_cache: { available: boolean; names: number; error: string | null };
    binaries: { error: string | null; signatures: boolean };
    geo: { available: boolean; error: string | null; provider: string | null };
  };
}
export type Method =
  | "snapshot"
  | "history"
  | "settings"
  | "download_geoip"
  | "refresh_feed"
  | "acknowledge"
  | "block"
  | "unblock"
  | "allowlist"
  | "terminate"
  | "verify_rules"
  | "icon"
  | "app_info"
  | "check_updates"
  | "restart_update"
  | "dismiss_whats_new"
  | "open_logs"
  | "copy_text"
  | "copy_diagnostics"
  | "reset_data"
  | "pick_geoip"
  | "export_history"
  | "test_notification";
export interface UpdateState {
  state: "disabled" | "off" | "idle" | "checking" | "latest" | "downloading" | "ready" | "error";
  version?: string;
  percent?: number;
  checked_at?: number;
  error?: string | null;
}
export interface AppInfo {
  version: string;
  electron: string;
  packaged: boolean;
  update: UpdateState;
  whats_new: { from: string; to: string } | null;
}
export interface Navigation {
  page: string;
  app_id?: string;
  alert_id?: string;
}
export type NativeAPI = Record<Method, (params?: object) => Promise<any>> & {
  on_navigate: (callback: (target: Navigation) => void) => () => void;
  on_alert: (callback: (alert: Alert) => void) => () => void;
  on_update: (callback: (state: UpdateState) => void) => () => void;
};
declare global {
  interface Window {
    beaver?: NativeAPI;
  }
}
