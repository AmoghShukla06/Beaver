// Tauri desktop bridge: provides the same `window.beaver` API the UI has always used.
// Service calls go through one allowlisted `rpc` command; everything else is a named shell command.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { NativeAPI } from "./types";

const RPC = ["snapshot", "history", "settings", "refresh_feed", "download_geoip", "acknowledge", "block", "unblock", "allowlist", "terminate", "verify_rules"];

function subscribe(channel: string) {
  return (callback: (data: any) => void) => {
    let stop: (() => void) | undefined;
    let cancelled = false;
    listen(channel, (event) => callback(event.payload)).then((unlisten) => (cancelled ? unlisten() : (stop = unlisten)));
    return () => {
      cancelled = true;
      stop?.();
    };
  };
}

export function installBridge() {
  if (!("__TAURI_INTERNALS__" in window)) return;
  const api: Record<string, unknown> = {};
  for (const method of RPC) api[method] = (params: object = {}) => invoke("rpc", { method, params });
  for (const method of ["pick_geoip", "test_notification", "app_info", "check_updates", "restart_update", "dismiss_whats_new", "open_logs", "copy_diagnostics", "reset_data"])
    api[method] = () => invoke(method);
  api.export_history = (p: { app_id: string }) => invoke("export_history", { appId: p.app_id });
  api.icon = (p: { path: string }) => invoke("icon", { path: p.path });
  api.copy_text = (p: { text: string }) => invoke("copy_text", { text: p.text });
  api.on_navigate = subscribe("beaver:navigate");
  api.on_alert = subscribe("beaver:alert");
  api.on_update = subscribe("beaver:update");
  window.beaver = Object.freeze(api) as unknown as NativeAPI;
  // External links open in the system browser only if the shell's allowlist accepts them.
  document.addEventListener("click", (event) => {
    const link = (event.target as HTMLElement | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
    if (!link || !/^https:/.test(link.href)) return;
    event.preventDefault();
    void invoke("open_url", { url: link.href }).catch(() => {});
  });
}

installBridge();
