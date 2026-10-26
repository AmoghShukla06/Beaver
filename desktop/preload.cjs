const { contextBridge, ipcRenderer } = require("electron");
const methods = [
  "snapshot",
  "history",
  "settings",
  "download_geoip",
  "refresh_feed",
  "acknowledge",
  "block",
  "unblock",
  "allowlist",
  "terminate",
  "verify_rules",
  "icon",
  "app_info",
  "check_updates",
  "restart_update",
  "dismiss_whats_new",
  "open_logs",
  "copy_text",
  "copy_diagnostics",
  "pick_geoip",
  "export_history",
  "test_notification",
];
const api = Object.fromEntries(
  methods.map((method) => [
    method,
    (params = {}) => ipcRenderer.invoke("beaver:" + method, params),
  ]),
);
// Main-process pushes: notification clicks (navigate) and new alerts. Returns an unsubscribe function.
for (const channel of ["navigate", "alert", "update"])
  api["on_" + channel] = (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on("beaver:" + channel, listener);
    return () => ipcRenderer.removeListener("beaver:" + channel, listener);
  };
contextBridge.exposeInMainWorld("beaver", Object.freeze(api));
