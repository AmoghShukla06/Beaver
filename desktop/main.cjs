const {
  app,
  BrowserWindow,
  ipcMain,
  Tray,
  Menu,
  Notification,
  nativeImage,
  dialog,
  session,
  shell,
  clipboard,
} = require("electron");
const path = require("node:path");
const os = require("node:os");
const fsSync = require("node:fs");
const fs = require("node:fs/promises");
const { pathToFileURL } = require("node:url");
const { Backend } = require("./backend.cjs");

const asset = (name) => path.join(__dirname, "../assets", name);
const startHidden = process.argv.includes("--hidden");
let win = null,
  tray = null,
  backend = null,
  quitting = false,
  settings = {},
  status = {},
  navigation = null,
  restarts = [],
  lastToast = 0,
  toastTimer = null,
  updateReady = null,
  updater = null,
  expected = "";
const queued = [];
let update = { state: "disabled" }; // shown in Settings → About
let whatsNew = null; // { from, to } after an update, until dismissed
let logFile = null;
const iconCache = new Map(); // executable path -> Promise<NativeImage | null>
let knownPaths = new Set(); // only paths the service reported may be read for icons
const live = new Set(); // Notifications are garbage-collected (and lose click handlers) unless referenced.
const icons = {};
const methods = [
  "snapshot",
  "history",
  "settings",
  "refresh_feed",
  "download_geoip",
  "acknowledge",
  "block",
  "unblock",
  "allowlist",
  "terminate",
  "verify_rules",
];

// The UI is static SVG and tables; software compositing saves ~100 MB in a process that otherwise lives all day.
app.disableHardwareAcceleration();
app.setAppUserModelId("org.beaver.security");
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on("second-instance", () => showWindow());
  app
    .whenReady()
    .then(start)
    .catch((error) => {
      dialog.showErrorBox("Beaver could not start", error.message);
      app.quit();
    });
  app.on("before-quit", () => {
    quitting = true;
    clearTimeout(toastTimer);
    backend?.close();
  });
  app.on("window-all-closed", () => {
    if (!tray || quitting) app.quit();
  });
}

// Local app log: about 2 MB max (one rotation). Errors and lifecycle only, never connection data.
function log(message) {
  if (!logFile) return;
  try {
    if (fsSync.existsSync(logFile) && fsSync.statSync(logFile).size > 1_000_000)
      fsSync.renameSync(logFile, logFile + ".1");
    fsSync.appendFileSync(logFile, new Date().toISOString() + " " + message + "\n");
  } catch {
    /* logging must never break monitoring */
  }
}

function dataDir() {
  return process.env.BEAVER_TEST_DATA && !app.isPackaged
    ? process.env.BEAVER_TEST_DATA
    : path.join(app.getPath("userData"), "data");
}

function logsDir() {
  return path.join(dataDir(), "logs");
}

function trackVersion() {
  const marker = path.join(app.getPath("userData"), "last-version");
  let previous = "";
  try {
    previous = fsSync.readFileSync(marker, "utf8").trim();
  } catch {}
  if (previous && previous !== app.getVersion())
    whatsNew = { from: previous, to: app.getVersion() };
  try {
    fsSync.writeFileSync(marker, app.getVersion());
  } catch {}
}

async function start() {
  fsSync.mkdirSync(logsDir(), { recursive: true });
  logFile = path.join(logsDir(), "app.log");
  log(`Beaver ${app.getVersion()} starting (${process.platform} ${os.release()}, Electron ${process.versions.electron})`);
  if (app.isPackaged) trackVersion();
  const preview =
    !app.isPackaged && process.env.BEAVER_DEV_URL === "http://127.0.0.1:5173";
  expected = preview
    ? "http://127.0.0.1:5173/"
    : pathToFileURL(path.join(__dirname, "../dist/index.html")).href;
  session.defaultSession.setPermissionRequestHandler((_wc, _p, callback) =>
    callback(false),
  );
  session.defaultSession.setPermissionCheckHandler(() => false);
  for (const name of ["beaver.png", "tray.png", "tray-alert.png"])
    icons[name] = nativeImage.createFromPath(asset(name));
  startBackend();
  registerIpc();
  try {
    tray = new Tray(trayIcon(false));
    tray.on("click", () => showWindow());
    tray.on("double-click", () => showWindow());
    refreshTray();
  } catch {
    tray = null;
  }
  try {
    settings = await backend.call("settings", { patch: {} });
    await applyInstallerOptions();
    applyLoginItem(settings.start_at_login);
  } catch {
    /* The window shows service errors. */
  }
  // Launched at login: stay in the tray without a renderer (saves ~100 MB) unless no tray exists.
  if (!startHidden || !tray) showWindow();
  startUpdater();
}

function startUpdater() {
  if (!app.isPackaged || process.env.BEAVER_TEST_DATA) return;
  try {
    ({ autoUpdater: updater } = require("electron-updater"));
  } catch {
    return;
  }
  updater.logger = null;
  updater.autoDownload = true;
  updater.autoInstallOnAppQuit = true;
  update = { state: "idle" };
  const set = (value) => {
    update = { ...update, ...value };
    win?.webContents.send("beaver:update", update);
  };
  updater.on("checking-for-update", () => set({ state: "checking", error: null }));
  updater.on("update-not-available", () => set({ state: "latest", checked_at: Date.now() / 1000 }));
  updater.on("update-available", (info) => set({ state: "downloading", version: info.version, percent: 0 }));
  updater.on("download-progress", (p) => set({ state: "downloading", percent: Math.round(p.percent) }));
  updater.on("error", (error) => {
    // Offline or no release metadata: try again at the next check.
    log("update check failed: " + String(error?.message || error).slice(0, 300));
    set({ state: "error", error: "Could not reach GitHub Releases", checked_at: Date.now() / 1000 });
  });
  updater.on("update-downloaded", (info) => {
    updateReady = info.version;
    set({ state: "ready", version: info.version });
    log("update downloaded: " + info.version);
    refreshTray();
    toast({
      title: `Beaver ${info.version} is ready`,
      body: "Restart Beaver to finish updating. Monitoring resumes automatically.",
      actions: [{ label: "Restart now", run: installUpdate }],
    });
  });
  // Checks GitHub Releases at startup and every 6 hours; Settings can turn this off.
  const check = () => {
    if (settings.auto_update !== false && !updateReady)
      updater.checkForUpdates().catch(() => {});
  };
  setTimeout(check, 30000);
  setInterval(check, 6 * 3600 * 1000);
}

function installUpdate() {
  quitting = true;
  updater?.quitAndInstall(false, true);
}

// The Windows installer's "Start Beaver when I sign in" choice, applied once and then removed.
async function applyInstallerOptions() {
  if (!app.isPackaged) return;
  const file = path.join(process.resourcesPath, "installer-options.json");
  let options;
  try {
    options = JSON.parse(fsSync.readFileSync(file, "utf8"));
  } catch {
    return;
  }
  try {
    if (typeof options.start_at_login === "boolean")
      settings = await backend.call("settings", { patch: { start_at_login: options.start_at_login } });
    fsSync.rmSync(file, { force: true });
    log("applied installer options: " + JSON.stringify(options));
  } catch (error) {
    log("installer options not applied: " + error.message);
  }
}

function startBackend() {
  backend = new Backend({
    directory: dataDir(),
    packaged: app.isPackaged,
    resources: process.resourcesPath,
    onEvent,
    log,
    onExit: () => {
      if (quitting) return;
      // Monitoring must survive a crashed service, but never spin: at most 5 restarts in 10 minutes.
      const now = Date.now();
      restarts = restarts.filter((t) => now - t < 600000);
      if (restarts.length >= 5) return log("service restart limit reached");
      restarts.push(now);
      setTimeout(() => {
        if (!quitting) startBackend();
      }, 3000);
    },
  });
  if (win) backend.call("visibility", { visible: win.isVisible() }).catch(() => {});
}

function createWindow() {
  win = new BrowserWindow({
    width: 1440,
    height: 960,
    minWidth: 760,
    minHeight: 600,
    title: "Beaver",
    show: false,
    backgroundColor: "#0b1018",
    autoHideMenuBar: true,
    icon: asset("beaver.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
    },
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (
      url === "https://db-ip.com/" ||
      /^https:\/\/www\.virustotal\.com\/gui\/file\/[0-9a-f]{64}$/.test(url) ||
      /^https:\/\/(feodotracker\.abuse\.ch|www\.spamhaus\.org|github\.com|rules\.emergingthreats\.net|attack\.mitre\.org|npcap\.com)\/[\w./#-]*$/.test(url)
    )
      void shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event) => event.preventDefault());
  win.webContents.on("will-attach-webview", (event) => event.preventDefault());
  win.webContents.on("did-finish-load", () => {
    if (navigation) win.webContents.send("beaver:navigate", navigation);
    navigation = null;
  });
  win.once("ready-to-show", () => win.show());
  const visible = (value) => () =>
    backend?.call("visibility", { visible: value }).catch(() => {});
  win.on("show", visible(true));
  win.on("restore", visible(true));
  win.on("minimize", visible(false));
  win.on("close", (event) => {
    if (!quitting && tray && settings.close_to_tray !== false) {
      // Destroy rather than hide: the renderer is the largest memory consumer and is not needed in the tray.
      event.preventDefault();
      win.destroy();
    }
  });
  win.on("closed", () => {
    win = null;
    visible(false)();
  });
  refreshOverlay();
  void win.loadURL(expected);
}

function showWindow(target) {
  if (target) navigation = target;
  if (!win) return createWindow();
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
  if (navigation && !win.webContents.isLoading()) {
    win.webContents.send("beaver:navigate", navigation);
    navigation = null;
  }
}

function trusted(event) {
  const url = event.senderFrame?.url;
  if (
    !win ||
    event.sender !== win.webContents ||
    event.senderFrame !== win.webContents.mainFrame ||
    url?.split("#")[0] !== expected
  )
    throw new Error("Untrusted desktop request");
}

function registerIpc() {
  for (const method of methods) {
    ipcMain.handle("beaver:" + method, async (event, params) => {
      trusted(event);
      if (
        !params ||
        typeof params !== "object" ||
        Array.isArray(params) ||
        JSON.stringify(params).length > 32768
      )
        throw new Error("Invalid request");
      if (method === "settings" && "start_at_login" in (params.patch || {}))
        applyLoginItem(params.patch.start_at_login, true);
      const result = await backend.call(method, params);
      if (method === "settings") {
        settings = result;
        refreshTray();
      }
      if (method === "snapshot") {
        settings = result.settings;
        knownPaths = new Set(
          [...result.apps, ...result.alerts].map((a) => a.path).filter(Boolean),
        );
      }
      return result;
    });
  }
  ipcMain.handle("beaver:icon", async (event, params) => {
    trusted(event);
    if (typeof params?.path !== "string" || !knownPaths.has(params.path)) return null;
    const image = await appIcon(params.path);
    return image ? image.toDataURL() : null;
  });
  ipcMain.handle("beaver:pick_geoip", async (event) => {
    trusted(event);
    const selected = await dialog.showOpenDialog(win, {
      title: "Choose a local GeoIP City database",
      properties: ["openFile"],
      filters: [{ name: "MaxMind database", extensions: ["mmdb"] }],
    });
    if (selected.canceled) return { cancelled: true };
    return backend.call("settings", {
      patch: { geoip_path: selected.filePaths[0] },
    });
  });
  ipcMain.handle("beaver:export_history", async (event, params) => {
    trusted(event);
    if (typeof params?.app_id !== "string" || params.app_id.length > 100)
      throw new Error("Invalid application");
    const selected = await dialog.showSaveDialog(win, {
      title: "Export connection history",
      defaultPath: "beaver-connections.json",
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (selected.canceled) return { cancelled: true };
    let items = [],
      offset = 0;
    while (true) {
      const page = await backend.call("history", {
        app_id: params.app_id,
        offset,
        limit: 100,
      });
      items.push(...page.items);
      offset += page.items.length;
      if (!page.items.length || offset >= page.total || offset >= 100000)
        break;
    }
    await fs.writeFile(
      selected.filePath,
      JSON.stringify(
        {
          exported_at: new Date().toISOString(),
          app_id: params.app_id,
          connections: items,
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );
    return { exported: items.length };
  });
  ipcMain.handle("beaver:app_info", (event) => {
    trusted(event);
    return {
      version: app.getVersion(),
      electron: process.versions.electron,
      packaged: app.isPackaged,
      update: settings.auto_update === false && update.state !== "ready" ? { ...update, state: "off" } : update,
      whats_new: whatsNew,
    };
  });
  ipcMain.handle("beaver:check_updates", async (event) => {
    trusted(event);
    if (!updater) throw new Error("Updates are available in installed builds.");
    await updater.checkForUpdates();
    return update;
  });
  ipcMain.handle("beaver:restart_update", (event) => {
    trusted(event);
    if (!updateReady) throw new Error("No update is ready yet.");
    installUpdate();
    return { ok: true };
  });
  ipcMain.handle("beaver:dismiss_whats_new", (event) => {
    trusted(event);
    whatsNew = null;
    return { ok: true };
  });
  ipcMain.handle("beaver:reset_data", async (event) => {
    trusted(event);
    // Stop the service (it holds the database), delete everything Beaver stored, then start fresh.
    quitting = true;
    applyLoginItem(false);
    const exited = backend.exited;
    backend.close();
    await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5000))]);
    logFile = null;
    await fs.rm(dataDir(), { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    fsSync.rmSync(path.join(app.getPath("userData"), "last-version"), { force: true });
    app.relaunch();
    app.exit(0);
    return { ok: true };
  });
  ipcMain.handle("beaver:open_logs", async (event) => {
    trusted(event);
    const error = await shell.openPath(logsDir());
    if (error) throw new Error(error);
    return { ok: true };
  });
  ipcMain.handle("beaver:copy_text", (event, params) => {
    trusted(event);
    if (typeof params?.text !== "string" || params.text.length > 20000) throw new Error("Invalid text");
    clipboard.writeText(params.text);
    return { copied: true };
  });
  ipcMain.handle("beaver:copy_diagnostics", async (event) => {
    trusted(event);
    clipboard.writeText(await diagnostics());
    return { copied: true };
  });
  ipcMain.handle("beaver:test_notification", (event) => {
    trusted(event);
    toast({
      title: "Beaver notification test",
      body: "Native notifications are connected. High-risk and remote-access detections will appear here, even when the window is closed.",
    });
    return { ok: true };
  });
}

// ---- Notifications -------------------------------------------------------------------------------------

// Support report for GitHub issues. Usernames, IP addresses and paths are redacted.
async function diagnostics() {
  const redact = (text) =>
    String(text)
      .replace(/([A-Za-z]:(?:\\\\|\\)Users(?:\\\\|\\))[^\\\s"]+/gi, "$1<user>")
      .replace(/(\/home\/)[^/\s"]+/g, "$1<user>")
      .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, "<ip>")
      .replace(/\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b|(?:\b[0-9a-f]{1,4})?(?::[0-9a-f]{1,4})*::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?/gi, "<ip>");
  const tail = (file) => {
    try {
      return fsSync.readFileSync(file, "utf8").trim().split("\n").slice(-40).join("\n");
    } catch {
      return "(none)";
    }
  };
  let snapshot = null;
  try {
    snapshot = await backend.call("snapshot");
  } catch (error) {
    snapshot = { error: error.message };
  }
  const c = snapshot.coverage || {};
  const report = {
    beaver: app.getVersion(),
    electron: process.versions.electron,
    os: `${process.platform} ${os.release()} ${process.arch}`,
    packaged: app.isPackaged,
    update,
    settings: snapshot.settings && Object.fromEntries(Object.entries(snapshot.settings).filter(([k]) => k !== "geoip_path")),
    coverage: c.platform && {
      elevated: c.elevated,
      inventory_error: c.inventory_error,
      capture: { available: c.capture.available, active: c.capture.active, error: c.capture.error, interfaces: c.capture.interfaces },
      feeds: c.intel.feeds.map((f) => `${f.id}: ${f.enabled ? (f.fresh ? "current" : "stale") : "off"}${f.error ? " (" + f.error + ")" : ""}`),
      dns_cache: c.dns_cache,
      geo: c.geo?.available,
      power: c.power,
    },
    counts: snapshot.apps && {
      apps: snapshot.apps.length,
      connections: snapshot.connections.length,
      alerts: snapshot.alerts.length,
      rules: snapshot.rules.length,
    },
    error: snapshot.error,
  };
  return redact(
    "## Beaver diagnostics\n```json\n" + JSON.stringify(report, null, 2) + "\n```\n" +
      "### app.log\n```\n" + tail(path.join(logsDir(), "app.log")) + "\n```\n" +
      "### service.log\n```\n" + tail(path.join(logsDir(), "service.log")) + "\n```\n",
  );
}

function appIcon(file) {
  if (!iconCache.has(file)) {
    if (iconCache.size > 500) iconCache.clear();
    iconCache.set(
      file,
      app
        .getFileIcon(file, { size: "normal" })
        .then((image) => (image.isEmpty() ? null : image))
        .catch(() => null),
    );
  }
  return iconCache.get(file);
}

function onEvent(event, data) {
  if (event === "status") {
    status = data;
    refreshTray();
    refreshOverlay();
    return;
  }
  if (event !== "alert") return;
  win?.webContents.send("beaver:alert", data);
  const remote = data.risk.evidence.some((e) => e.category === "remote");
  if (
    !settings.notifications ||
    Date.now() / 1000 < (settings.snoozed_until || 0) ||
    !(
      data.level === "High" ||
      (remote && settings.remote_alerts !== false) ||
      (data.level === "Info" && settings.notify_new_apps !== false) ||
      (data.level === "Medium" && settings.notify_medium)
    )
  )
    return;
  queued.push(data);
  // Coalesce bursts: at most one toast every 8 seconds; the rest are summarized.
  const wait = Math.max(0, lastToast + 8000 - Date.now());
  clearTimeout(toastTimer);
  toastTimer = setTimeout(flushAlerts, wait);
}

async function flushAlerts() {
  const batch = queued.splice(0);
  if (!batch.length) return;
  lastToast = Date.now();
  const high = batch.some((a) => a.level === "High");
  if (batch.length > 1)
    return toast({
      title: `Beaver · ${batch.length} new security alerts`,
      body: [...new Set(batch.map((a) => a.app_name))].slice(0, 4).join(", ") +
        ". Click to review the evidence.",
      critical: high,
      target: { page: "alerts" },
    });
  const alert = batch[0];
  const remote = alert.risk.evidence.find((e) => e.category === "remote");
  const where = alert.endpoint
    ? " · " +
      (alert.endpoint.domain || alert.endpoint.ip) +
      (alert.endpoint.country ? " (" + alert.endpoint.country + ")" : "")
    : "";
  const target = { page: "alerts", app_id: alert.app_id, alert_id: alert.id };
  const review = { label: "Review", run: () => showWindow(target) };
  const blockApp = alert.path && process.platform === "win32"
    ? { label: "Block app", run: () => act(alert, "block", { kind: "application", target: alert.path }, `${alert.app_name} is blocked from the network.`) }
    : null;
  let title, body, actions;
  if (alert.response?.action === "terminated") {
    title = `Beaver stopped ${alert.app_name}`;
    body = `${alert.title}. Active protection ended the process. Review the evidence and block it if needed.`;
    actions = [review, blockApp];
  } else if (remote) {
    title = `Remote access alert · ${alert.app_name}`;
    body = `${remote.title}${where}. If you did not start this, end the session now.`;
    actions = [
      { label: "End session", run: () => act(alert, "terminate", { app_id: alert.app_id }, `${alert.app_name} was stopped. Anyone connected through it is disconnected.`) },
      review,
    ];
  } else if (alert.level === "Info") {
    title = `New app online · ${alert.app_name}`;
    body = `${alert.publisher ? "Signed by " + alert.publisher : alert.signature === "unsigned" ? "Unsigned program" : "Publisher unknown"}${where}. First internet connection seen by Beaver.`;
    actions = [
      { label: "Looks fine", run: () => act(alert, "acknowledge", { id: alert.id }, null) },
      blockApp || review,
    ];
  } else {
    title = `${alert.level} risk · ${alert.app_name}`;
    body = `${alert.title}${where}. Click to investigate.`;
    actions = [{ label: "Investigate", run: () => showWindow(target) }, blockApp];
  }
  toast({
    title,
    body,
    critical: alert.level === "High" || Boolean(remote),
    target,
    actions: actions.filter(Boolean),
    icon: alert.path ? await appIcon(alert.path) : null,
  });
}

// A notification button runs one service action directly; the OS still asks for elevation where required.
function act(alert, method, params, done) {
  backend
    .call(method, params)
    .then(() => done && toast({ title: "Beaver", body: done }))
    .catch((error) =>
      toast({
        title: `Beaver could not complete that for ${alert.app_name}`,
        body: error.message,
        target: { page: "alerts", app_id: alert.app_id },
      }),
    );
}

function toast({ title, body, critical = false, target, actions = [], icon = null }) {
  if (!Notification.isSupported())
    throw new Error("Native notifications are unavailable in this desktop session.");
  const notification = new Notification({
    title,
    body: body.slice(0, 250),
    icon: icon || asset("beaver.png"),
    urgency: critical ? "critical" : "normal",
    timeoutType: critical ? "never" : "default",
    actions: actions.map((a) => ({ type: "button", text: a.label })),
  });
  notification.on("action", (event, index) => {
    release();
    actions[event?.actionIndex ?? index]?.run();
  });
  live.add(notification);
  const release = () => live.delete(notification);
  notification.on("click", () => {
    release();
    showWindow(target);
  });
  notification.on("close", release);
  notification.on("failed", release);
  notification.show();
}

// ---- Tray, badge, login item ---------------------------------------------------------------------------

function trayIcon(alert) {
  const image = icons[alert ? "tray-alert.png" : "tray.png"];
  return image.isEmpty() ? icons["beaver.png"].resize({ width: 24, height: 24 }) : image;
}

function refreshTray() {
  if (!tray) return;
  const pending = status.unacknowledged || 0;
  const snoozed = Date.now() / 1000 < (settings.snoozed_until || 0);
  const line = pending
    ? `${pending} alert${pending === 1 ? "" : "s"} to review`
    : status.apps != null
      ? `Monitoring ${status.apps} apps · ${status.connections} connections`
      : "Starting monitoring…";
  tray.setImage(trayIcon(status.unacknowledged_high > 0));
  tray.setToolTip("Beaver · " + line + (snoozed ? " · notifications paused" : ""));
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: line, enabled: false },
      { type: "separator" },
      { label: "Open Beaver", click: () => showWindow() },
      ...(updateReady
        ? [{ label: `Restart to update to ${updateReady}`, click: installUpdate }]
        : []),
      {
        label: pending ? `Review alerts (${pending})` : "Alerts",
        click: () => showWindow({ page: "alerts" }),
      },
      { type: "separator" },
      {
        label: snoozed ? "Resume notifications" : "Pause notifications for 1 hour",
        click: () =>
          backend
            .call("settings", {
              patch: { snoozed_until: snoozed ? 0 : Date.now() / 1000 + 3600 },
            })
            .then((value) => {
              settings = value;
              refreshTray();
            })
            .catch(() => {}),
      },
      { type: "separator" },
      {
        label: "Quit Beaver",
        click: () => {
          quitting = true;
          app.quit();
        },
      },
    ]),
  );
}

function refreshOverlay() {
  if (!win || process.platform !== "win32") return;
  win.setOverlayIcon(
    status.unacknowledged_high > 0 ? icons["tray-alert.png"] : null,
    status.unacknowledged_high > 0 ? "High-risk alerts to review" : "",
  );
}

function applyLoginItem(enabled, strict = false) {
  if (!app.isPackaged) {
    if (strict && enabled)
      throw new Error("Start at login is available in installed builds.");
    return;
  }
  if (process.platform === "linux") {
    // XDG autostart; AppImage exposes its own path in APPIMAGE.
    const dir = path.join(os.homedir(), ".config", "autostart");
    const file = path.join(dir, "beaver.desktop");
    const exec = (process.env.APPIMAGE || process.execPath).replace(/"/g, '\\"');
    const body =
      "[Desktop Entry]\nType=Application\nName=Beaver\nComment=Network security monitor\n" +
      `Exec="${exec}" --hidden\nIcon=beaver-security\nX-GNOME-Autostart-enabled=true\nNoDisplay=false\n`;
    void (enabled
      ? fs.mkdir(dir, { recursive: true }).then(() => fs.writeFile(file, body, { mode: 0o644 }))
      : fs.rm(file, { force: true })
    ).catch(() => {});
    return;
  }
  app.setLoginItemSettings({ openAtLogin: Boolean(enabled), args: ["--hidden"] });
}
