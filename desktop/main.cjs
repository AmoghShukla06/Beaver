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
} = require("electron");
const path = require("node:path");
const os = require("node:os");
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

async function start() {
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
  updater.on("error", () => {}); // offline or no release metadata: try again later
  updater.on("update-downloaded", (info) => {
    updateReady = info.version;
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

function startBackend() {
  const dataDir =
    process.env.BEAVER_TEST_DATA && !app.isPackaged
      ? process.env.BEAVER_TEST_DATA
      : path.join(app.getPath("userData"), "data");
  backend = new Backend({
    directory: dataDir,
    packaged: app.isPackaged,
    resources: process.resourcesPath,
    onEvent,
    onExit: () => {
      if (quitting) return;
      // Monitoring must survive a crashed service, but never spin: at most 5 restarts in 10 minutes.
      const now = Date.now();
      restarts = restarts.filter((t) => now - t < 600000);
      if (restarts.length >= 5) return;
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
      if (method === "snapshot") settings = result.settings;
      return result;
    });
  }
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

function flushAlerts() {
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

function toast({ title, body, critical = false, target, actions = [] }) {
  if (!Notification.isSupported())
    throw new Error("Native notifications are unavailable in this desktop session.");
  const notification = new Notification({
    title,
    body: body.slice(0, 250),
    icon: asset("beaver.png"),
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
