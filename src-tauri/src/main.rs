//! Beaver desktop shell (Tauri). Owns the tray, notifications, login item and the window; the monitoring
//! service runs as a separate sidecar process and speaks line-delimited JSON-RPC over stdio.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod icons;
mod service;
mod updater;

use serde_json::{json, Value};
use service::Service;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use tauri_plugin_dialog::DialogExt as _;
use tauri_plugin_opener::OpenerExt as _;

const RPC_METHODS: [&str; 11] = ["snapshot", "history", "settings", "refresh_feed", "download_geoip", "acknowledge", "block", "unblock", "allowlist", "terminate", "verify_rules"];
const TRAY: &[u8] = include_bytes!("../../assets/tray.png");
const TRAY_ALERT: &[u8] = include_bytes!("../../assets/tray-alert.png");

#[derive(Default)]
struct Shell {
    settings: Value,
    status: Value,
    navigation: Option<Value>,
    known_paths: HashSet<String>,
    queued: Vec<Value>,
    last_toast: Option<Instant>,
    toast_pending: bool,
    whats_new: Option<Value>,
    quitting: bool,
}

pub struct State {
    service: Mutex<Option<Arc<Service>>>,
    shell: Mutex<Shell>,
    restarts: Mutex<Vec<Instant>>,
    pub update: Mutex<Value>,
}

pub fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Same locations Electron used (%APPDATA%\Beaver\data, ~/.config/Beaver/data) so upgrades keep history.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("BEAVER_TEST_DATA").filter(|_| cfg!(debug_assertions)) {
        return PathBuf::from(dir);
    }
    base_dir().join("data")
}
pub fn base_dir() -> PathBuf {
    #[cfg(windows)]
    let root = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    #[cfg(not(windows))]
    let root = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config"));
    root.join("Beaver")
}
fn logs_dir() -> PathBuf {
    data_dir().join("logs")
}

/// Local app log, about 2 MB max (one rotation). Errors and lifecycle only, never connection data.
pub fn log(message: &str) {
    let file = logs_dir().join("app.log");
    let _ = std::fs::create_dir_all(logs_dir());
    if std::fs::metadata(&file).is_ok_and(|m| m.len() > 1_000_000) {
        let _ = std::fs::rename(&file, file.with_extension("log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&file) {
        use std::io::Write;
        let _ = writeln!(f, "{:.3} {message}", now());
    }
}

fn state(app: &AppHandle) -> tauri::State<'_, State> {
    app.state::<State>()
}

pub fn service(app: &AppHandle) -> Result<Arc<Service>, String> {
    state(app).service.lock().unwrap().clone().ok_or_else(|| "Telemetry service is starting.".to_string())
}

/// Tell the service whether a window is visible without blocking the calling (often main) thread.
fn set_visible(app: &AppHandle, visible: bool) {
    if let Ok(s) = service(app) {
        std::thread::spawn(move || {
            let _ = s.call("visibility", json!({ "visible": visible }));
        });
    }
}

fn start_service(app: &AppHandle) {
    let handle = app.clone();
    let on_event = move |event: &str, data: Value| on_event(&handle, event, data);
    let restart = app.clone();
    let on_exit = move || {
        let st = state(&restart);
        if st.shell.lock().unwrap().quitting {
            return;
        }
        // Monitoring must survive a crashed service, but never spin: at most 5 restarts in 10 minutes.
        let mut restarts = st.restarts.lock().unwrap();
        restarts.retain(|t| t.elapsed() < Duration::from_secs(600));
        if restarts.len() >= 5 {
            log("service restart limit reached");
            return;
        }
        restarts.push(Instant::now());
        let again = restart.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            start_service(&again);
        });
    };
    match Service::spawn(&data_dir(), Box::new(on_event), Box::new(on_exit)) {
        Ok(s) => {
            *state(app).service.lock().unwrap() = Some(Arc::new(s));
            set_visible(app, app.get_webview_window("main").is_some());
        }
        Err(e) => log(&format!("service failed to start: {e}")),
    }
}

// ---- window ------------------------------------------------------------------------------------

/// WebView2 flags: Tauri's defaults plus software compositing (the UI is static SVG and tables, and the GPU
/// process costs ~100 MB in an app that stays open all day). Debug builds keep WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
/// (used by the end-to-end tests to open a DevTools port).
fn browser_args() -> String {
    let mut args = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-gpu".to_string();
    if cfg!(debug_assertions) {
        if let Ok(extra) = std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") {
            args = format!("{args} {extra}");
        }
    }
    args
}

/// Show (or create) the window. Always runs on the main thread, whichever thread asks.
fn show_window(app: &AppHandle, target: Option<Value>) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || show_window_now(&handle, target));
}

fn show_window_now(app: &AppHandle, target: Option<Value>) {
    if let Some(t) = target {
        state(app).shell.lock().unwrap().navigation = Some(t);
    }
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
        if let Some(nav) = state(app).shell.lock().unwrap().navigation.take() {
            let _ = win.emit("beaver:navigate", nav);
        }
        return;
    }
    log("creating window");
    let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Beaver")
        .inner_size(1440.0, 960.0)
        .min_inner_size(760.0, 600.0)
        .background_color(tauri::window::Color(11, 16, 24, 255))
        .additional_browser_args(&browser_args())
        // The webview may only show Beaver's own pages; external links go through `open_url`'s allowlist.
        .on_navigation(|url| matches!(url.host_str(), Some("tauri.localhost") | Some("localhost") | Some("127.0.0.1")) || url.scheme() == "tauri")
        .build();
    match win {
        Ok(win) => {
            let _ = win.set_focus();
            set_visible(app, true);
            refresh_overlay(app);
        }
        Err(e) => log(&format!("window failed: {e}")),
    }
}

fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    let app = window.app_handle();
    match event {
        WindowEvent::CloseRequested { .. } => {
            // Closing destroys the webview (the largest memory consumer); the run loop's ExitRequested guard keeps
            // Beaver alive in the tray. Without a tray, or with close-to-tray off, closing quits Beaver.
            let quit_now = {
                let st = state(app);
                let shell = st.shell.lock().unwrap();
                !shell.quitting && (app.tray_by_id("main").is_none() || shell.settings["close_to_tray"] == false)
            };
            if quit_now {
                quit(app);
            }
        }
        WindowEvent::Destroyed => set_visible(app, false),
        WindowEvent::Resized(_) => set_visible(app, !window.is_minimized().unwrap_or(false)),
        _ => {}
    }
}

// ---- events, notifications, tray ---------------------------------------------------------------

fn on_event(app: &AppHandle, event: &str, data: Value) {
    match event {
        "status" => {
            state(app).shell.lock().unwrap().status = data;
            refresh_tray(app);
            refresh_overlay(app);
        }
        "alert" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.emit("beaver:alert", &data);
            }
            let st = state(app);
            let mut shell = st.shell.lock().unwrap();
            let s = &shell.settings;
            let remote = data["risk"]["evidence"].as_array().is_some_and(|e| e.iter().any(|x| x["category"] == "remote"));
            let level = data["level"].as_str().unwrap_or("");
            let wanted = level == "High"
                || (remote && s["remote_alerts"] != false)
                || (level == "Info" && s["notify_new_apps"] != false)
                || (level == "Medium" && s["notify_medium"] == true);
            if s["notifications"] == false || now() < s["snoozed_until"].as_f64().unwrap_or(0.0) || !wanted {
                return;
            }
            shell.queued.push(data);
            // Coalesce bursts: at most one toast every 8 seconds; the rest are summarized.
            if !shell.toast_pending {
                shell.toast_pending = true;
                let wait = shell.last_toast.map(|t| Duration::from_secs(8).saturating_sub(t.elapsed())).unwrap_or_default();
                let app = app.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(wait);
                    flush_alerts(&app);
                });
            }
        }
        _ => {}
    }
}

#[derive(Clone)]
pub struct Action {
    pub label: &'static str,
    pub id: String,
}

fn flush_alerts(app: &AppHandle) {
    let batch: Vec<Value> = {
        let st = state(app);
        let mut shell = st.shell.lock().unwrap();
        shell.toast_pending = false;
        shell.last_toast = Some(Instant::now());
        std::mem::take(&mut shell.queued)
    };
    let Some(alert) = batch.first() else { return };
    if batch.len() > 1 {
        let mut names: Vec<&str> = batch.iter().filter_map(|a| a["app_name"].as_str()).collect();
        names.dedup();
        let high = batch.iter().any(|a| a["level"] == "High");
        notify(app, &format!("Beaver · {} new security alerts", batch.len()),
               &format!("{}. Click to review the evidence.", names.iter().take(4).cloned().collect::<Vec<_>>().join(", ")), high, json!({ "page": "alerts" }), vec![], None);
        return;
    }
    let name = alert["app_name"].as_str().unwrap_or("An app");
    let ep = &alert["endpoint"];
    let place = if ep.is_object() {
        format!(" · {}{}", ep["domain"].as_str().or(ep["ip"].as_str()).unwrap_or(""), ep["country"].as_str().map(|c| format!(" ({c})")).unwrap_or_default())
    } else {
        String::new()
    };
    let target = json!({ "page": "alerts", "app_id": alert["app_id"], "alert_id": alert["id"] });
    let id = alert["id"].as_str().unwrap_or("").to_string();
    let block = (cfg!(windows) && alert["path"].is_string()).then(|| Action { label: "Block app", id: format!("block:{id}") });
    let review = Action { label: "Review", id: "review".into() };
    let remote = alert["risk"]["evidence"].as_array().and_then(|e| e.iter().find(|x| x["category"] == "remote")).cloned();
    let (title, body, actions) = if alert["response"]["action"] == "terminated" {
        (format!("Beaver stopped {name}"), format!("{}. Active protection ended the process. Review the evidence and block it if needed.", alert["title"].as_str().unwrap_or("")),
         [Some(review), block].into_iter().flatten().collect())
    } else if let Some(r) = remote {
        (format!("Remote access alert · {name}"), format!("{}{place}. If you did not start this, end the session now.", r["title"].as_str().unwrap_or("")),
         vec![Action { label: "End session", id: format!("end:{id}") }, review])
    } else if alert["level"] == "Info" {
        let who = alert["publisher"].as_str().map(|p| format!("Signed by {p}")).unwrap_or_else(|| if alert["signature"] == "unsigned" { "Unsigned program".into() } else { "Publisher unknown".into() });
        (format!("New app online · {name}"), format!("{who}{place}. First internet connection seen by Beaver."),
         vec![Some(Action { label: "Looks fine", id: format!("ack:{id}") }), Some(block.unwrap_or(review))].into_iter().flatten().collect())
    } else {
        (format!("{} risk · {name}", alert["level"].as_str().unwrap_or("")), format!("{}{place}. Click to investigate.", alert["title"].as_str().unwrap_or("")),
         [Some(Action { label: "Investigate", id: "review".into() }), block].into_iter().flatten().collect())
    };
    let critical = alert["level"] == "High" || title.starts_with("Remote");
    let icon = alert["path"].as_str().and_then(icons::png_file);
    let alert = alert.clone();
    notify(app, &title, &body, critical, target, actions, Some((alert, icon)));
}

/// A notification button runs one service action directly; the OS still asks for elevation where required.
fn act(app: &AppHandle, action: &str, alert: &Value) {
    let name = alert["app_name"].as_str().unwrap_or("the app").to_string();
    let (method, params, done) = match action.split(':').next().unwrap_or("") {
        "end" => ("terminate", json!({ "app_id": alert["app_id"] }), format!("{name} was stopped. Anyone connected through it is disconnected.")),
        "block" => ("block", json!({ "kind": "application", "target": alert["path"] }), format!("{name} is blocked from the network.")),
        "ack" => ("acknowledge", json!({ "id": alert["id"] }), String::new()),
        "update" => return updater::install(app),
        _ => return show_window(app, Some(json!({ "page": "alerts", "app_id": alert["app_id"] }))),
    };
    let app = app.clone();
    let alert = alert.clone();
    std::thread::spawn(move || match service(&app).and_then(|s| s.call(method, params)) {
        Ok(_) if !done.is_empty() => notify(&app, "Beaver", &done, false, json!({ "page": "alerts" }), vec![], None),
        Ok(_) => {}
        Err(e) => notify(&app, &format!("Beaver could not complete that for {name}"), &e, false, json!({ "page": "alerts", "app_id": alert["app_id"] }), vec![], None),
    });
}

pub fn notify(app: &AppHandle, title: &str, body: &str, critical: bool, target: Value, actions: Vec<Action>, alert: Option<(Value, Option<PathBuf>)>) {
    let body: String = body.chars().take(250).collect();
    let (alert, icon) = alert.unwrap_or((Value::Null, None));
    let icon = icon.or_else(|| icons::brand_png());
    #[cfg(windows)]
    {
        use tauri_winrt_notification::{Duration as D, IconCrop, Toast};
        let app_id = if cfg!(debug_assertions) { Toast::POWERSHELL_APP_ID.to_string() } else { app.config().identifier.clone() };
        let mut toast = Toast::new(&app_id).title(title).text1(&body).duration(if critical { D::Long } else { D::Short });
        if let Some(p) = &icon {
            toast = toast.icon(p, IconCrop::Square, "");
        }
        for a in &actions {
            toast = toast.add_button(a.label, &a.id);
        }
        let handle = app.clone();
        toast = toast.on_activated(move |action| {
            match action.as_deref() {
                Some(a) if a != "review" => act(&handle, a, &alert),
                _ => {
                    let h = handle.clone();
                    let t = target.clone();
                    show_window(&h, Some(t));
                }
            }
            Ok(())
        });
        if let Err(e) = toast.show() {
            log(&format!("notification failed: {e}"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut n = notify_rust::Notification::new();
        n.summary(title).body(&body).appname("Beaver").urgency(if critical { notify_rust::Urgency::Critical } else { notify_rust::Urgency::Normal });
        match &icon {
            Some(p) => n.icon(&p.to_string_lossy()),
            None => n.icon("beaver"),
        };
        n.action("default", "Open");
        for a in &actions {
            n.action(&a.id, a.label);
        }
        let handle = app.clone();
        std::thread::spawn(move || match n.show() {
            Ok(shown) => shown.wait_for_action(|action| match action {
                "__closed" => {}
                "default" | "review" => {
                    let h = handle.clone();
                    show_window(&h, Some(target));
                }
                other => act(&handle, other, &alert),
            }),
            Err(e) => log(&format!("notification failed: {e}")),
        });
    }
}

fn refresh_tray(app: &AppHandle) {
    let Some(tray) = app.tray_by_id("main") else { return };
    let (line, snoozed, alert_icon) = {
        let st = state(app);
        let shell = st.shell.lock().unwrap();
        let pending = shell.status["unacknowledged"].as_i64().unwrap_or(0);
        let snoozed = now() < shell.settings["snoozed_until"].as_f64().unwrap_or(0.0);
        let line = if pending > 0 {
            format!("{pending} alert{} to review", if pending == 1 { "" } else { "s" })
        } else if shell.status["apps"].is_number() {
            format!("Monitoring {} apps · {} connections", shell.status["apps"], shell.status["connections"])
        } else {
            "Starting monitoring…".into()
        };
        (line, snoozed, shell.status["unacknowledged_high"].as_i64().unwrap_or(0) > 0)
    };
    let update = state(app).update.lock().unwrap().clone();
    let _ = tray.set_icon(Image::from_bytes(if alert_icon { TRAY_ALERT } else { TRAY }).ok());
    let _ = tray.set_tooltip(Some(format!("Beaver · {line}{}", if snoozed { " · notifications paused" } else { "" })));
    let build = || -> tauri::Result<Menu<tauri::Wry>> {
        let menu = Menu::new(app)?;
        menu.append(&MenuItem::with_id(app, "status", &line, false, None::<&str>)?)?;
        menu.append(&PredefinedMenuItem::separator(app)?)?;
        menu.append(&MenuItem::with_id(app, "open", "Open Beaver", true, None::<&str>)?)?;
        menu.append(&MenuItem::with_id(app, "alerts", "Alerts", true, None::<&str>)?)?;
        if update["state"] == "ready" {
            menu.append(&MenuItem::with_id(app, "update", format!("Restart to update to {}", update["version"].as_str().unwrap_or("")), true, None::<&str>)?)?;
        }
        menu.append(&PredefinedMenuItem::separator(app)?)?;
        menu.append(&MenuItem::with_id(app, "snooze", if snoozed { "Resume notifications" } else { "Pause notifications for 1 hour" }, true, None::<&str>)?)?;
        menu.append(&PredefinedMenuItem::separator(app)?)?;
        menu.append(&MenuItem::with_id(app, "quit", "Quit Beaver", true, None::<&str>)?)?;
        Ok(menu)
    };
    if let Ok(menu) = build() {
        let _ = tray.set_menu(Some(menu));
    }
}

fn refresh_overlay(app: &AppHandle) {
    #[cfg(windows)]
    if let Some(win) = app.get_webview_window("main") {
        let high = state(app).shell.lock().unwrap().status["unacknowledged_high"].as_i64().unwrap_or(0) > 0;
        let _ = win.set_overlay_icon(if high { Image::from_bytes(TRAY_ALERT).ok() } else { None });
    }
    let _ = app;
}

fn on_menu(app: &AppHandle, id: &str) {
    match id {
        "open" => show_window(app, None),
        "alerts" => show_window(app, Some(json!({ "page": "alerts" }))),
        "update" => updater::install(app),
        "snooze" => {
            let snoozed = now() < state(app).shell.lock().unwrap().settings["snoozed_until"].as_f64().unwrap_or(0.0);
            let until = if snoozed { 0.0 } else { now() + 3600.0 };
            if let Ok(v) = service(app).and_then(|s| s.call("settings", json!({ "patch": { "snoozed_until": until } }))) {
                state(app).shell.lock().unwrap().settings = v;
                refresh_tray(app);
            }
        }
        "quit" => quit(app),
        _ => {}
    }
}

pub fn quit(app: &AppHandle) {
    state(app).shell.lock().unwrap().quitting = true;
    if let Some(s) = state(app).service.lock().unwrap().take() {
        s.close();
    }
    app.exit(0);
}

fn apply_login_item(app: &AppHandle, enabled: bool) {
    if cfg!(debug_assertions) {
        return;
    }
    let launcher = app.autolaunch();
    let result = if enabled { launcher.enable() } else { launcher.disable() };
    if let Err(e) = result {
        log(&format!("login item: {e}"));
    }
}

/// The Windows installer's "Start Beaver when I sign in" choice, applied once and then removed.
fn apply_installer_options(app: &AppHandle) {
    let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)) else { return };
    let file = dir.join("installer-options.json");
    let Ok(text) = std::fs::read_to_string(&file) else { return };
    if let Some(enabled) = serde_json::from_str::<Value>(&text).ok().and_then(|v| v["start_at_login"].as_bool()) {
        if let Ok(v) = service(app).and_then(|s| s.call("settings", json!({ "patch": { "start_at_login": enabled } }))) {
            state(app).shell.lock().unwrap().settings = v;
        }
    }
    let _ = std::fs::remove_file(file);
    log(&format!("applied installer options: {}", text.trim()));
}

fn track_version(app: &AppHandle) {
    let marker = base_dir().join("last-version");
    let current = app.package_info().version.to_string();
    let previous = std::fs::read_to_string(&marker).unwrap_or_default().trim().to_string();
    if !previous.is_empty() && previous != current {
        state(app).shell.lock().unwrap().whats_new = Some(json!({ "from": previous, "to": current }));
    }
    let _ = std::fs::create_dir_all(base_dir());
    let _ = std::fs::write(marker, current);
}

// ---- commands (the window's only API; see capabilities/default.json) ----------------------------

#[tauri::command]
async fn rpc(app: AppHandle, method: String, params: Value) -> Result<Value, String> {
    if !RPC_METHODS.contains(&method.as_str()) || !params.is_object() || params.to_string().len() > 32768 {
        return Err("Invalid request".into());
    }
    if method == "settings" {
        if let Some(enabled) = params["patch"]["start_at_login"].as_bool() {
            if cfg!(debug_assertions) && enabled {
                return Err("Start at login is available in installed builds.".into());
            }
            apply_login_item(&app, enabled);
        }
    }
    let svc = service(&app)?;
    let m = method.clone();
    let result = tauri::async_runtime::spawn_blocking(move || svc.call(&m, params)).await.map_err(|e| e.to_string())??;
    let st = state(&app);
    let mut shell = st.shell.lock().unwrap();
    if method == "settings" {
        shell.settings = result.clone();
    }
    if method == "snapshot" {
        shell.settings = result["settings"].clone();
        shell.known_paths = result["apps"].as_array().into_iter().flatten().chain(result["alerts"].as_array().into_iter().flatten())
            .filter_map(|a| a["path"].as_str().map(String::from)).collect();
    }
    drop(shell);
    if method == "settings" {
        refresh_tray(&app);
    }
    Ok(result)
}

#[tauri::command]
async fn pick_geoip(app: AppHandle) -> Result<Value, String> {
    let picked = app.dialog().file().set_title("Choose a local GeoIP City database").add_filter("MaxMind database", &["mmdb"]).blocking_pick_file();
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else { return Ok(json!({ "cancelled": true })) };
    let svc = service(&app)?;
    tauri::async_runtime::spawn_blocking(move || svc.call("settings", json!({ "patch": { "geoip_path": path.to_string_lossy() } }))).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn export_history(app: AppHandle, app_id: String) -> Result<Value, String> {
    if app_id.len() > 100 {
        return Err("Invalid application".into());
    }
    let picked = app.dialog().file().set_title("Export connection history").set_file_name("beaver-connections.json").add_filter("JSON", &["json"]).blocking_save_file();
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else { return Ok(json!({ "cancelled": true })) };
    let svc = service(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut items = vec![];
        let mut offset = 0;
        loop {
            let page = svc.call("history", json!({ "app_id": app_id, "offset": offset, "limit": 100 }))?;
            let got = page["items"].as_array().cloned().unwrap_or_default();
            offset += got.len();
            let done = got.is_empty() || offset as i64 >= page["total"].as_i64().unwrap_or(0) || offset >= 100_000;
            items.extend(got);
            if done {
                break;
            }
        }
        let doc = json!({ "exported_at": now(), "app_id": app_id, "connections": items });
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).map_err(|e| e.to_string())?;
        Ok(json!({ "exported": items.len() }))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn test_notification(app: AppHandle) -> Value {
    notify(&app, "Beaver notification test", "Native notifications are connected. High-risk and remote-access detections will appear here, even when the window is closed.",
           false, json!({ "page": "settings" }), vec![], None);
    json!({ "ok": true })
}

#[tauri::command]
fn icon(app: AppHandle, path: String) -> Option<String> {
    // Only paths the service reported may be read for icons.
    state(&app).shell.lock().unwrap().known_paths.contains(&path).then(|| icons::data_url(&path)).flatten()
}

#[tauri::command]
fn app_info(app: AppHandle) -> Value {
    let st = state(&app);
    let shell = st.shell.lock().unwrap();
    let mut update = st.update.lock().unwrap().clone();
    if shell.settings["auto_update"] == false && update["state"] != "ready" {
        update["state"] = json!("off");
    }
    json!({ "version": app.package_info().version.to_string(), "runtime": format!("Tauri {}", tauri::VERSION),
            "packaged": !cfg!(debug_assertions), "update": update, "whats_new": shell.whats_new })
}

#[tauri::command]
async fn check_updates(app: AppHandle) -> Result<Value, String> {
    if cfg!(debug_assertions) {
        return Err("Updates are available in installed builds.".into());
    }
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || updater::check(&a)).await.map_err(|e| e.to_string())?;
    Ok(state(&app).update.lock().unwrap().clone())
}

#[tauri::command]
fn restart_update(app: AppHandle) -> Result<Value, String> {
    if state(&app).update.lock().unwrap()["state"] != "ready" {
        return Err("No update is ready yet.".into());
    }
    updater::install(&app);
    Ok(json!({ "ok": true }))
}

#[tauri::command]
fn dismiss_whats_new(app: AppHandle) -> Value {
    state(&app).shell.lock().unwrap().whats_new = None;
    json!({ "ok": true })
}

#[tauri::command]
fn open_logs(app: AppHandle) -> Result<Value, String> {
    let _ = std::fs::create_dir_all(logs_dir());
    app.opener().open_path(logs_dir().to_string_lossy(), None::<&str>).map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true }))
}

#[tauri::command]
fn copy_text(app: AppHandle, text: String) -> Result<Value, String> {
    if text.len() > 20000 {
        return Err("Invalid text".into());
    }
    app.clipboard().write_text(text).map_err(|e| e.to_string())?;
    Ok(json!({ "copied": true }))
}

#[tauri::command]
async fn copy_diagnostics(app: AppHandle) -> Result<Value, String> {
    let a = app.clone();
    let report = tauri::async_runtime::spawn_blocking(move || diagnostics(&a)).await.map_err(|e| e.to_string())?;
    app.clipboard().write_text(report).map_err(|e| e.to_string())?;
    Ok(json!({ "copied": true }))
}

#[tauri::command]
async fn reset_data(app: AppHandle) -> Result<Value, String> {
    // Stop the service (it holds the database), delete everything Beaver stored, then start fresh.
    state(&app).shell.lock().unwrap().quitting = true;
    apply_login_item(&app, false);
    if let Some(s) = state(&app).service.lock().unwrap().take() {
        s.close();
        s.wait(Duration::from_secs(5));
    }
    let dir = data_dir();
    for _ in 0..10 {
        if std::fs::remove_dir_all(&dir).is_ok() || !dir.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = std::fs::remove_file(base_dir().join("last-version"));
    app.restart();
}

#[tauri::command]
fn open_url(app: AppHandle, url: String) -> Result<(), String> {
    let allowed = url == "https://db-ip.com/"
        || url == "https://npcap.com/#download"
        || (url.starts_with("https://www.virustotal.com/gui/file/") && url.len() == 36 + 64 && url[36..].chars().all(|c| c.is_ascii_hexdigit()))
        || ["https://feodotracker.abuse.ch/", "https://www.spamhaus.org/", "https://github.com/", "https://rules.emergingthreats.net/", "https://attack.mitre.org/"]
            .iter()
            .any(|p| url.starts_with(p) && url[p.len()..].chars().all(|c| c.is_ascii_alphanumeric() || "./#-_".contains(c)));
    if !allowed {
        return Err("Link not allowed".into());
    }
    app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

/// Support report for GitHub issues. Usernames, IP addresses and paths are redacted.
fn diagnostics(app: &AppHandle) -> String {
    let tail = |name: &str| {
        std::fs::read_to_string(logs_dir().join(name)).map(|t| t.lines().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")).unwrap_or_else(|_| "(none)".into())
    };
    let snap = service(app).and_then(|s| s.call("snapshot", json!({}))).unwrap_or_else(|e| json!({ "error": e }));
    let c = &snap["coverage"];
    let mut settings = snap["settings"].clone();
    if let Some(o) = settings.as_object_mut() {
        o.remove("geoip_path");
    }
    let report = json!({
        "beaver": app.package_info().version.to_string(), "runtime": format!("Tauri {}", tauri::VERSION),
        "os": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH), "packaged": !cfg!(debug_assertions),
        "update": *state(app).update.lock().unwrap(), "settings": settings,
        "coverage": { "elevated": c["elevated"], "inventory_error": c["inventory_error"],
                      "capture": { "available": c["capture"]["available"], "active": c["capture"]["active"], "error": c["capture"]["error"], "interfaces": c["capture"]["interfaces"] },
                      "feeds": c["intel"]["feeds"].as_array().map(|f| f.iter().map(|x| format!("{}: {}", x["id"].as_str().unwrap_or(""),
                          if x["enabled"] == false { "off" } else if x["fresh"] == true { "current" } else { "stale" })).collect::<Vec<_>>()),
                      "dns_cache": c["dns_cache"], "geo": c["geo"]["available"], "power": c["power"] },
        "counts": { "apps": snap["apps"].as_array().map(Vec::len), "connections": snap["connections"].as_array().map(Vec::len),
                    "alerts": snap["alerts"].as_array().map(Vec::len), "rules": snap["rules"].as_array().map(Vec::len) },
        "error": snap["error"],
    });
    redact(&format!("## Beaver diagnostics\n```json\n{}\n```\n### app.log\n```\n{}\n```\n### service.log\n```\n{}\n```\n",
                    serde_json::to_string_pretty(&report).unwrap(), tail("app.log"), tail("service.log")))
}

/// Hide user names, IPv4 and IPv6 addresses while keeping clock times like 06:25:18.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let words: Vec<&str> = text.split_inclusive(|c: char| c.is_whitespace() || "\"',()[]{}".contains(c)).collect();
    for w in words {
        let (core, tail) = w.split_at(w.trim_end_matches(|c: char| c.is_whitespace() || "\"',()[]{}".contains(c)).len());
        out += &redact_word(core);
        out += tail;
    }
    out
}

fn redact_word(w: &str) -> String {
    let lower = w.to_lowercase();
    for marker in [":\\\\users\\\\", ":\\users\\", "/home/"] {
        if let Some(i) = lower.find(marker) {
            let start = i + marker.len();
            let rest = &w[start..];
            let end = rest.find(['\\', '/']).unwrap_or(rest.len());
            return format!("{}<user>{}", &w[..start], redact_word(&rest[end..]));
        }
    }
    let bare = w;
    let ip_part = bare.split('%').next().unwrap_or(bare);
    let is_v4 = ip_part.parse::<std::net::Ipv4Addr>().is_ok();
    let is_v6 = ip_part.contains("::") || ip_part.matches(':').count() >= 3;
    if (is_v4 || (is_v6 && ip_part.parse::<std::net::Ipv6Addr>().is_ok())) && !ip_part.is_empty() {
        return format!("<ip>{}", &bare[ip_part.len()..]);
    }
    w.to_string()
}

fn main() {
    let hidden = std::env::args().any(|a| a == "--hidden");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            log("second launch: showing window");
            show_window(app, None)
        }))
        .plugin(tauri_plugin_autostart::Builder::new().args(["--hidden"]).build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .manage(State { service: Mutex::new(None), shell: Mutex::new(Shell::default()), restarts: Mutex::default(), update: Mutex::new(json!({ "state": "disabled" })) })
        .invoke_handler(tauri::generate_handler![rpc, pick_geoip, export_history, test_notification, icon, app_info, check_updates, restart_update,
                                                 dismiss_whats_new, open_logs, copy_text, copy_diagnostics, reset_data, open_url])
        .on_window_event(on_window_event)
        .setup(move |app| {
            let handle = app.handle().clone();
            log(&format!("Beaver {} starting ({} {})", app.package_info().version, std::env::consts::OS, tauri::VERSION));
            if !cfg!(debug_assertions) {
                track_version(&handle);
            }
            start_service(&handle);
            let tray = TrayIconBuilder::with_id("main")
                .icon(Image::from_bytes(TRAY)?)
                .tooltip("Beaver")
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| on_menu(app, e.id.as_ref()))
                .on_tray_icon_event(|tray, e| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } | TrayIconEvent::DoubleClick { .. } = e {
                        show_window(tray.app_handle(), None);
                    }
                })
                .build(app);
            if let Err(e) = &tray {
                log(&format!("tray unavailable: {e}"));
            }
            if let Ok(v) = service(&handle).and_then(|s| s.call("settings", json!({ "patch": {} }))) {
                state(&handle).shell.lock().unwrap().settings = v;
                apply_installer_options(&handle);
                let login = state(&handle).shell.lock().unwrap().settings["start_at_login"] == true;
                apply_login_item(&handle, login);
            }
            refresh_tray(&handle);
            // Launched at sign-in: stay in the tray without a webview unless no tray exists.
            if !hidden || tray.is_err() {
                show_window(&handle, None);
            }
            updater::schedule(&handle);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Beaver failed to start")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                // Closing the last window keeps Beaver in the tray; only explicit Quit exits.
                if code.is_none() && !state(app).shell.lock().unwrap().quitting && app.tray_by_id("main").is_some() {
                    api.prevent_exit();
                }
            }
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn redaction() {
        let r = super::redact("C:\\Users\\amogh\\x.exe at 10.1.2.3 and 2606:4700::1111 06:25:18 \"C:\\\\Users\\\\amogh\\\\a\" /home/amogh/.cache fe80::1%eth0");
        assert!(!r.contains("amogh"), "{r}");
        assert!(r.contains("06:25:18") && !r.contains("10.1.2.3") && !r.contains("2606:4700") && !r.contains("fe80::1"), "{r}");
    }
}
