//! Beaver monitoring service. Private line-delimited JSON-RPC over inherited stdin/stdout; no listening socket.
mod binaries;
mod capture;
mod dnscache;
mod firewall;
mod geodownload;
mod intel;
mod model;
mod monitor;
mod net;
mod pcap;
mod risk;
mod store;

use firewall::{rule_id, validate, Firewall};
use monitor::Monitor;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use store::Store;

pub fn system() -> &'static str {
    if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "Other"
    }
}

/// Methods that wait on the network or an OS authorization prompt run off the request loop.
const SLOW: [&str; 6] = ["refresh_feed", "download_geoip", "block", "unblock", "verify_rules", "terminate"];

struct Service {
    store: Arc<Store>,
    monitor: Arc<Monitor>,
    firewall: Firewall,
    out: Arc<Mutex<std::io::Stdout>>,
}

fn send(out: &Mutex<std::io::Stdout>, message: &Value) {
    let mut out = out.lock().unwrap();
    let _ = writeln!(out, "{message}");
    let _ = out.flush();
}

fn param<'a>(params: &'a Value, key: &str) -> Result<&'a Value, String> {
    params.get(key).ok_or_else(|| format!("'{key}'"))
}

impl Service {
    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, String> {
        if !params.is_object() {
            return Err("Expected an object".into());
        }
        match method {
            "snapshot" => {
                let mut s = self.monitor.snapshot();
                s["alerts"] = json!(self.store.alerts(200));
                s["rules"] = json!(self.firewall.rules());
                s["settings"] = json!(self.store.settings());
                s["allowlist"] = json!(self.store.allowlist());
                s["firewall"] = self.firewall.capabilities();
                s["data_path"] = json!(self.store.directory.to_string_lossy());
                Ok(s)
            }
            "history" => {
                let app = param(params, "app_id")?.as_str().ok_or("Invalid application")?;
                self.store.history(app, params["offset"].as_i64().unwrap_or(0), params["limit"].as_i64().unwrap_or(50))
            }
            "settings" => {
                let patch = params.get("patch").cloned().unwrap_or(json!({}));
                let patch = patch.as_object().ok_or("Invalid settings")?;
                if let Some(path) = patch.get("geoip_path").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                    intel::validate_city_db(path)?;
                }
                Ok(json!(self.store.set_settings(patch)?))
            }
            "download_geoip" => {
                let path = geodownload::download_city(&self.store.directory)?;
                Ok(json!(self.store.set_settings(json!({ "geoip_path": path }).as_object().unwrap())?))
            }
            "refresh_feed" => self.monitor.intel.refresh(false),
            "acknowledge" => {
                self.store.acknowledge(param(params, "id")?.as_str().ok_or("Invalid alert")?)?;
                self.monitor.reset_summary();
                Ok(json!({ "ok": true }))
            }
            "visibility" => {
                self.monitor.visible.store(params["visible"] == true, std::sync::atomic::Ordering::Relaxed);
                Ok(json!({ "ok": true }))
            }
            "verify_rules" => Ok(self.firewall.verify()),
            "terminate" => self.monitor.terminate(param(params, "app_id")?.as_str().ok_or("Invalid application")?),
            "block" => self.firewall.apply(param(params, "kind")?.as_str().unwrap_or(""), param(params, "target")?.as_str().ok_or("Invalid firewall target")?),
            "unblock" => self.firewall.remove(param(params, "id")?.as_str().ok_or("Unknown Beaver rule")?),
            "allowlist" => {
                let kind = param(params, "kind")?.as_str().unwrap_or("");
                let target = param(params, "target")?.as_str().unwrap_or("");
                let enabled = param(params, "enabled")?.as_bool().ok_or("Invalid allowlist entry")?;
                let target = match kind {
                    "endpoint" => validate(kind, target, system())?,
                    "application" if Path::new(target).is_absolute() && target.len() <= 4096 => target.to_string(),
                    "application" => return Err("Expected absolute application path".into()),
                    _ => return Err("Invalid allowlist entry".into()),
                };
                self.store.allow(&rule_id(kind, &target), kind, &target, enabled)?;
                Ok(json!({ "ok": true }))
            }
            _ => Err("Unknown method".into()),
        }
    }

    fn handle(&self, request: &Value) {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request["method"].as_str().unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let response = match self.dispatch(method, &params) {
            Ok(result) => json!({ "id": id, "result": result }),
            Err(e) => json!({ "id": id, "error": e.chars().take(600).collect::<String>() }),
        };
        send(&self.out, &response);
    }
}

// ---- logging: local, rotating, errors and lifecycle only -----------------------------------------

struct FileLog {
    path: PathBuf,
    lock: Mutex<()>,
}
impl log::Log for FileLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info && m.target().starts_with("beaver_service")
    }
    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let _guard = self.lock.lock().unwrap();
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > 1_000_000) {
            let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(f, "{:.3} {} {}", intel::now(), r.level(), r.args());
        }
    }
    fn flush(&self) {}
}

fn setup_logging(directory: &Path) {
    let dir = directory.join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let logger = Box::leak(Box::new(FileLog { path: dir.join("service.log"), lock: Mutex::new(()) }));
    if log::set_logger(logger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
    log::info!("Service {} started on {} ({})", env!("CARGO_PKG_VERSION"), system(), std::env::consts::ARCH);
}

/// A permanent background monitor should never compete with foreground work.
fn background_priority() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS};
        SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
    #[cfg(unix)]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(dir) = args.iter().position(|a| a == "--data-dir").and_then(|i| args.get(i + 1)) else {
        eprintln!("usage: beaver-service --data-dir <path>");
        std::process::exit(2);
    };
    let directory = PathBuf::from(dir);
    let store = match Store::open(&directory) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Could not open data store: {e}");
            std::process::exit(1);
        }
    };
    setup_logging(&directory);
    // A panic in any worker leaves poisoned locks behind; exit so the desktop app restarts a clean service.
    std::panic::set_hook(Box::new(|info| {
        log::error!("Service panic: {info}");
        eprintln!("Service panic: {info}");
        std::process::exit(70);
    }));
    background_priority();
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let events = out.clone();
    // Unsolicited event lines (no id) let the desktop react to alerts without polling.
    let monitor = Monitor::new(store.clone(), Arc::new(move |event: &str, data| send(&events, &json!({ "event": event, "data": data }))));
    let service = Arc::new(Service { firewall: Firewall::new(store.clone()), store, monitor: monitor.clone(), out });
    monitor.run();
    {
        let s = service.clone();
        std::thread::spawn(move || {
            if !s.store.rules().is_empty() {
                s.firewall.verify();
            }
        });
    }
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.len() > 65536 {
            send(&service.out, &json!({ "id": null, "error": "Request is too large" }));
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v @ Value::Object(_)) => v,
            Ok(_) => {
                send(&service.out, &json!({ "id": null, "error": "Expected an object" }));
                continue;
            }
            Err(e) => {
                send(&service.out, &json!({ "id": null, "error": e.to_string() }));
                continue;
            }
        };
        if SLOW.contains(&request["method"].as_str().unwrap_or("")) {
            let s = service.clone();
            std::thread::spawn(move || s.handle(&request));
        } else {
            service.handle(&request);
        }
    }
    monitor.shutdown(); // stdin closed: the desktop app is gone
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_rejects_unknown_and_invalid() {
        let (store, dir) = store::tests::temp();
        let store = Arc::new(store);
        let service = Service {
            monitor: Monitor::new(store.clone(), Arc::new(|_: &str, _| {})),
            firewall: Firewall::new(store.clone()),
            store,
            out: Arc::new(Mutex::new(std::io::stdout())),
        };
        assert!(service.dispatch("execute_shell", &json!({})).is_err());
        assert!(service.dispatch("snapshot", &json!([])).is_err());
        assert!(service.dispatch("allowlist", &json!({"kind": "endpoint", "target": "1.1.1.1", "enabled": "yes"})).is_err());
        assert!(service.dispatch("terminate", &json!({"app_id": "not-running"})).is_err());
        assert_eq!(service.dispatch("visibility", &json!({"visible": false})).unwrap(), json!({"ok": true}));
        let snap = service.dispatch("snapshot", &json!({})).unwrap();
        assert!(snap["settings"]["notifications"] == true && snap["firewall"]["lockdown"] == firewall::LOCKDOWN_PORTS);
        let _ = std::fs::remove_dir_all(dir);
    }
}
