//! The monitoring service sidecar: spawn, line-delimited JSON-RPC, pushed events, exit detection.
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Reply = Result<Value, String>;

pub struct Service {
    stdin: Mutex<Option<ChildStdin>>,
    pending: Arc<Mutex<HashMap<u64, Sender<Reply>>>>,
    sequence: AtomicU64,
    error: Arc<Mutex<Option<String>>>,
    child: Mutex<Child>,
}

fn executable() -> PathBuf {
    let name = if cfg!(windows) { "beaver-service.exe" } else { "beaver-service" };
    let beside = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(name)));
    match beside.filter(|p| p.exists()) {
        Some(p) => p,
        // Development: cargo's shared workspace output.
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("target").join(if cfg!(debug_assertions) { "debug" } else { "release" }).join(name),
    }
}

impl Service {
    pub fn spawn(data_dir: &Path, on_event: Box<dyn Fn(&str, Value) + Send>, on_exit: Box<dyn Fn() + Send>) -> Result<Service, String> {
        let exe = executable();
        if !exe.exists() {
            return Err(format!("Telemetry service is missing ({}). Reinstall Beaver.", exe.display()));
        }
        let mut cmd = Command::new(&exe);
        cmd.arg("--data-dir").arg(data_dir).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0000_0008); // DETACHED_PROCESS: no console host at all; stdio pipes still work
        }
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let pending: Arc<Mutex<HashMap<u64, Sender<Reply>>>> = Arc::default();
        let error: Arc<Mutex<Option<String>>> = Arc::default();
        let (p, e) = (pending.clone(), error.clone());
        // Events are handled on their own thread: handlers touch the tray/window (main thread), and the
        // reader must stay free to deliver RPC replies the main thread may be waiting for.
        let (events_tx, events_rx) = channel::<(String, Value)>();
        std::thread::Builder::new().name("beaver-events".into()).spawn(move || {
            for (event, data) in events_rx {
                on_event(&event, data);
            }
        }).map_err(|e| e.to_string())?;
        std::thread::Builder::new().name("beaver-rpc".into()).spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(message) = serde_json::from_str::<Value>(&line) else { continue };
                if let Some(event) = message["event"].as_str() {
                    let _ = events_tx.send((event.to_string(), message["data"].clone()));
                    continue;
                }
                let Some(id) = message["id"].as_u64() else { continue };
                if let Some(tx) = p.lock().unwrap().remove(&id) {
                    let _ = tx.send(match message.get("error").and_then(Value::as_str) {
                        Some(err) => Err(err.to_string()),
                        None => Ok(message["result"].clone()),
                    });
                }
            }
            *e.lock().unwrap() = Some("Telemetry service stopped. Beaver is restarting it.".into());
            for (_, tx) in p.lock().unwrap().drain() {
                let _ = tx.send(Err("Telemetry service stopped. Beaver is restarting it.".into()));
            }
            on_exit();
        }).map_err(|e| e.to_string())?;
        // Tracebacks go to the local log file only.
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                crate::log(&format!("service stderr: {}", line.chars().take(4000).collect::<String>()));
            }
        });
        Ok(Service { stdin: Mutex::new(child.stdin.take()), pending, sequence: AtomicU64::new(0), error, child: Mutex::new(child) })
    }

    pub fn call(&self, method: &str, params: Value) -> Reply {
        if let Some(e) = self.error.lock().unwrap().clone() {
            return Err(e);
        }
        if self.pending.lock().unwrap().len() >= 32 {
            return Err("Too many pending requests".into());
        }
        let id = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = channel();
        self.pending.lock().unwrap().insert(id, tx);
        {
            let mut stdin = self.stdin.lock().unwrap();
            let Some(stdin) = stdin.as_mut() else { return Err("Telemetry service disconnected.".into()) };
            if writeln!(stdin, "{}", json!({ "id": id, "method": method, "params": params })).and_then(|_| stdin.flush()).is_err() {
                self.pending.lock().unwrap().remove(&id);
                return Err("Telemetry service disconnected.".into());
            }
        }
        rx.recv_timeout(Duration::from_secs(135)).unwrap_or_else(|_| {
            self.pending.lock().unwrap().remove(&id);
            Err("The operation timed out. Check the operating-system authorization dialog before retrying.".into())
        })
    }

    /// Closing stdin tells the service to stop; it is killed if it has not exited within 3 seconds.
    pub fn close(&self) {
        *self.error.lock().unwrap() = Some("Beaver is closing.".into());
        self.stdin.lock().unwrap().take();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut child = self.child.lock().unwrap();
        while std::time::Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
    }

    pub fn wait(&self, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        let mut child = self.child.lock().unwrap();
        while std::time::Instant::now() < deadline && child.try_wait().ok().flatten().is_none() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
