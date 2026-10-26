//! Background executable inspection: SHA-256, Authenticode status (Windows) and install location.
//! Cached per path+size+mtime, so each binary version is hashed and verified once.
use crate::intel::now;
use crate::model::Binary;
use crate::store::Store;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;

pub fn mtime(m: &std::fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Where an executable lives; user-writable staging folders are a classic malware trait.
pub fn location(path: &str, system: &str) -> &'static str {
    let p = path.replace('\\', "/").to_lowercase();
    if system == "Windows" {
        if ["/appdata/local/temp/", "/windows/temp/", "/$recycle.bin/", "/users/public/", "/downloads/"].iter().any(|s| p.contains(s)) {
            return "staging";
        }
        if ["c:/program files/", "c:/program files (x86)/", "c:/programdata/microsoft/windows defender/", "c:/windows/"].iter().any(|s| p.starts_with(s)) {
            return "system";
        }
        return "user";
    }
    if p.starts_with("/dev/shm/") {
        "memory"
    } else if p.starts_with("/tmp/") || p.starts_with("/var/tmp/") || p.contains("/downloads/") || p.contains("/.cache/") {
        "staging"
    } else if ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/var/lib/flatpak/", "/nix/store/", "/app/"].iter().any(|s| p.starts_with(s)) {
        "system"
    } else {
        "user"
    }
}

pub fn publisher(subject: &str) -> Option<String> {
    subject.split(',').map(str::trim).find_map(|p| p.strip_prefix("CN=")).map(|cn| cn.trim_matches('"').chars().take(200).collect())
}

fn sha256(path: &str) -> std::io::Result<Option<String>> {
    let mut file = std::fs::File::open(path)?;
    let (mut hasher, mut buf, mut total) = (Sha256::new(), vec![0u8; 1 << 20], 0u64);
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_HASH_BYTES {
            return Ok(None);
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}

const SIGNATURE_SCRIPT: &str = "$ErrorActionPreference='SilentlyContinue';$paths=[Console]::In.ReadToEnd()|ConvertFrom-Json;\
$out=@(foreach($p in $paths){$s=Get-AuthenticodeSignature -LiteralPath $p;[pscustomobject]@{path=$p;status=[string]$s.Status;\
subject=[string]$s.SignerCertificate.Subject;os=[bool]$s.IsOSBinary}});ConvertTo-Json -InputObject $out -Compress";

/// One hidden PowerShell process verifies a whole batch (including catalog-signed system files).
fn signatures(paths: &[String]) -> Result<HashMap<String, serde_json::Value>, String> {
    if !cfg!(windows) || paths.is_empty() {
        return Ok(HashMap::new());
    }
    let encoded = crate::firewall::encode_ps(SIGNATURE_SCRIPT);
    let input = serde_json::to_string(paths).unwrap();
    let out = crate::firewall::run(&["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded], Some(&input), 120)?;
    if out.0 != 0 {
        return Err(format!("Signature verification failed: {}", out.2.chars().rev().take(200).collect::<String>().chars().rev().collect::<String>()));
    }
    let rows: serde_json::Value = serde_json::from_str(if out.1.trim().is_empty() { "[]" } else { &out.1 }).map_err(|e| e.to_string())?;
    let rows = if rows.is_array() { rows.as_array().unwrap().clone() } else { vec![rows] };
    Ok(rows.into_iter().filter_map(|r| Some((r["path"].as_str()?.to_string(), r))).collect())
}

pub struct Binaries {
    store: Arc<Store>,
    system: &'static str,
    cache: Arc<Mutex<HashMap<String, Binary>>>,
    pending: Arc<Mutex<HashSet<String>>>,
    queue: Mutex<Option<Sender<String>>>,
    pub error: Arc<Mutex<Option<String>>>,
}

impl Binaries {
    pub fn new(store: Arc<Store>, system: &'static str) -> Binaries {
        Binaries { store, system, cache: Arc::default(), pending: Arc::default(), queue: Mutex::new(None), error: Arc::default() }
    }

    /// Cached inspection, or a pending record while one is scheduled. Never blocks sampling.
    pub fn info(&self, path: &str) -> Binary {
        if let Some(b) = self.cache.lock().unwrap().get(path) {
            return b.clone();
        }
        if let Some(b) = self.store.binary(path) {
            self.cache.lock().unwrap().insert(path.to_string(), b.clone());
            return b;
        }
        if self.pending.lock().unwrap().insert(path.to_string()) {
            let mut queue = self.queue.lock().unwrap();
            let delivered = queue.as_ref().is_some_and(|q| q.send(path.to_string()).is_ok());
            if !delivered {
                let (tx, rx) = channel::<String>();
                tx.send(path.to_string()).ok();
                *queue = Some(tx);
                let (store, cache, pending, error, system) = (self.store.clone(), self.cache.clone(), self.pending.clone(), self.error.clone(), self.system);
                std::thread::Builder::new()
                    .name("beaver-binaries".into())
                    .spawn(move || loop {
                        let first = match rx.recv_timeout(Duration::from_secs(30)) {
                            Ok(p) => p,
                            Err(RecvTimeoutError::Timeout) => continue,
                            Err(RecvTimeoutError::Disconnected) => return,
                        };
                        std::thread::sleep(Duration::from_millis(500)); // coalesce a startup burst into one verification process
                        let mut batch = vec![first];
                        while batch.len() < 40 {
                            match rx.try_recv() {
                                Ok(p) => batch.push(p),
                                Err(_) => break,
                            }
                        }
                        if let Err(e) = inspect(&batch, &store, &cache, system) {
                            log::warn!("Executable inspection failed: {e}");
                            *error.lock().unwrap() = Some(e);
                        }
                        let mut p = pending.lock().unwrap();
                        for path in &batch {
                            p.remove(path);
                        }
                    })
                    .ok();
            }
        }
        Binary { path: path.into(), state: "pending".into(), location: location(path, self.system).into(), ..Default::default() }
    }

    pub fn forget_missing(&self, alive: &HashSet<String>) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 2000 {
            cache.retain(|k, _| alive.contains(k));
        }
    }
}

fn inspect(paths: &[String], store: &Store, cache: &Mutex<HashMap<String, Binary>>, system: &'static str) -> Result<(), String> {
    let meta: HashMap<&String, Option<std::fs::Metadata>> = paths.iter().map(|p| (p, std::fs::metadata(p).ok())).collect();
    let present: Vec<String> = paths.iter().filter(|p| meta[p].is_some()).cloned().collect();
    let sigs = signatures(&present)?;
    for path in paths {
        let mut b = Binary { path: path.clone(), state: "inspected".into(), location: location(path, system).into(), inspected: Some(now()), ..Default::default() };
        match &meta[path] {
            None => {
                b.state = "unavailable".into();
                b.detail = Some("The executable could not be read for inspection.".into());
            }
            Some(m) => {
                b.size = Some(m.len());
                b.mtime = Some(mtime(m));
                match sha256(path) {
                    Ok(h) => b.sha256 = h,
                    Err(e) => b.detail = Some(e.to_string()),
                }
                if system == "Windows" {
                    match sigs.get(path) {
                        Some(s) => {
                            let status = s["status"].as_str().unwrap_or("UnknownError").to_string();
                            b.signature = Some(match status.as_str() {
                                "Valid" => "valid",
                                "NotSigned" => "unsigned",
                                "HashMismatch" => "tampered",
                                "NotTrusted" => "untrusted",
                                _ => "unknown",
                            }.into());
                            b.signature_status = Some(status);
                            b.publisher = s["subject"].as_str().and_then(publisher);
                            b.os_binary = s["os"].as_bool().unwrap_or(false);
                        }
                        None => b.signature = Some("unknown".into()),
                    }
                }
            }
        }
        b.first_seen = Some(store.put_binary(&b)?);
        cache.lock().unwrap().insert(path.clone(), b);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locations_and_publisher() {
        assert_eq!(location("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe", "Windows"), "staging");
        assert_eq!(location("C:\\Users\\a\\Downloads\\x.exe", "Windows"), "staging");
        assert_eq!(location("C:\\Program Files\\App\\a.exe", "Windows"), "system");
        assert_eq!(location("C:\\Users\\a\\AppData\\Local\\Programs\\code\\Code.exe", "Windows"), "user");
        assert_eq!(location("/dev/shm/x", "Linux"), "memory");
        assert_eq!(location("/usr/bin/curl", "Linux"), "system");
        assert_eq!(location("/tmp/x", "Linux"), "staging");
        assert_eq!(publisher("CN=\"Microsoft Corporation\", O=Microsoft").as_deref(), Some("Microsoft Corporation"));
        assert_eq!(publisher(""), None);
    }
}
