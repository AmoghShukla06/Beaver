//! User-requested native firewall operations, narrowly scoped to Beaver-owned rules.
use crate::intel::now;
use crate::store::Store;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Inbound remote-login services blocked by Remote access lockdown. SSH is omitted: blocking it can lock out servers.
pub const LOCKDOWN_PORTS: &str = "23,3389,5900,5901,5902,5903,5938,5985,5986";

pub fn rule_id(kind: &str, target: &str) -> String {
    Sha256::digest(format!("{kind}:{target}").as_bytes()).iter().take(12).map(|b| format!("{b:02x}")).collect()
}

pub fn validate(kind: &str, target: &str, system: &str) -> Result<String, String> {
    if target.len() > 4096 || target.chars().any(|c| (c as u32) < 32) {
        return Err("Invalid firewall target".into());
    }
    match kind {
        "endpoint" => {
            let addr: IpAddr = target.parse().map_err(|_| "Invalid firewall target".to_string())?;
            if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
                return Err("Loopback, unspecified and multicast addresses cannot be blocked".into());
            }
            Ok(addr.to_string())
        }
        "application" => {
            if system != "Windows" {
                return Err("Linux does not support executable-path rules in nftables. Block selected remote endpoints instead.".into());
            }
            let p = Path::new(target);
            if !p.is_absolute() || !p.is_file() {
                return Err("Select an existing absolute executable path".into());
            }
            Ok(p.canonicalize().map(|c| c.to_string_lossy().trim_start_matches(r"\\?\").to_string()).unwrap_or_else(|_| target.into()))
        }
        "ports" => {
            let mut ports: Vec<u32> = target.split(',').map(|p| p.trim().parse::<u32>()).collect::<Result<_, _>>().map_err(|_| "Ports must be numbers separated by commas".to_string())?;
            ports.sort_unstable();
            ports.dedup();
            if ports.is_empty() || ports.len() > 32 || ports.iter().any(|p| !(1..=65535).contains(p)) {
                return Err("Choose 1-32 ports between 1 and 65535".into());
            }
            Ok(ports.iter().map(u32::to_string).collect::<Vec<_>>().join(","))
        }
        _ => Err("Unsupported rule type".into()),
    }
}

pub fn ps_literal(v: &str) -> String {
    format!("'{}'", v.replace('\'', "''"))
}

pub fn windows_script(kind: &str, target: &str, remove: bool) -> String {
    let id = format!("Beaver-{}", rule_id(kind, target));
    let names = [format!("{id}-In"), format!("{id}-Out")];
    let cleanup = names
        .iter()
        .map(|n| format!("Get-NetFirewallRule -Name {} -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop", ps_literal(n)))
        .collect::<Vec<_>>()
        .join(";");
    if remove {
        return format!("$ErrorActionPreference='Stop';{cleanup}");
    }
    let (option, directions): (String, &[&str]) = if kind == "ports" {
        (format!("-Protocol TCP -LocalPort {target} "), &["Inbound"]) // validated digits and commas only
    } else {
        (format!("{}{} ", if kind == "application" { "-Program " } else { "-RemoteAddress " }, ps_literal(target)), &["Inbound", "Outbound"])
    };
    let adds = names
        .iter()
        .zip(directions)
        .map(|(n, d)| format!("New-NetFirewallRule -Name {0} -DisplayName {0} -Group 'Beaver' -Direction {d} -Action Block -Profile Any {option}-ErrorAction Stop | Out-Null", ps_literal(n)))
        .collect::<Vec<_>>()
        .join(";");
    format!("$ErrorActionPreference='Stop';try {{{cleanup};{adds}}} catch {{{cleanup};exit 1}}")
}

pub fn linux_script(kind: &str, target: &str, remove: bool) -> Result<String, String> {
    if kind != "endpoint" && kind != "ports" {
        return Err("Linux supports endpoint and port rules only".into());
    }
    let table = format!("beaver_{}", rule_id(kind, target));
    if remove {
        return Ok(format!("delete table inet {table}\n"));
    }
    if kind == "ports" {
        let ports = validate("ports", target, "Linux")?.replace(',', ", ");
        return Ok(format!("add table inet {table}\nadd chain inet {table} input {{ type filter hook input priority -10; policy accept; }}\nadd rule inet {table} input iifname != \"lo\" tcp dport {{ {ports} }} drop\n"));
    }
    let addr: IpAddr = target.parse().map_err(|_| "Invalid address".to_string())?;
    let family = if addr.is_ipv6() { "ip6" } else { "ip" };
    Ok(format!("add table inet {table}\nadd chain inet {table} output {{ type filter hook output priority -10; policy accept; }}\nadd chain inet {table} input {{ type filter hook input priority -10; policy accept; }}\nadd rule inet {table} output {family} daddr {addr} drop\nadd rule inet {table} input {family} saddr {addr} drop\n"))
}

// ---- process helpers -----------------------------------------------------------------------------

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= chunk.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// PowerShell -EncodedCommand payload (UTF-16LE, base64) so scripts never pass through a shell parser.
pub fn encode_ps(script: &str) -> String {
    base64(&script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>())
}

/// Run a program without a console window; returns (exit code, stdout, stderr).
pub fn run(args: &[&str], input: Option<&str>, timeout_secs: u64) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new(args[0]);
    cmd.args(&args[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let Some(text) = input {
        child.stdin.take().unwrap().write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    } else {
        drop(child.stdin.take());
    }
    let start = Instant::now();
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            let _ = child.kill();
            return Err("The operation timed out".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok((out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
}

fn which(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(name)).find(|p| p.is_file()).map(|p| p.to_string_lossy().into_owned()))
}

pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

// ---- firewall ------------------------------------------------------------------------------------

pub type Runner = Box<dyn Fn(&[&str], Option<&str>) -> Result<(i32, String, String), String> + Send + Sync>;

pub struct Firewall {
    store: Arc<Store>,
    runner: Runner,
    pub system: String,
    pub boot_time: Box<dyn Fn() -> f64 + Send + Sync>,
}

impl Firewall {
    pub fn new(store: Arc<Store>) -> Firewall {
        Firewall {
            store,
            runner: Box::new(|args, input| run(args, input, 120)),
            system: crate::system().into(),
            boot_time: Box::new(|| sysinfo::System::boot_time() as f64),
        }
    }

    #[cfg(test)]
    pub fn with_runner(store: Arc<Store>, system: &str, runner: Runner) -> Firewall {
        Firewall { store, runner, system: system.into(), boot_time: Box::new(|| 0.0) }
    }

    fn nft(&self) -> bool {
        self.system == "Linux" && which("nft").is_some()
    }

    pub fn capabilities(&self) -> Value {
        let windows = self.system == "Windows";
        json!({ "platform": self.system, "endpoint": windows || self.nft(), "application": windows, "ports": windows || self.nft(),
                "lockdown": LOCKDOWN_PORTS, "elevation": if windows { "Windows UAC" } else { "polkit (pkexec)" },
                "note": "Rules require approval in the operating system. Endpoint blocks affect every application. Linux executable-path blocking is unavailable." })
    }

    /// Recorded rules with live state. nftables rules added at runtime do not survive a reboot.
    pub fn rules(&self) -> Vec<Value> {
        let mut rules = self.store.rules();
        if self.system == "Linux" {
            let booted = (self.boot_time)();
            for r in &mut rules {
                if r["state"] == "applied" && r["verified_at"].as_f64().unwrap_or(0.0) < booted {
                    r["state"] = json!("inactive");
                }
            }
        }
        rules
    }

    fn execute(&self, kind: &str, target: &str, remove: bool) -> Result<(), String> {
        let result = if self.system == "Windows" {
            let encoded = encode_ps(&windows_script(kind, target, remove));
            let wrapper = format!("$p=Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',{});exit $p.ExitCode", ps_literal(&encoded));
            (self.runner)(&["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", &wrapper], None)?
        } else if self.system == "Linux" {
            let nft = which("nft").ok_or("Install nftables to manage endpoint blocks")?;
            let script = linux_script(kind, target, remove)?;
            if is_root() {
                (self.runner)(&[&nft, "-f", "-"], Some(&script))?
            } else {
                let pkexec = which("pkexec").ok_or("Install polkit (pkexec) for per-action authorization")?;
                (self.runner)(&[&pkexec, &nft, "-f", "-"], Some(&script))?
            }
        } else {
            return Err("Unsupported operating system".into());
        };
        if result.0 != 0 {
            let tail: String = result.2.chars().rev().take(500).collect::<String>().chars().rev().collect();
            return Err(format!("The operating system did not apply the rule. Authorization may have been cancelled. {tail}"));
        }
        Ok(())
    }

    /// Names of Beaver rules present in the OS firewall, or None when they cannot be read unprivileged.
    fn present(&self) -> Option<HashSet<String>> {
        if self.system == "Windows" {
            let script = "@(Get-NetFirewallRule -Group 'Beaver' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) | ConvertTo-Json -Compress";
            let out = (self.runner)(&["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], None).ok()?;
            if out.0 != 0 {
                return None;
            }
            let v: Value = serde_json::from_str(if out.1.trim().is_empty() { "[]" } else { &out.1 }).ok()?;
            return Some(match v {
                Value::String(s) => [s].into(),
                Value::Array(a) => a.into_iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                _ => HashSet::new(),
            });
        }
        if self.system == "Linux" && is_root() {
            let out = (self.runner)(&[&which("nft")?, "list", "tables"], None).ok()?;
            return (out.0 == 0).then(|| out.1.lines().filter_map(|l| l.split_whitespace().last().map(String::from)).collect());
        }
        None
    }

    /// Reconcile recorded rules with the OS. Read-only: never re-applies or removes anything.
    pub fn verify(&self) -> Value {
        let Some(present) = self.present() else {
            return json!({ "verified": false, "rules": self.rules(), "note": "Rule state cannot be read without elevation on this system." });
        };
        let now = now();
        for mut rule in self.store.rules() {
            if rule["state"] != "applied" && rule["state"] != "missing" {
                continue;
            }
            let id = rule["id"].as_str().unwrap_or("");
            let ident = if self.system == "Windows" { format!("Beaver-{id}-In") } else { format!("beaver_{id}") };
            if present.contains(&ident) {
                rule["state"] = json!("applied");
                rule["verified_at"] = json!(now);
            } else {
                rule["state"] = json!("missing");
            }
            let _ = self.store.put_rule(&rule);
        }
        json!({ "verified": true, "rules": self.rules() })
    }

    pub fn apply(&self, kind: &str, target: &str) -> Result<Value, String> {
        let target = validate(kind, target, &self.system)?;
        let id = rule_id(kind, &target);
        if let Some(existing) = self.rules().into_iter().find(|r| r["id"] == id.as_str() && r["state"] == "applied") {
            return Ok(existing);
        }
        let pending = json!({ "id": id, "kind": kind, "target": target, "created": now(), "state": "pending", "verified_at": null });
        self.store.put_rule(&pending)?; // journal before OS mutation; a crash leaves an explicitly unverified rule
        if let Err(e) = self.execute(kind, &target, false) {
            let mut failed = pending.clone();
            failed["state"] = json!("unverified");
            self.store.put_rule(&failed)?;
            return Err(e);
        }
        let mut done = pending;
        done["state"] = json!("applied");
        done["verified_at"] = json!(now());
        self.store.put_rule(&done)?;
        Ok(done)
    }

    pub fn remove(&self, id: &str) -> Result<Value, String> {
        let rule = self.store.rules().into_iter().find(|r| r["id"] == id).ok_or("Unknown Beaver rule")?;
        self.execute(rule["kind"].as_str().unwrap_or(""), rule["target"].as_str().unwrap_or(""), true)?;
        self.store.delete_rule(id)?;
        Ok(json!({ "removed": id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::temp;
    use std::sync::Mutex;

    #[test]
    fn rule_ids_match_the_python_service() {
        // sha256("endpoint:1.1.1.1")[:24], so rules created by earlier versions keep their OS names.
        assert_eq!(rule_id("endpoint", "1.1.1.1"), "67006d841f9894c47df6bfde");
        assert_eq!(rule_id("ports", LOCKDOWN_PORTS), "1b764b44ec457ffedcb714f8");
    }

    #[test]
    fn validation_rejects_injection_and_dangerous_targets() {
        for t in ["1.1.1.1; reboot", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "1.1.1.1\n"] {
            assert!(validate("endpoint", t, "Windows").is_err(), "{t}");
        }
        assert!(validate("application", "/bin/sh", "Linux").is_err());
        for p in ["3389;calc", "0", "70000", ""] {
            assert!(validate("ports", p, "Windows").is_err());
        }
        assert_eq!(validate("ports", "5900, 3389,3389", "Windows").unwrap(), "3389,5900");
    }

    #[test]
    fn scripts() {
        assert_eq!(ps_literal("C:\\it's\\app.exe"), "'C:\\it''s\\app.exe'");
        let s = windows_script("endpoint", "1.1.1.1", false);
        assert!(s.contains("-Action Block") && s.contains("-Direction Inbound") && s.contains("-Direction Outbound") && s.contains("catch"));
        let s = windows_script("ports", LOCKDOWN_PORTS, false);
        assert!(s.contains("-LocalPort 23,3389") && !s.contains("Outbound"));
        let n = linux_script("ports", "3389,5900", false).unwrap();
        assert!(n.contains("tcp dport { 3389, 5900 } drop") && !n.contains("output"));
        assert!(linux_script("endpoint", "2606:4700:4700::1111", false).unwrap().contains("ip6 daddr"));
        assert_eq!(encode_ps("ab"), "YQBiAA==");
    }

    #[test]
    fn apply_failure_verify_and_reboot() {
        let (store, dir) = temp();
        let store = Arc::new(store);
        let fw = Firewall::with_runner(store.clone(), "Windows", Box::new(|a, _| Ok((if a[4].contains("Start-Process") { 1 } else { 0 }, String::new(), "cancelled".into()))));
        assert!(fw.apply("endpoint", "1.1.1.1").is_err());
        assert_eq!(store.rules()[0]["state"], "unverified");
        let present = format!("[\"Beaver-{}-In\"]", rule_id("endpoint", "1.1.1.1"));
        let fw = Firewall::with_runner(store.clone(), "Windows", Box::new(move |a, _| Ok((0, if a[4].contains("Get-NetFirewallRule -Group") { present.clone() } else { String::new() }, String::new()))));
        fw.apply("endpoint", "1.1.1.1").unwrap();
        fw.apply("endpoint", "2.2.2.2").unwrap();
        let states: Vec<(String, String)> = fw.verify()["rules"].as_array().unwrap().iter().map(|r| (r["target"].as_str().unwrap().into(), r["state"].as_str().unwrap().into())).collect();
        assert!(states.contains(&("1.1.1.1".into(), "applied".into())) && states.contains(&("2.2.2.2".into(), "missing".into())));
        assert!(fw.remove("foreign").is_err());

        let calls = Arc::new(Mutex::new(0));
        let c = calls.clone();
        let mut fw = Firewall::with_runner(store.clone(), "Linux", Box::new(move |_, _| {
            *c.lock().unwrap() += 1;
            Ok((0, String::new(), String::new()))
        }));
        let booted = now() + 100.0;
        fw.boot_time = Box::new(move || booted);
        store.put_rule(&json!({"id": "x", "kind": "endpoint", "target": "3.3.3.3", "state": "applied", "verified_at": now()})).unwrap();
        assert!(fw.rules().iter().any(|r| r["id"] == "x" && r["state"] == "inactive"));
        drop(fw);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Real nftables block/unblock. Run ONLY in a disposable namespace: scripts/test-linux-firewall.sh.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn native_nft_blocks_and_unblocks() {
        use std::net::{TcpListener, TcpStream};
        use std::process::Command;
        // Fail closed before any mutation unless we are in a different network namespace from the caller.
        let host = std::env::var("BEAVER_HOST_NETNS").expect("run through scripts/test-linux-firewall.sh");
        assert_ne!(std::fs::read_link("/proc/self/ns/net").unwrap().to_string_lossy(), host, "refusing to touch the host firewall");
        let sh = |c: &str| assert!(Command::new("sh").args(["-c", c]).status().unwrap().success(), "{c}");
        sh("ip link set lo up && ip addr add 192.0.2.1/32 dev lo && nft add table inet beaver_unrelated_test");
        let server = TcpListener::bind("192.0.2.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let connects = || TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)).is_ok();
        let (store, dir) = temp();
        let fw = Firewall::new(Arc::new(store));
        assert!(connects(), "baseline connection failed");
        let rule = fw.apply("endpoint", "192.0.2.1").unwrap();
        assert!(!connects(), "nft rule did not block the endpoint");
        fw.remove(rule["id"].as_str().unwrap()).unwrap();
        assert!(connects(), "connection did not recover after removal");
        sh("nft list table inet beaver_unrelated_test >/dev/null");
        drop(fw);
        let _ = std::fs::remove_dir_all(dir);
    }
}
