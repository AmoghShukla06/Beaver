//! Transparent, deterministic rules, not malware verdicts. Geography never contributes to risk.
//!
//! Threat-intelligence evidence is never suppressed by an allowlist. Behavioral evidence is suppressed by an
//! application allowlist and reduced by a verified publisher signature. Remote-access evidence is not reduced
//! by a signature, because the tools abused in scams are legitimately signed. See docs/DETECTION.md.
use crate::binaries::location;
use crate::intel::{Hit, Intelligence};
use crate::model::{Binary, Conn, Evidence, Risk};
use crate::net::public;
use std::collections::{BTreeMap, HashMap, HashSet};

pub trait Matcher {
    fn match_ip(&self, ip: &str) -> Vec<Hit>;
    fn match_domain(&self, domain: Option<&str>) -> Vec<Hit>;
    fn fresh(&self) -> bool;
}
impl Matcher for Intelligence {
    fn match_ip(&self, ip: &str) -> Vec<Hit> {
        Intelligence::match_ip(self, ip)
    }
    fn match_domain(&self, domain: Option<&str>) -> Vec<Hit> {
        Intelligence::match_domain(self, domain)
    }
    fn fresh(&self) -> bool {
        Intelligence::fresh(self)
    }
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).replace('\\', "/").to_lowercase().trim_end_matches('/').to_string()
}

/// Windows binaries malware commonly impersonates, and the only folders they ship from.
fn protected_dirs(name: &str) -> Option<Vec<String>> {
    let root = system_root();
    let (sys32, wow64) = (format!("{root}/system32"), format!("{root}/syswow64"));
    match name {
        "lsass.exe" | "csrss.exe" | "smss.exe" | "wininit.exe" | "winlogon.exe" | "services.exe" | "lsm.exe" | "spoolsv.exe"
        | "searchindexer.exe" | "fontdrvhost.exe" => Some(vec![sys32]),
        "svchost.exe" | "taskhostw.exe" | "dllhost.exe" | "conhost.exe" | "rundll32.exe" | "regsvr32.exe" | "taskmgr.exe"
        | "wmiprvse.exe" | "sihost.exe" => Some(vec![sys32, wow64]),
        "explorer.exe" => Some(vec![root, wow64]),
        _ => None,
    }
}
pub fn is_protected(name: &str) -> bool {
    protected_dirs(&name.to_lowercase()).is_some()
}

const LINUX_KERNEL_NAMES: [&str; 7] = ["kworker", "kthreadd", "ksoftirqd", "migration", "rcu_", "kswapd", "watchdog"];

fn lolbin(name: &str) -> Option<i32> {
    Some(match name {
        "mshta.exe" | "regsvr32.exe" | "certutil.exe" | "installutil.exe" | "msxsl.exe" | "cmstp.exe" => 35,
        "bitsadmin.exe" | "msbuild.exe" | "wscript.exe" | "cscript.exe" | "rundll32.exe" | "regasm.exe" | "regsvcs.exe" => 30,
        "powershell.exe" | "pwsh.exe" => 15,
        _ => return None,
    })
}

fn rat_port(port: u16) -> Option<&'static str> {
    Some(match port {
        4444 => "Metasploit default",
        1604 => "DarkComet default",
        4782 => "Quasar RAT default",
        5552 => "njRAT default",
        6606 | 7707 | 8808 => "AsyncRAT default",
        1337 | 31337 => "common backdoor",
        6667..=6669 => "IRC (legacy botnet C2)",
        _ => return None,
    })
}

const OFFICE: [&str; 12] = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
                            "acrord32.exe", "acrobat.exe", "wordpad.exe", "hwp.exe"];
const TOR_PORTS: [u16; 5] = [9001, 9030, 9050, 9051, 9150];
const QUIET_PORTS: [u16; 4] = [53, 123, 5353, 1900];

/// Remote-control software: legitimate support tools that are also the primary instrument of tech-support scams.
const REMOTE_TOOLS: [(&str, &str); 43] = [
    ("anydesk", "AnyDesk"), ("teamviewer", "TeamViewer"), ("teamviewer_service", "TeamViewer"), ("tv_w32", "TeamViewer"),
    ("tv_x64", "TeamViewer"), ("rustdesk", "RustDesk"), ("screenconnect.clientservice", "ConnectWise ScreenConnect"),
    ("screenconnect.windowsclient", "ConnectWise ScreenConnect"), ("srservice", "Splashtop"), ("strwinclt", "Splashtop"),
    ("tvnserver", "TightVNC"), ("winvnc", "UltraVNC"), ("vncserver", "VNC server"), ("vncserver-x11", "RealVNC"),
    ("x11vnc", "x11vnc"), ("x0vncserver", "TigerVNC"), ("ateraagent", "Atera"), ("client32", "NetSupport Manager"),
    ("rutserv", "Remote Utilities"), ("rfusclient", "Remote Utilities"), ("aa_v3", "Ammyy Admin"), ("ammyy_admin", "Ammyy Admin"),
    ("supremo", "Supremo"), ("supremoservice", "Supremo"), ("lmiguardian", "LogMeIn"), ("logmein", "LogMeIn"),
    ("remotepcservice", "RemotePC"), ("remoting_host", "Chrome Remote Desktop"), ("rserver3", "Radmin"), ("dwagent", "DWService"),
    ("getscreen", "Getscreen.me"), ("meshagent", "MeshCentral"), ("quickassist", "Windows Quick Assist"),
    ("msra", "Windows Remote Assistance"), ("ngrok", "ngrok tunnel"), ("ultraviewer", "UltraViewer"),
    ("ultraviewer_service", "UltraViewer"), ("zohoassist", "Zoho Assist"), ("aeroadmin", "AeroAdmin"), ("romserver", "LiteManager"),
    ("simplehelp", "SimpleHelp"), ("iperiusremote", "Iperius Remote"), ("hoptodesk", "HopToDesk"),
];

fn remote_port_name(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => "SSH",
        23 => "Telnet",
        3389 => "Remote Desktop (RDP)",
        5900..=5903 => "VNC",
        5938 => "TeamViewer",
        5985 | 5986 => "WinRM",
        7070 => "AnyDesk",
        _ => return None,
    })
}
fn inbound_sensitive(port: u16) -> Option<&'static str> {
    remote_port_name(port).or(match port {
        445 => Some("SMB file sharing"),
        135 => Some("Windows RPC"),
        139 => Some("NetBIOS"),
        _ => None,
    })
}

const SHELLS: [&str; 11] = ["cmd.exe", "bash", "sh", "dash", "zsh", "ksh", "fish", "ash", "busybox", "bash.exe", "sh.exe"];
const NET_TOOLS: [&str; 10] = ["nc", "ncat", "netcat", "socat", "nc.exe", "ncat.exe", "nc64.exe", "socat.exe", "telnet", "telnet.exe"];
const BROWSERS: [&str; 19] = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "chrome",
                              "chromium", "firefox", "firefox-bin", "brave", "opera", "vivaldi-bin", "msedge", "librewolf", "waterfox",
                              "arc.exe", "zen.exe"];
const EXFIL_DOMAINS: [(&str, &str, i32); 17] = [
    ("api.telegram.org", "Telegram Bot API", 35), ("transfer.sh", "transfer.sh file sharing", 25), ("file.io", "file.io file sharing", 25),
    ("gofile.io", "GoFile file sharing", 25), ("anonfiles.com", "AnonFiles", 25), ("bashupload.com", "bashupload", 25),
    ("temp.sh", "temp.sh file sharing", 25), ("catbox.moe", "Catbox file sharing", 25), ("0x0.st", "0x0.st file sharing", 25),
    ("uguu.se", "Uguu file sharing", 25), ("filebin.net", "Filebin", 25), ("pastebin.com", "Pastebin", 20), ("paste.ee", "Paste.ee", 20),
    ("webhook.site", "webhook.site", 25), ("ngrok.io", "ngrok tunnel", 20), ("ngrok-free.app", "ngrok tunnel", 20),
    ("trycloudflare.com", "Cloudflare quick tunnel", 20),
];
const MESSENGERS: [&str; 5] = ["telegram", "ayugram", "kotatogram", "unigram", "64gram"];

pub fn remote_tool(name: &str) -> Option<&'static str> {
    let key = name.to_lowercase();
    let key = key.strip_suffix(".exe").unwrap_or(&key);
    REMOTE_TOOLS
        .iter()
        .find(|(k, _)| *k == key)
        .or_else(|| REMOTE_TOOLS.iter().find(|(k, _)| k.len() > 5 && key.starts_with(k)))
        .map(|(_, v)| *v)
}

fn exfil_channel(domain: Option<&str>) -> Option<(&'static str, i32)> {
    let d = domain?.to_lowercase();
    EXFIL_DOMAINS.iter().find(|(k, _, _)| d == *k || d.ends_with(&format!(".{k}"))).map(|(_, n, p)| (*n, *p))
}

/// Mean interval when new connections start on a steady schedule (low jitter), else None.
pub fn beacon(starts: &[f64]) -> Option<f64> {
    if starts.len() < 6 {
        return None;
    }
    let gaps: Vec<f64> = starts.windows(2).map(|w| w[1] - w[0]).collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if !(20.0..=3600.0).contains(&mean) {
        return None;
    }
    let deviation = (gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64).sqrt();
    (deviation <= 3.0f64.max(0.15 * mean)).then_some(mean)
}

fn masquerade(name: &str, path: Option<&str>, system: &str) -> Option<String> {
    let path = path?;
    let n = name.to_lowercase();
    let p = path.replace('\\', "/").to_lowercase();
    let folder = p.rsplit_once('/').map(|(f, _)| f).unwrap_or("");
    if system == "Windows" {
        if let Some(dirs) = protected_dirs(&n) {
            if !dirs.iter().any(|d| d == folder) {
                return Some(format!("{name} normally runs only from {}, but this copy runs from {path}.", dirs[0].replace('/', "\\")));
            }
        }
    }
    if system == "Linux" && LINUX_KERNEL_NAMES.iter().any(|k| n.starts_with(k)) {
        return Some(format!("{name} is a kernel-thread name, but this process has a user-space executable at {path}."));
    }
    None
}

#[derive(Default)]
pub struct Context<'a> {
    pub system: &'a str,
    pub binary: Option<&'a Binary>,
    pub listening: Option<&'a HashSet<(String, u16)>>,
    pub beacons: Option<&'a BTreeMap<(String, u16), Vec<f64>>>,
    pub totals: Option<[u64; 2]>,
    pub deleted: bool,
    pub fileless: bool,
    pub parent: Option<&'a str>,
}

fn ev(rule: &str, points: i32, title: impl Into<String>, detail: impl Into<String>, category: &str, technique: Option<&str>) -> Evidence {
    Evidence { rule: rule.into(), points, title: title.into(), detail: detail.into(), category: category.into(), technique: technique.map(Into::into), ..Default::default() }
}
fn with_endpoint(mut e: Evidence, ip: &str) -> Evidence {
    e.endpoint = Some(ip.to_string());
    e
}

pub fn assess(name: &str, path: Option<&str>, connections: &[&Conn], intel: &dyn Matcher, observations: u32, allowlisted: bool,
              allowed_endpoints: &HashSet<String>, ctx: &Context) -> Risk {
    let system = if ctx.system.is_empty() { std::env::consts::OS } else { ctx.system };
    let empty = HashSet::new();
    let listening = ctx.listening.unwrap_or(&empty);
    let is_listening = |c: &Conn| listening.contains(&(c.protocol.clone(), c.local_port));
    let lname = name.to_lowercase();
    let mut evidence: Vec<Evidence> = vec![];

    // 1. Threat intelligence: strongest hit per endpoint; additional malicious endpoints add a little.
    let mut per_endpoint: Vec<(String, i32, Hit, bool, Vec<Hit>)> = vec![];
    let mut seen = HashSet::new();
    for c in connections {
        let Some(ip) = c.remote_ip.as_deref() else { continue };
        if !seen.insert(ip.to_string()) || !public(ip) {
            continue;
        }
        let mut hits = intel.match_ip(ip);
        hits.extend(intel.match_domain(c.domain.as_deref()));
        let Some(best) = hits.iter().max_by_key(|h| h.points).cloned() else { continue };
        let inbound = is_listening(c);
        let points = if !inbound || best.points >= 80 { best.points } else { best.points / 4 };
        per_endpoint.push((ip.to_string(), points, best, inbound, hits));
    }
    per_endpoint.sort_by_key(|e| -e.1);
    let intel_score = per_endpoint.first().map(|e| e.1 + (5 * (per_endpoint.len() as i32 - 1)).min(15)).unwrap_or(0);
    for (ip, points, best, inbound, hits) in per_endpoint.iter().take(5) {
        let target = &best.value;
        let mut lists: Vec<&str> = hits.iter().map(|h| h.name).collect();
        lists.sort();
        lists.dedup();
        let rule = if target != ip { "intel-domain" } else if best.feed == "feodo" { "known-c2" } else { "threat-intel" };
        let mut e = ev(rule, *points,
            format!("{}{}", best.category, if *inbound && *points < best.points { " (inbound)" } else { "" }),
            format!("{target}{} is listed by {}. {}A list match is evidence for investigation, not proof that this application is malicious.",
                    if target != ip { format!(" ({ip})") } else { String::new() }, lists.join(", "),
                    if *inbound { "The remote host connected to a listening port, which usually indicates scanning rather than compromise. " } else { "" }),
            "intel", Some("T1071"));
        e.source = Some(best.source.to_string());
        e.endpoint = Some(ip.clone());
        e.feeds = Some(hits.iter().map(|h| h.feed.to_string()).collect());
        evidence.push(e);
    }

    let (mut behavior, mut trust, mut exposure) = (0, 0, 0);
    let product = remote_tool(name);
    if !allowlisted {
        // 2. Remote control and data theft.
        let public_live: Vec<&&Conn> = connections
            .iter()
            .filter(|c| c.remote_ip.as_deref().is_some_and(public) && matches!(c.status.as_str(), "ESTABLISHED" | "OBSERVED" | "SYN_SENT"))
            .collect();
        if let (Some(product), Some(first)) = (product, public_live.first()) {
            exposure += 30;
            evidence.push(with_endpoint(ev("remote-access-tool", 30, format!("Remote-control software is connected ({product})"),
                format!("{product} lets another person see and control this computer. If you did not start it yourself, especially after an unexpected call, pop-up or message asking you to install it, end the session now and change your passwords. If you use {product} intentionally, allowlist it."),
                "remote", Some("T1219")), first.remote_ip.as_deref().unwrap()));
        }
        if let Some(c) = public_live.iter().find(|c| c.protocol == "TCP" && is_listening(c) && inbound_sensitive(c.local_port).is_some()) {
            let service = inbound_sensitive(c.local_port).unwrap();
            let ip = c.remote_ip.as_deref().unwrap();
            exposure += 80;
            evidence.push(with_endpoint(ev("inbound-remote-login", 80, format!("{service} session from the internet"),
                format!("{ip} is connected to the {service} service on port {}. Unless you expected a remote login from that address, someone outside your network may be accessing this computer. Disconnect it and block the port from Firewall.", c.local_port),
                "remote", Some("T1021")), ip));
        }
        let mut exposed: Vec<u16> = connections
            .iter()
            .filter(|c| c.status == "LISTEN" && remote_port_name(c.local_port).is_some() && !c.local_ip.starts_with("127.") && !c.local_ip.starts_with("::1"))
            .map(|c| c.local_port)
            .collect();
        exposed.sort_unstable();
        exposed.dedup();
        if !exposed.is_empty() {
            exposure += 15;
            let list: Vec<String> = exposed.iter().map(|p| format!("{p} ({})", remote_port_name(*p).unwrap())).collect();
            let mut e = ev("exposed-remote-service", 15, "Remote-access service is reachable from the network",
                format!("Listening on {}. Attackers scan for these services. Use Remote access lockdown in Firewall if you do not need incoming remote logins.", list.join(", ")),
                "remote", Some("T1133"));
            e.ports = Some(exposed);
            evidence.push(e);
        }
        if let Some(c) = public_live.iter().find(|c| !is_listening(c)) {
            let (ip, port) = (c.remote_ip.as_deref().unwrap(), c.remote_port.unwrap_or(0));
            if SHELLS.contains(&lname.as_str()) {
                exposure += 70;
                evidence.push(with_endpoint(ev("reverse-shell", 70, "Command shell connected directly to the internet",
                    format!("{name} holds a network connection to {ip}:{port}. Shells do not normally open sockets themselves; this is the signature of a reverse shell that gives an attacker interactive control."),
                    "remote", Some("T1059")), ip));
            } else if NET_TOOLS.contains(&lname.as_str()) {
                exposure += 40;
                evidence.push(with_endpoint(ev("raw-network-tool", 40, format!("{name} is connected to the internet"),
                    format!("{name} can pipe a command shell over the network. Administrators also use it for testing."), "remote", Some("T1059")), ip));
            }
        }
        if !BROWSERS.contains(&lname.as_str()) {
            for c in connections {
                if let Some((channel, points)) = exfil_channel(c.domain.as_deref()) {
                    if channel.starts_with("Telegram") && MESSENGERS.iter().any(|m| lname.starts_with(m)) {
                        continue;
                    }
                    behavior += points;
                    evidence.push(with_endpoint(ev("exfil-channel", points, format!("Sends data to {channel}"),
                        format!("{} ({}) is a service infostealers use to upload stolen passwords, cookies and files. Some bots, scripts and backup tools use it legitimately.",
                                c.domain.as_deref().unwrap_or(""), c.remote_ip.as_deref().unwrap_or("")),
                        "exfil", Some("T1567")), c.remote_ip.as_deref().unwrap_or("")));
                    break;
                }
            }
        }

        // 3. Identity and integrity.
        if let Some(detail) = masquerade(name, path, system) {
            behavior += 60;
            let title = if system == "Windows" { "Impersonates a Windows system process" } else { "Impersonates a kernel thread" };
            evidence.push(ev("masquerading", 60, title, format!("{detail} Malware commonly copies trusted process names to hide."), "identity", Some("T1036.005")));
        }
        if ctx.fileless {
            behavior += 60;
            evidence.push(ev("fileless", 60, "Runs from an in-memory file",
                "The executable is an anonymous memory file (memfd), a technique used to run code without writing it to disk. Some sandboxes and JIT runtimes also do this.",
                "identity", Some("T1620")));
        } else if ctx.deleted {
            behavior += 45;
            evidence.push(ev("deleted-executable", 45, "Executable was deleted while running",
                "The program file no longer exists on disk. Malware deletes itself to hinder analysis; package upgrades can also cause this briefly.",
                "identity", Some("T1070.004")));
        }
        let binary = ctx.binary;
        match binary.and_then(|b| b.signature.as_deref()) {
            Some("tampered") => {
                behavior += 50;
                evidence.push(ev("tampered-signature", 50, "Digital signature does not match the file",
                    "The file was modified after it was signed. This indicates tampering or corruption.", "identity", Some("T1554")));
            }
            Some("untrusted") => {
                behavior += 20;
                evidence.push(ev("untrusted-signature", 20, "Signed by an untrusted certificate",
                    "The signing certificate does not chain to a trusted root. Self-signed developer builds also look like this.", "identity", Some("T1553.002")));
            }
            Some("unsigned") => {
                behavior += 10;
                evidence.push(ev("unsigned", 10, "No digital signature",
                    "The executable is not Authenticode-signed. This is common for open-source, scripting and developer tools.", "identity", None));
            }
            Some("valid") => {
                if let Some(publisher) = binary.and_then(|b| b.publisher.as_deref()) {
                    trust = 10;
                    evidence.push(ev("verified-publisher", -10, format!("Verified publisher: {publisher}"),
                        "The Authenticode signature is valid. Signed software can still be abused, so this only reduces behavioral signals.", "trust", None));
                }
            }
            _ => {}
        }
        let where_ = binary.map(|b| b.location.clone()).filter(|l| !l.is_empty()).or_else(|| path.map(|p| location(p, system).to_string()));
        match where_.as_deref() {
            Some("memory") => {
                behavior += 40;
                evidence.push(ev("shared-memory-executable", 40, "Runs from shared memory (/dev/shm)",
                    "Executables in /dev/shm leave no persistent file. Legitimate software rarely does this.", "identity", Some("T1620")));
            }
            Some("staging") => {
                behavior += 20;
                evidence.push(ev("temporary-executable", 20, "Runs from a temporary or download folder",
                    "A network-active executable is in temporary or download storage. Installers and portable apps also run from these locations.", "identity", Some("T1204.002")));
            }
            _ => {}
        }

        // 4. Network behavior on non-allowlisted, public endpoints.
        let outbound: Vec<&&Conn> = connections
            .iter()
            .filter(|c| c.remote_ip.as_ref().is_some_and(|ip| !allowed_endpoints.contains(ip)) && !is_listening(c))
            .collect();
        let mut ports: HashMap<&str, HashSet<Option<u16>>> = HashMap::new();
        for c in connections {
            if let Some(ip) = c.remote_ip.as_deref().filter(|ip| !allowed_endpoints.contains(*ip)) {
                ports.entry(ip).or_default().insert(c.remote_port);
            }
        }
        if ports.values().any(|p| p.len() >= 30) {
            behavior += 35;
            evidence.push(ev("port-fanout", 35, "Unusual port fan-out",
                "At least 30 distinct ports on one endpoint are observable at once. Scanners and development tools can legitimately do this.", "behavior", Some("T1046")));
        }
        if ports.len() >= 100 {
            behavior += 20;
            evidence.push(ev("endpoint-fanout", 20, "Many simultaneous destinations",
                "At least 100 distinct remote IPs are observable. Browsers, peer-to-peer clients and update tools can legitimately do this.", "behavior", None));
        }
        let public_out: Vec<&&&Conn> = outbound.iter().filter(|c| public(c.remote_ip.as_deref().unwrap())).collect();
        if let (Some(points), Some(first)) = (lolbin(&lname), public_out.first()) {
            behavior += points;
            let ip = first.remote_ip.as_deref().unwrap();
            evidence.push(with_endpoint(ev("lolbin-network", points, format!("{name} is contacting the internet"),
                format!("{name} is a built-in Windows tool that attackers use to download or run remote code. Observed endpoint: {ip}:{}. Administrators and scripts also use it.", first.remote_port.unwrap_or(0)),
                "behavior", Some(if points >= 30 { "T1218" } else { "T1059.001" })), ip));
        }
        let parent = ctx.parent.unwrap_or("").to_lowercase();
        let script_host = matches!(lname.as_str(), "mshta.exe" | "wscript.exe" | "cscript.exe");
        if OFFICE.contains(&parent.as_str()) && (lolbin(&lname).is_some() || script_host) && !public_out.is_empty() {
            behavior += 40;
            evidence.push(ev("document-spawned", 40, format!("Started by {} and contacting the internet", ctx.parent.unwrap_or("")),
                format!("{name} was launched by a document application. Malicious documents use this to download a second stage. Some macros and add-ins do this legitimately."),
                "behavior", Some("T1204.002")));
        }
        if let Some(c) = public_out.iter().find(|c| c.remote_port.and_then(rat_port).is_some()) {
            let (ip, port) = (c.remote_ip.as_deref().unwrap(), c.remote_port.unwrap());
            behavior += 20;
            evidence.push(with_endpoint(ev("suspicious-port", 20, "Connects to a port associated with remote-access malware",
                format!("{ip}:{port} uses the {} port. Some games and services reuse these ports.", rat_port(port).unwrap()), "behavior", Some("T1571")), ip));
        }
        if let Some(c) = public_out.iter().find(|c| c.remote_port.is_some_and(|p| TOR_PORTS.contains(&p))) {
            if !lname.starts_with("tor") && !lname.starts_with("firefox") {
                let ip = c.remote_ip.as_deref().unwrap();
                behavior += 15;
                evidence.push(with_endpoint(ev("tor-port", 15, "Connects to a Tor relay port",
                    format!("{ip}:{} is a default Tor port. Malware uses Tor to hide its command server; privacy tools use it legitimately.", c.remote_port.unwrap()),
                    "behavior", Some("T1090.003")), ip));
            }
        }
        if let Some(beacons) = ctx.beacons {
            let steady = beacons.iter().find_map(|((ip, port), starts)| {
                (!allowed_endpoints.contains(ip) && !QUIET_PORTS.contains(port) && public(ip)).then(|| beacon(starts).map(|i| (ip, port, i))).flatten()
            });
            if let Some((ip, port, interval)) = steady {
                behavior += 25;
                evidence.push(with_endpoint(ev("beaconing", 25, "Contacts a server on a fixed schedule",
                    format!("New connections to {ip}:{port} start every {interval:.0} seconds with very little variation. Malware beacons to command servers this way; update checks and telemetry can too."),
                    "behavior", Some("T1071")), ip));
            }
        }
        if let Some([up, down]) = ctx.totals {
            if up > 200 * 1024 * 1024 && up > 8 * (down + 1) {
                behavior += 20;
                evidence.push(ev("upload-volume", 20, "Uploads far more than it downloads",
                    format!("{} MB sent versus {} MB received this session. Backups, cloud sync and video calls also upload heavily.", up / 1_048_576, down / 1_048_576),
                    "behavior", Some("T1041")));
            }
        }
    }

    let score = (intel_score + (behavior - trust).max(0) + exposure).min(100);
    let level = if score >= 80 {
        "High"
    } else if score >= 30 {
        "Medium"
    } else if path.is_none() || observations < 3 || !intel.fresh() {
        "Unknown"
    } else {
        "Low"
    };
    let mut reason = match level {
        "High" => "Strong threat evidence needs investigation.",
        "Medium" => "Behavior deserves review; legitimate explanations are possible.",
        "Low" => "No strong signals in the observable activity. This is not a safety guarantee.",
        _ => "Insufficient identity, observation time, or fresh threat intelligence to assess confidently.",
    }
    .to_string();
    if level == "High" || level == "Medium" {
        if let Some(strongest) = evidence.iter().filter(|e| e.points > 0).max_by_key(|e| e.points) {
            reason += &format!(" Strongest signal: {}.", strongest.title);
        }
    }
    Risk {
        level: level.into(),
        score: (level != "Unknown").then_some(score),
        evidence,
        reason,
        allowlisted,
        intel_score,
        behavior_score: (behavior - trust).max(0) + exposure,
        remote_tool: product.map(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        ips: HashMap<String, (i32, &'static str)>,
        domains: HashMap<String, i32>,
        fresh: bool,
    }
    fn fake() -> Fake {
        Fake { ips: HashMap::new(), domains: HashMap::new(), fresh: true }
    }
    fn mk(feed: &'static str, value: &str, points: i32) -> Hit {
        Hit { feed, name: feed, category: "Fixture category", points, source: "https://example.invalid", malware: "x", value: value.into() }
    }
    impl Matcher for Fake {
        fn match_ip(&self, ip: &str) -> Vec<Hit> {
            self.ips.get(ip).filter(|_| self.fresh).map(|(p, f)| vec![mk(f, ip, *p)]).unwrap_or_default()
        }
        fn match_domain(&self, d: Option<&str>) -> Vec<Hit> {
            d.and_then(|d| self.domains.get(d).filter(|_| self.fresh).map(|p| vec![mk("threat-domains", d, *p)])).unwrap_or_default()
        }
        fn fresh(&self) -> bool {
            self.fresh
        }
    }

    fn conn(ip: &str, port: u16) -> Conn {
        Conn { id: "c".into(), app_id: "a".into(), pid: Some(1), process_created: None, local_ip: "192.168.1.2".into(), local_port: 50000,
               remote_ip: Some(ip.into()), remote_port: Some(port), protocol: "TCP".into(), status: "ESTABLISHED".into(), source: "OS".into(),
               first_seen: 0.0, last_seen: 0.0, domain: None, geo: None, threat: None }
    }
    fn rules(r: &Risk) -> HashSet<String> {
        r.evidence.iter().map(|e| e.rule.clone()).collect()
    }
    fn run(name: &str, path: Option<&str>, cs: &[Conn], intel: &Fake, ctx: Context) -> Risk {
        let refs: Vec<&Conn> = cs.iter().collect();
        assess(name, path, &refs, intel, 10, false, &HashSet::new(), &ctx)
    }
    fn win<'a>() -> Context<'a> {
        Context { system: "Windows", ..Default::default() }
    }
    fn lin<'a>() -> Context<'a> {
        Context { system: "Linux", ..Default::default() }
    }

    #[test]
    fn unknown_low_and_c2_even_when_allowlisted() {
        let mut f = fake();
        f.fresh = false;
        assert_eq!(run("b", Some("/usr/bin/b"), &[conn("1.1.1.1", 443)], &f, lin()).level, "Unknown");
        let f = fake();
        let low = run("b", Some("/usr/bin/b"), &[conn("1.1.1.1", 443)], &f, lin());
        assert!(low.level == "Low" && low.reason.contains("not a safety guarantee"));
        let mut f = fake();
        f.ips.insert("1.1.1.1".into(), (90, "feodo"));
        let cs = [conn("1.1.1.1", 443)];
        let refs: Vec<&Conn> = cs.iter().collect();
        let allowed: HashSet<String> = ["1.1.1.1".to_string()].into();
        let r = assess("b", Some("/usr/bin/b"), &refs, &f, 3, true, &allowed, &lin());
        assert!(r.level == "High" && r.score == Some(90));
    }

    #[test]
    fn reputation_inbound_discount_and_bounded_multi_hits() {
        let mut f = fake();
        f.ips.insert("1.1.1.1".into(), (45, "et-compromised"));
        assert_eq!(run("b", Some("/usr/bin/b"), &[conn("1.1.1.1", 443)], &f, lin()).level, "Medium");
        let listening: HashSet<(String, u16)> = [("TCP".to_string(), 8080)].into();
        let mut c = conn("1.1.1.1", 443);
        c.local_port = 8080;
        let r = run("b", Some("/usr/bin/b"), &[c], &f, Context { system: "Linux", listening: Some(&listening), ..Default::default() });
        assert!(r.score == Some(11) && r.level == "Low");
        let mut f = fake();
        let cs: Vec<Conn> = (0..10).map(|i| conn(&format!("1.1.1.{i}"), 443)).collect();
        for i in 0..10 {
            f.ips.insert(format!("1.1.1.{i}"), (45, "ipsum"));
        }
        assert_eq!(run("b", Some("/usr/bin/b"), &cs, &f, lin()).intel_score, 60);
    }

    #[test]
    fn masquerade_staging_signature_and_lolbins() {
        let f = fake();
        let fake_svchost = run("svchost.exe", Some("C:\\Users\\Public\\svchost.exe"), &[conn("1.1.1.1", 443)], &f, win());
        assert!(rules(&fake_svchost).contains("masquerading") && fake_svchost.level == "High");
        let real = run("svchost.exe", Some("C:\\Windows\\System32\\svchost.exe"), &[conn("1.1.1.1", 443)], &f, win());
        assert!(!rules(&real).contains("masquerading"));
        let b = Binary { signature: Some("tampered".into()), location: "user".into(), ..Default::default() };
        assert_eq!(run("x.exe", Some("C:\\Tools\\x.exe"), &[conn("1.1.1.1", 443)], &f, Context { system: "Windows", binary: Some(&b), ..Default::default() }).score, Some(50));
        let r = run("mshta.exe", Some("C:\\Windows\\System32\\mshta.exe"), &[conn("1.1.1.1", 443)], &f,
                    Context { system: "Windows", parent: Some("WINWORD.EXE"), ..Default::default() });
        assert!(rules(&r).contains("lolbin-network") && rules(&r).contains("document-spawned") && r.level == "Medium");
        let staging = run("installer.exe", Some("C:\\Users\\T\\AppData\\Local\\Temp\\installer.exe"), &[conn("1.1.1.1", 443)], &f, win());
        assert!(staging.score == Some(20) && staging.level == "Low");
    }

    #[test]
    fn verified_publisher_reduces_behavior_only() {
        let f = fake();
        let b = Binary { signature: Some("valid".into()), publisher: Some("Contoso".into()), location: "system".into(), ..Default::default() };
        let beacons: BTreeMap<(String, u16), Vec<f64>> = [(("1.1.1.1".to_string(), 443), (0..10).map(|i| i as f64 * 30.0).collect())].into();
        let r = run("a.exe", Some("C:\\Program Files\\A\\a.exe"), &[conn("1.1.1.1", 443)], &f,
                    Context { system: "Windows", binary: Some(&b), beacons: Some(&beacons), ..Default::default() });
        assert_eq!(r.score, Some(15));
    }

    #[test]
    fn beacon_timing() {
        assert_eq!(beacon(&[0.0, 30.0, 60.0, 90.0, 120.0, 150.0]), Some(30.0));
        assert!(beacon(&[0.0, 30.0, 61.0, 89.0, 121.0, 150.0]).is_some());
        assert!(beacon(&[0.0, 5.0, 60.0, 61.0, 200.0, 201.0]).is_none() && beacon(&[0.0, 1.0, 2.0, 3.0, 4.0, 5.0]).is_none());
    }

    #[test]
    fn remote_access_inbound_shells_and_exfil() {
        let f = fake();
        let signed = Binary { signature: Some("valid".into()), publisher: Some("AnyDesk Software GmbH".into()), location: "system".into(), ..Default::default() };
        let r = run("AnyDesk.exe", Some("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe"), &[conn("1.1.1.1", 443)], &f,
                    Context { system: "Windows", binary: Some(&signed), ..Default::default() });
        assert!(r.level == "Medium" && r.remote_tool.as_deref() == Some("AnyDesk"));
        assert_eq!(remote_tool("TeamViewer_Service.exe"), Some("TeamViewer"));
        assert_eq!(remote_tool("notepad.exe"), None);

        let listening: HashSet<(String, u16)> = [("TCP".to_string(), 3389)].into();
        let mut listener = conn("0.0.0.0", 0);
        listener.remote_ip = None;
        listener.remote_port = None;
        listener.local_ip = "0.0.0.0".into();
        listener.local_port = 3389;
        listener.status = "LISTEN".into();
        let mut inbound = conn("45.33.32.156", 51515);
        inbound.local_port = 3389;
        let ctx = || Context { system: "Windows", listening: Some(&listening), ..Default::default() };
        let r = run("svchost.exe", Some("C:\\Windows\\System32\\svchost.exe"), &[listener.clone(), inbound], &f, ctx());
        assert!(r.level == "High" && rules(&r).contains("inbound-remote-login"));
        let mut lan = conn("192.168.1.9", 51515);
        lan.local_port = 3389;
        let r = run("svchost.exe", Some("C:\\Windows\\System32\\svchost.exe"), &[listener, lan], &f, ctx());
        assert!(!rules(&r).contains("inbound-remote-login") && rules(&r).contains("exposed-remote-service"));

        let r = run("bash", Some("/usr/bin/bash"), &[conn("1.1.1.1", 4444)], &f, lin());
        assert!(rules(&r).contains("reverse-shell") && rules(&r).contains("suspicious-port") && r.level == "High");

        let mut tg = conn("1.1.1.1", 443);
        tg.domain = Some("api.telegram.org".into());
        let unsigned = Binary { signature: Some("unsigned".into()), location: "staging".into(), ..Default::default() };
        let r = run("free.exe", Some("C:\\Users\\a\\Downloads\\free.exe"), &[tg.clone()], &f, Context { system: "Windows", binary: Some(&unsigned), ..Default::default() });
        assert!(rules(&r).contains("exfil-channel") && r.score == Some(65));
        assert!(!rules(&run("Telegram.exe", Some("C:\\T\\Telegram.exe"), &[tg], &f, win())).contains("exfil-channel"));
    }

    #[test]
    fn linux_fileless_and_ports() {
        let f = fake();
        assert!(rules(&run("x", Some("/memfd:x"), &[conn("1.1.1.1", 443)], &f, Context { system: "Linux", fileless: true, ..Default::default() })).contains("fileless"));
        assert_eq!(run("x", Some("/dev/shm/.x"), &[conn("1.1.1.1", 443)], &f, Context { system: "Linux", deleted: true, ..Default::default() }).level, "High");
        assert!(rules(&run("b", Some("/usr/bin/b"), &[conn("1.1.1.1", 9001)], &f, lin())).contains("tor-port"));
        assert!(!rules(&run("tor", Some("/usr/bin/tor"), &[conn("1.1.1.1", 9001)], &f, lin())).contains("tor-port"));
    }
}
