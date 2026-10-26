//! Real OS socket inventory, sampled independently of the UI.
use crate::binaries::Binaries;
use crate::capture::{Capture, Owner};
use crate::dnscache::DnsCache;
use crate::intel::{now, Geolocation, Intelligence};
use crate::model::{App, Binary, Conn};
use crate::net::public;
use crate::risk::{self, assess, Context};
use crate::store::Store;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const INTERVAL: f64 = 2.0;
const CHECKPOINT: f64 = 30.0;
const CLOSED: [&str; 7] = ["TIME_WAIT", "CLOSE", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"];
/// Active protection only acts on these unambiguous behaviors, and never on OS or validly signed binaries.
const AUTO_RESPONSE: [&str; 8] = ["reverse-shell", "masquerading", "fileless", "tampered-signature", "known-c2", "threat-intel", "intel-domain", "exfil-channel"];

pub type Emit = Arc<dyn Fn(&str, Value) + Send + Sync>;

#[derive(Clone)]
struct Ident {
    id: String,
    name: String,
    path: Option<String>,
    created: Option<f64>,
    parent: Option<String>,
    deleted: bool,
    fileless: bool,
    /// Raw OS start time for cheap PID-reuse checks; None when the process can't be opened.
    raw: Option<u64>,
    checked: Instant,
}

/// Process start time straight from the OS (~microseconds), used to detect PID reuse without
/// re-enumerating every process. None for protected processes that cannot be opened.
fn raw_start(pid: u32) -> Option<u64> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) != 0;
        CloseHandle(h);
        ok.then(|| (created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64)
    }
    #[cfg(not(windows))]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
    }
}

type ConnKey = (String, Option<u32>, Option<u64>, String, String, u16, Option<String>, Option<u16>);

struct Inner {
    sys: System,
    networks: sysinfo::Networks,
    current: HashMap<ConnKey, Conn>,
    identities: HashMap<u32, Ident>,
    observations: HashMap<String, u32>,
    previous_bytes: HashMap<String, [u64; 2]>,
    last_io: Option<(u64, u64)>,
    io_tick: Option<Instant>,
    last_tick: Option<Instant>,
    series: VecDeque<Value>,
    samples: u64,
    last_feed_attempt: f64,
    last_prune: f64,
    last_checkpoint: f64,
    dns_names: HashMap<String, String>,
    last_dns: f64,
    starts: HashMap<(String, String, u16), VecDeque<f64>>,
    summary: Option<Value>,
    on_battery: bool,
    last_power: Option<Instant>,
}

pub struct Monitor {
    pub store: Arc<Store>,
    pub intel: Arc<Intelligence>,
    pub capture: Arc<Capture>,
    geo: Mutex<Geolocation>,
    binaries: Binaries,
    dns: Mutex<DnsCache>,
    emit: Emit,
    inner: Mutex<Inner>,
    state: Mutex<Value>,
    apps: Mutex<Vec<App>>,
    pub visible: AtomicBool,
    error: Mutex<Option<String>>,
    stop: AtomicBool,
    started: f64,
    capture_available: Mutex<Option<bool>>,
    system: &'static str,
}

fn status_name(state: netstat2::TcpState) -> &'static str {
    use netstat2::TcpState::*;
    match state {
        Closed => "CLOSE",
        Listen => "LISTEN",
        SynSent => "SYN_SENT",
        SynReceived => "SYN_RECV",
        Established => "ESTABLISHED",
        FinWait1 => "FIN_WAIT1",
        FinWait2 => "FIN_WAIT2",
        CloseWait => "CLOSE_WAIT",
        Closing => "CLOSING",
        LastAck => "LAST_ACK",
        TimeWait => "TIME_WAIT",
        DeleteTcb => "DELETE_TCB",
        Unknown => "NONE",
    }
}

/// Same identity the Python service used: sha256(normcase(executable))[:24], so history stays attached.
fn app_id(key: &str) -> String {
    Sha256::digest(key.as_bytes()).iter().take(12).map(|b| format!("{b:02x}")).collect()
}
fn normcase(path: &str) -> String {
    if cfg!(windows) {
        path.replace('/', "\\").to_lowercase()
    } else {
        path.to_string()
    }
}

fn uuid() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    for i in 0..2u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i ^ now().to_bits());
        out += &format!("{:016x}", h.finish());
    }
    out
}

fn on_battery() -> bool {
    #[cfg(windows)]
    unsafe {
        let mut s: windows_sys::Win32::System::Power::SYSTEM_POWER_STATUS = std::mem::zeroed();
        windows_sys::Win32::System::Power::GetSystemPowerStatus(&mut s) != 0 && s.ACLineStatus == 0
    }
    #[cfg(not(windows))]
    {
        let Ok(dir) = std::fs::read_dir("/sys/class/power_supply") else { return false };
        let mut has_battery = false;
        for entry in dir.flatten() {
            let p = entry.path();
            let kind = std::fs::read_to_string(p.join("type")).unwrap_or_default();
            if kind.trim() == "Mains" && std::fs::read_to_string(p.join("online")).unwrap_or_default().trim() == "1" {
                return false;
            }
            has_battery |= kind.trim() == "Battery";
        }
        has_battery
    }
}

/// Total bytes (sent, received) across real interfaces. Windows uses the raw interface table, which skips the
/// per-row status queries and excludes NDIS filter rows that would count the same traffic twice.
fn interface_totals(networks: &mut sysinfo::Networks) -> (u64, u64) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2Ex, MibIfTableRaw, MIB_IF_TABLE2};
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2Ex(MibIfTableRaw, &mut table) == 0 && !table.is_null() {
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            let (mut sent, mut recv) = (0u64, 0u64);
            for row in rows {
                let filter = row.InterfaceAndOperStatusFlags._bitfield & 0b10 != 0;
                if row.Type != 24 && !filter {
                    sent += row.OutOctets;
                    recv += row.InOctets;
                }
            }
            FreeMibTable(table as _);
            return (sent, recv);
        }
    }
    networks.refresh(true);
    networks
        .iter()
        .filter(|(name, _)| !name.to_lowercase().starts_with("lo"))
        .fold((0, 0), |(s, r), (_, d)| (s + d.total_transmitted(), r + d.total_received()))
}

pub fn elevated() -> bool {
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0
    }
    #[cfg(not(windows))]
    {
        crate::firewall::is_root()
    }
}

impl Monitor {
    pub fn new(store: Arc<Store>, emit: Emit) -> Arc<Monitor> {
        let settings = store.settings();
        let disabled: Vec<String> = settings["disabled_feeds"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let system = crate::system();
        Arc::new(Monitor {
            intel: Arc::new(Intelligence::new(&store.directory, &disabled)),
            binaries: Binaries::new(store.clone(), system),
            capture: Capture::new(),
            geo: Mutex::new(Geolocation::new()),
            dns: Mutex::new(DnsCache::new()),
            emit,
            inner: Mutex::new(Inner {
                sys: System::new(),
                networks: if cfg!(windows) { sysinfo::Networks::new() } else { sysinfo::Networks::new_with_refreshed_list() },
                current: HashMap::new(),
                identities: HashMap::new(),
                observations: HashMap::new(),
                previous_bytes: HashMap::new(),
                last_io: None,
                io_tick: None,
                last_tick: None,
                series: VecDeque::with_capacity(1800),
                samples: 0,
                last_feed_attempt: 0.0,
                last_prune: 0.0,
                last_checkpoint: 0.0,
                dns_names: HashMap::new(),
                last_dns: 0.0,
                starts: HashMap::new(),
                summary: None,
                on_battery: false,
                last_power: None,
            }),
            state: Mutex::new(json!({ "ready": false, "apps": [], "connections": [], "traffic": [], "sampled_at": null })),
            apps: Mutex::default(),
            visible: AtomicBool::new(true),
            error: Mutex::default(),
            stop: AtomicBool::new(false),
            started: now(),
            capture_available: Mutex::new(None),
            system,
            store,
        })
    }

    /// Cached identity when the PID's start time is unchanged (protected processes: re-verified every 30 s).
    fn cached(inner: &Inner, pid: u32, raw: Option<u64>) -> Option<Ident> {
        let c = inner.identities.get(&pid)?;
        let fresh = match raw {
            Some(r) => c.raw == Some(r),
            None => c.checked.elapsed() < Duration::from_secs(30),
        };
        fresh.then(|| c.clone())
    }

    fn identity(inner: &mut Inner, pid: Option<u32>, raw: Option<u64>) -> Ident {
        let Some(pid) = pid.filter(|p| *p != 0) else {
            return Ident { id: "unattributed".into(), name: "Unattributed sockets".into(), path: None, created: None, parent: None,
                           deleted: false, fileless: false, raw: None, checked: Instant::now() };
        };
        if let Some(c) = Self::cached(inner, pid, raw) {
            return c;
        }
        let Some(proc_) = inner.sys.process(Pid::from_u32(pid)) else {
            let gone = Ident { id: format!("unavailable-{pid}"), name: format!("Process {pid} (unavailable)"), path: None, created: None,
                               parent: None, deleted: false, fileless: false, raw, checked: Instant::now() };
            inner.identities.insert(pid, gone.clone());
            return gone;
        };
        let created = proc_.start_time() as f64;
        if let Some(c) = inner.identities.get_mut(&pid).filter(|c| c.created == Some(created)) {
            c.raw = raw;
            c.checked = Instant::now();
            return c.clone();
        }
        let name = proc_.name().to_string_lossy().into_owned();
        let mut path = proc_.exe().map(|p| p.to_string_lossy().into_owned()).filter(|p| !p.is_empty());
        let parent = proc_.parent().and_then(|pp| inner.sys.process(pp)).map(|p| p.name().to_string_lossy().into_owned());
        let (mut deleted, mut fileless) = (false, false);
        if cfg!(target_os = "linux") {
            if let Ok(link) = std::fs::read_link(format!("/proc/{pid}/exe")) {
                let link = link.to_string_lossy().into_owned();
                fileless = link.starts_with("/memfd:");
                if let Some(stripped) = link.strip_suffix(" (deleted)") {
                    deleted = true;
                    path = Some(stripped.to_string());
                }
            }
        }
        let key = path.as_deref().map(normcase).unwrap_or_else(|| format!("pid:{pid}:{created}"));
        let ident = Ident { id: app_id(&key), name, path, created: Some(created), parent, deleted, fileless, raw, checked: Instant::now() };
        inner.identities.insert(pid, ident.clone());
        ident
    }

    pub fn sample(&self) -> Result<(), String> {
        let tick = Instant::now();
        let now = now();
        let settings = self.store.settings();
        self.geo.lock().unwrap().configure(settings["geoip_path"].as_str().unwrap_or(""));
        let disabled: Vec<String> = settings["disabled_feeds"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        if disabled.iter().cloned().collect::<HashSet<_>>() != self.intel.disabled() {
            self.intel.set_disabled(&disabled);
        }
        let want_capture = settings["capture"].as_bool().unwrap_or(false);
        if want_capture && !self.capture.enabled.load(Ordering::SeqCst) {
            self.capture.start();
        } else if !want_capture && self.capture.enabled.load(Ordering::SeqCst) {
            self.capture.stop();
        }

        use netstat2::{AddressFamilyFlags as AF, ProtocolFlags as PF, ProtocolSocketInfo as P};
        // A failed sample must not turn missing visibility into closed sockets.
        let sockets = netstat2::get_sockets_info(AF::IPV4 | AF::IPV6, PF::TCP | PF::UDP)
            .map_err(|e| format!("Connection inventory requires additional OS permissions: {e}"))?;

        let mut inner = self.inner.lock().unwrap();
        // Enumerating every process costs ~12 ms on Windows, so it only happens when a PID is new or reused.
        let pids: HashSet<u32> = sockets.iter().flat_map(|s| s.associated_pids.iter().copied()).filter(|p| *p != 0).collect();
        let raws: HashMap<u32, Option<u64>> = pids.iter().map(|p| (*p, raw_start(*p))).collect();
        if raws.iter().any(|(pid, raw)| Self::cached(&inner, *pid, *raw).is_none()) {
            inner.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet));
        }

        let mut apps: BTreeMap<String, App> = BTreeMap::new();
        let mut idents: HashMap<String, Ident> = HashMap::new();
        let mut conns: Vec<Conn> = vec![];
        let mut listening: HashMap<String, HashSet<(String, u16)>> = HashMap::new();
        for s in &sockets {
            let pid = s.associated_pids.first().copied();
            let raw = pid.and_then(|p| raws.get(&p).copied().flatten());
            let ident = Self::identity(&mut inner, pid, raw);
            let app = apps.entry(ident.id.clone()).or_insert_with(|| App { id: ident.id.clone(), name: ident.name.clone(), path: ident.path.clone(), parent: ident.parent.clone(), ..Default::default() });
            if let Some(p) = pid.filter(|p| *p != 0) {
                if !app.pids.contains(&p) {
                    app.pids.push(p);
                }
            }
            let (protocol, local, lport, remote, status) = match &s.protocol_socket_info {
                P::Tcp(t) => {
                    let remote = (!t.remote_addr.is_unspecified() || t.remote_port != 0).then(|| (t.remote_addr.to_string(), t.remote_port));
                    ("TCP", t.local_addr.to_string(), t.local_port, remote, status_name(t.state))
                }
                P::Udp(u) => ("UDP", u.local_addr.to_string(), u.local_port, None, "NONE"),
            };
            if status == "LISTEN" {
                listening.entry(ident.id.clone()).or_default().insert((protocol.into(), lport));
            }
            conns.push(Conn { id: String::new(), app_id: ident.id.clone(), pid: pid.filter(|p| *p != 0), process_created: ident.created, local_ip: local, local_port: lport,
                              remote_ip: remote.as_ref().map(|r| r.0.clone()), remote_port: remote.map(|r| r.1), protocol: protocol.into(), status: status.into(),
                              source: "OS socket table".into(), first_seen: 0.0, last_seen: 0.0, domain: None, geo: None, threat: None });
            idents.insert(ident.id.clone(), ident);
        }
        let owners: Vec<Owner> = conns.iter().filter(|c| c.pid.is_some())
            .map(|c| Owner { app_id: &c.app_id, protocol: &c.protocol, local_ip: &c.local_ip, local_port: c.local_port, remote: c.remote_ip.as_deref().zip(c.remote_port) })
            .collect();
        self.capture.update_owners(&owners);
        let (totals, flows, captured_domains) = self.capture.snapshot();
        let captured = self.capture.active();
        if self.dns.lock().unwrap().available && now - inner.last_dns >= 10.0 {
            inner.last_dns = now;
            inner.dns_names = self.dns.lock().unwrap().read();
        }
        let mut domains = inner.dns_names.clone();
        domains.extend(captured_domains);
        let existing: HashSet<(String, String, String, u16, Option<String>, Option<u16>)> =
            conns.iter().map(|c| (c.app_id.clone(), c.protocol.clone(), c.local_ip.clone(), c.local_port, c.remote_ip.clone(), c.remote_port)).collect();
        for (aid, proto, lip, lp, rip, rp) in flows {
            if apps.contains_key(&aid) && !existing.contains(&(aid.clone(), proto.clone(), lip.clone(), lp, Some(rip.clone()), Some(rp))) {
                conns.push(Conn { id: String::new(), app_id: aid, pid: None, process_created: None, local_ip: lip, local_port: lp, remote_ip: Some(rip), remote_port: Some(rp),
                                  protocol: proto, status: "OBSERVED".into(), source: "Packet metadata".into(), first_seen: 0.0, last_seen: 0.0, domain: None, geo: None, threat: None });
            }
        }

        let mut current: HashMap<ConnKey, Conn> = HashMap::new();
        let mut new_ids: Vec<ConnKey> = vec![];
        {
            let mut geo = self.geo.lock().unwrap();
            for c in &mut conns {
                let key = c.key();
                let old = inner.current.get(&key);
                c.id = old.map(|o| o.id.clone()).unwrap_or_else(uuid);
                c.first_seen = old.map(|o| o.first_seen).unwrap_or(now);
                c.last_seen = now;
                c.domain = c.remote_ip.as_ref().and_then(|ip| domains.get(ip).cloned()).or_else(|| old.and_then(|o| o.domain.clone()));
                c.geo = c.remote_ip.as_deref().and_then(|ip| geo.lookup(ip));
                if let Some(ip) = c.remote_ip.as_deref() {
                    let mut hits = self.intel.match_ip(ip);
                    hits.extend(self.intel.match_domain(c.domain.as_deref()));
                    c.threat = hits.into_iter().max_by_key(|h| h.points);
                }
                if let Some(app) = apps.get_mut(&c.app_id) {
                    app.connections += 1;
                }
                if old.is_none() {
                    new_ids.push(key.clone());
                    let is_listen = listening.get(&c.app_id).is_some_and(|l| l.contains(&(c.protocol.clone(), c.local_port)));
                    if c.protocol == "TCP" && !is_listen {
                        if let (Some(ip), Some(port)) = (&c.remote_ip, c.remote_port) {
                            let starts = inner.starts.entry((c.app_id.clone(), ip.clone(), port)).or_insert_with(|| VecDeque::with_capacity(10));
                            if starts.len() == 10 {
                                starts.pop_front();
                            }
                            starts.push_back(now);
                        }
                    }
                }
                current.insert(key, c.clone());
            }
        }
        let ended: Vec<(String, f64)> = inner.current.iter().filter(|(k, _)| !current.contains_key(*k)).map(|(_, v)| (v.id.clone(), v.last_seen)).collect();
        let checkpoint = now - inner.last_checkpoint >= CHECKPOINT;
        if checkpoint {
            inner.last_checkpoint = now; // checkpoint last_seen and late domains for live rows
        }
        let records: Vec<&Conn> = if checkpoint { current.values().collect() } else { new_ids.iter().filter_map(|k| current.get(k)).collect() };
        self.store.connections(&records, &ended)?;
        inner.current = current;
        if inner.starts.len() > 5000 || inner.samples % 300 == 0 {
            inner.starts.retain(|_, v| v.back().is_some_and(|t| now - t < 3600.0));
        }

        let allow = self.store.allowlist();
        let allowed_apps: HashSet<String> = allow.iter().filter(|r| r["kind"] == "application").filter_map(|r| r["target"].as_str().map(String::from)).collect();
        let allowed_endpoints: HashSet<String> = allow.iter().filter(|r| r["kind"] == "endpoint").filter_map(|r| r["target"].as_str().map(String::from)).collect();
        let mut grouped: HashMap<&str, Vec<&Conn>> = HashMap::new();
        for c in &conns {
            grouped.entry(c.app_id.as_str()).or_default().push(c);
        }
        let mut beacons: HashMap<String, BTreeMap<(String, u16), Vec<f64>>> = HashMap::new();
        for ((aid, ip, port), starts) in &inner.starts {
            if apps.contains_key(aid) && starts.len() >= 6 {
                beacons.entry(aid.clone()).or_default().insert((ip.clone(), *port), starts.iter().copied().collect());
            }
        }
        let elapsed = inner.last_tick.map(|t| tick.duration_since(t).as_secs_f64());
        let active = settings["active_protection"].as_bool().unwrap_or(false);
        let empty = vec![];
        for (aid, app) in apps.iter_mut() {
            *inner.observations.entry(aid.clone()).or_insert(0) += 1;
            let observations = inner.observations[aid];
            let ident = idents.get(aid);
            let total = totals.get(aid).copied().unwrap_or([0, 0]);
            let previous = inner.previous_bytes.get(aid).copied();
            let binary: Option<Binary> = app.path.as_deref().map(|p| self.binaries.info(p));
            let cs = grouped.get(aid.as_str()).unwrap_or(&empty);
            let ctx = Context {
                system: self.system,
                binary: binary.as_ref(),
                listening: listening.get(aid),
                beacons: beacons.get(aid),
                totals: captured.then_some(total),
                deleted: ident.is_some_and(|i| i.deleted),
                fileless: ident.is_some_and(|i| i.fileless),
                parent: app.parent.as_deref(),
            };
            let allowlisted = app.path.as_ref().is_some_and(|p| allowed_apps.contains(p));
            app.risk = assess(&app.name, app.path.as_deref(), cs, self.intel.as_ref(), observations, allowlisted, &allowed_endpoints, &ctx);
            app.binary = binary;
            app.listening = listening.get(aid).map(HashSet::len).unwrap_or(0);
            if let (true, Some(e), Some(p)) = (captured, elapsed, previous) {
                app.upload_bps = Some(total[0].saturating_sub(p[0]) as f64 / e);
                app.download_bps = Some(total[1].saturating_sub(p[1]) as f64 / e);
            }
            if captured {
                app.uploaded = Some(total[0]);
                app.downloaded = Some(total[1]);
            }
            // Wait for executable inspection before a Medium alert so a late signature result does not re-alert.
            let pending = app.binary.as_ref().is_some_and(|b| b.state == "pending");
            if app.risk.level == "High" || (app.risk.level == "Medium" && !pending) {
                self.alert(app, cs, now, active);
            }
            self.new_app(app, cs, &listening, now);
        }
        inner.previous_bytes = totals;
        self.traffic(&mut inner, tick, now);
        inner.last_tick = Some(tick);
        inner.samples += 1;
        *self.error.lock().unwrap() = None;

        let mut sorted: Vec<App> = apps.into_values().collect();
        sorted.sort_by(|a, b| (-(a.risk.score.unwrap_or(0)), -(a.connections as i64), &a.name).cmp(&(-(b.risk.score.unwrap_or(0)), -(b.connections as i64), &b.name)));
        let last = inner.series.back().cloned().unwrap_or(json!({}));
        *self.state.lock().unwrap() = json!({ "ready": true, "sampled_at": now, "apps": sorted, "connections": conns, "traffic": inner.series,
                                              "upload_bps": last.get("upload"), "download_bps": last.get("download"), "started": self.started });
        self.publish(&mut inner, &sorted, &conns);
        let alive: HashSet<u32> = sorted.iter().flat_map(|a| a.pids.iter().copied()).collect();
        inner.identities.retain(|k, _| alive.contains(k));
        let ids: HashSet<&String> = sorted.iter().map(|a| &a.id).collect();
        inner.observations.retain(|k, _| ids.contains(k));
        if now - inner.last_prune > 60.0 {
            let _ = self.store.prune();
            inner.last_prune = now;
            self.binaries.forget_missing(&sorted.iter().filter_map(|a| a.path.clone()).collect());
        }
        *self.apps.lock().unwrap() = sorted;
        if settings["feed_updates"].as_bool().unwrap_or(true) && now - inner.last_feed_attempt > 600.0 {
            inner.last_feed_attempt = now;
            let intel = self.intel.clone();
            std::thread::spawn(move || {
                let _ = intel.refresh(true);
            });
        }
        Ok(())
    }

    /// Interface counters; while no window is open they are read every third tick.
    fn traffic(&self, inner: &mut Inner, tick: Instant, now: f64) {
        if !self.visible.load(Ordering::Relaxed) && inner.io_tick.is_some() && inner.samples % 3 != 0 {
            return;
        }
        let (sent, recv) = interface_totals(&mut inner.networks);
        let (mut up, mut down) = (Value::Null, Value::Null);
        if let (Some((ls, lr)), Some(t)) = (inner.last_io, inner.io_tick) {
            let span = tick.duration_since(t).as_secs_f64().max(0.001);
            up = json!(sent.saturating_sub(ls) as f64 / span);
            down = json!(recv.saturating_sub(lr) as f64 / span);
        }
        inner.last_io = Some((sent, recv));
        inner.io_tick = Some(tick);
        if inner.series.len() == 1800 {
            inner.series.pop_front();
        }
        inner.series.push_back(json!({ "time": now, "upload": up, "download": down }));
    }

    fn alert(&self, app: &App, conns: &[&Conn], now: f64, active: bool) {
        let risk = &app.risk;
        let mut rules: Vec<String> = risk.evidence.iter().filter(|e| e.points >= 15)
            .map(|e| if e.category == "intel" { format!("{}:{}", e.rule, e.endpoint.clone().unwrap_or_default()) } else { e.rule.clone() })
            .collect();
        rules.sort();
        rules.dedup();
        let Some(top) = risk.evidence.iter().filter(|e| e.points > 0).max_by_key(|e| e.points) else { return };
        let endpoint = conns.iter().find(|c| c.remote_ip.is_some() && c.remote_ip == top.endpoint).map(|c| {
            json!({ "ip": c.remote_ip, "port": c.remote_port, "domain": c.domain, "country": c.geo.as_ref().and_then(|g| g.get("country")) })
        });
        let mut alert = json!({ "id": uuid(), "key": format!("{}|{}|{}", app.id, risk.level, rules.join(",")), "app_id": app.id, "app_name": app.name,
                                "path": app.path, "created": now, "level": risk.level, "title": top.title, "risk": risk, "endpoint": endpoint });
        if self.store.add_alert(&alert).unwrap_or(false) {
            let binary = app.binary.clone().unwrap_or_default();
            if active && risk.level == "High" && binary.signature.as_deref() != Some("valid") && !binary.os_binary
                && risk.evidence.iter().any(|e| AUTO_RESPONSE.contains(&e.rule.as_str()))
            {
                alert["response"] = match self.terminate_app(app, true) {
                    Ok(r) => json!({ "action": "terminated", "at": crate::intel::now() }).as_object().unwrap().clone().into_iter().chain(r.as_object().unwrap().clone()).collect(),
                    Err(e) => json!({ "action": "failed", "at": crate::intel::now(), "error": e }),
                };
                let _ = self.store.update_alert(&alert);
            }
            alert["acknowledged"] = json!(false);
            (self.emit)("alert", alert);
        }
    }

    /// Record an executable's first internet connection; alert unless it is an OS binary or Beaver is still learning.
    fn new_app(&self, app: &App, conns: &[&Conn], listening: &HashMap<String, HashSet<(String, u16)>>, now: f64) {
        let Some(path) = app.path.as_deref() else { return };
        let binary = app.binary.clone().unwrap_or_default();
        if binary.state == "pending" || self.store.is_known(path) {
            return;
        }
        let first = conns.iter().find(|c| {
            c.remote_ip.as_deref().is_some_and(public) && !listening.get(&app.id).is_some_and(|l| l.contains(&(c.protocol.clone(), c.local_port)))
        });
        let Some(first) = first else { return };
        if !self.store.first_internet(path) || self.store.learning() || binary.os_binary {
            return;
        }
        let alert = json!({ "id": uuid(), "key": format!("new-app|{path}"), "app_id": app.id, "app_name": app.name, "path": path, "created": now,
                            "level": "Info", "kind": "new-app", "title": "First internet connection", "publisher": binary.publisher, "signature": binary.signature,
                            "risk": { "level": "Info", "score": null, "evidence": [], "reason": "A program connected to the internet for the first time.", "allowlisted": false },
                            "endpoint": { "ip": first.remote_ip, "port": first.remote_port, "domain": first.domain, "country": first.geo.as_ref().and_then(|g| g.get("country")) } });
        if self.store.add_alert(&alert).unwrap_or(false) {
            let mut a = alert;
            a["acknowledged"] = json!(false);
            (self.emit)("alert", a);
        }
    }

    pub fn terminate(&self, app_id: &str) -> Result<Value, String> {
        let app = self.apps.lock().unwrap().iter().find(|a| a.id == app_id).cloned().ok_or("That application is no longer running")?;
        self.terminate_app(&app, false)
    }

    /// Stop every live process of one application. Refuses Beaver, PID 0/4 and core Windows processes.
    fn terminate_app(&self, app: &App, automatic: bool) -> Result<Value, String> {
        if app.pids.is_empty() {
            return Err("That application is no longer running".into());
        }
        let binary = app.binary.clone().unwrap_or_default();
        if risk::is_protected(&app.name) || (binary.os_binary && app.risk.remote_tool.is_none()) {
            return Err("Beaver will not stop core operating-system processes. Block its endpoints in Firewall instead.".into());
        }
        let me = std::process::id();
        let mut sys = System::new();
        let pids: Vec<Pid> = app.pids.iter().map(|p| Pid::from_u32(*p)).collect();
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&pids), true, ProcessRefreshKind::nothing());
        let parent = sys.process(Pid::from_u32(me)).and_then(|p| p.parent()).map(|p| p.as_u32());
        let known = self.inner.lock().unwrap().identities.clone();
        let (mut stopped, mut failed) = (vec![], vec![]);
        for pid in &app.pids {
            let same = known.get(pid).is_some_and(|i| i.id == app.id);
            let proc_ = sys.process(Pid::from_u32(*pid));
            if *pid <= 4 || *pid == me || Some(*pid) == parent || !same || proc_.is_none() {
                failed.push(json!({ "pid": pid, "error": "Process identity changed or is protected" }));
                continue;
            }
            let proc_ = proc_.unwrap();
            if known.get(pid).and_then(|i| i.created) != Some(proc_.start_time() as f64) {
                continue; // exited and the PID was reused
            }
            if proc_.kill() {
                stopped.push(*pid);
            } else {
                failed.push(json!({ "pid": pid, "error": "Requires administrator rights. Block the application in Firewall instead." }));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            sys.refresh_processes_specifics(ProcessesToUpdate::Some(&pids), true, ProcessRefreshKind::nothing());
            if stopped.iter().all(|p| sys.process(Pid::from_u32(*p)).is_none()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if stopped.is_empty() && !failed.is_empty() {
            return Err(failed[0]["error"].as_str().unwrap_or("Could not stop the process").into());
        }
        Ok(json!({ "terminated": stopped, "failed": failed, "automatic": automatic }))
    }

    /// Push a small status summary (tray tooltip, badge) only when it changes.
    fn publish(&self, inner: &mut Inner, apps: &[App], conns: &[Conn]) {
        let count = |l: &str| apps.iter().filter(|a| a.risk.level == l).count();
        let unack = self.store.alert_counts();
        let total: i64 = unack.values().filter_map(Value::as_i64).sum();
        let summary = json!({ "apps": apps.iter().filter(|a| a.id != "unattributed").count(), "high": count("High"), "medium": count("Medium"),
                              "connections": conns.iter().filter(|c| c.remote_ip.is_some() && !CLOSED.contains(&c.status.as_str())).count(),
                              "unacknowledged": total, "unacknowledged_high": unack.get("High").and_then(Value::as_i64).unwrap_or(0),
                              "intel_fresh": self.intel.fresh() });
        if inner.summary.as_ref() != Some(&summary) {
            inner.summary = Some(summary.clone());
            (self.emit)("status", summary);
        }
    }

    pub fn reset_summary(&self) {
        self.inner.lock().unwrap().summary = None;
    }

    fn capture_probe(&self) -> bool {
        *self.capture_available.lock().unwrap().get_or_insert_with(|| crate::pcap::live::Pcap::load().is_ok())
    }

    /// 2 s normally; 4 s when no window is open and the device runs on battery.
    pub fn interval(&self) -> f64 {
        let mut inner = self.inner.lock().unwrap();
        if inner.last_power.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
            inner.last_power = Some(Instant::now());
            inner.on_battery = on_battery();
        }
        if inner.on_battery && !self.visible.load(Ordering::Relaxed) { INTERVAL * 2.0 } else { INTERVAL }
    }

    pub fn snapshot(&self) -> Value {
        let mut data = self.state.lock().unwrap().clone();
        let (on_battery, dns_names) = {
            let i = self.inner.lock().unwrap();
            (i.on_battery, i.dns_names.len())
        };
        let geo = self.geo.lock().unwrap();
        let dns = self.dns.lock().unwrap();
        let mut capture = self.capture.status();
        capture["available"] = json!(self.capture_probe());
        data["coverage"] = json!({
            "platform": self.system, "elevated": elevated(), "inventory_error": *self.error.lock().unwrap(),
            "inventory": "OS socket polling every 2 seconds; short-lived connections can be missed. Linux may omit sockets without sufficient permissions.",
            "capture": capture, "intel": self.intel.status(),
            "power": { "on_battery": on_battery, "interval": if on_battery && !self.visible.load(Ordering::Relaxed) { INTERVAL * 2.0 } else { INTERVAL } },
            "geo": { "available": geo.available(), "error": geo.error, "provider": geo.provider() },
            "dns_cache": { "available": dns.available, "names": dns_names, "error": dns.error },
            "binaries": { "error": *self.binaries.error.lock().unwrap(), "signatures": self.system == "Windows" },
            "domains": format!("Domains come from observed plaintext DNS answers, the TLS server name{}. Encrypted DNS (DoH/DoT) lookups are only named through the TLS server name.",
                               if dns.available { " and the Windows DNS client cache" } else { "" }),
        });
        data
    }

    pub fn run(self: &Arc<Self>) {
        let me = self.clone();
        std::thread::Builder::new()
            .name("beaver-monitor".into())
            .spawn(move || {
                while !me.stop.load(Ordering::SeqCst) {
                    let start = Instant::now();
                    if let Err(e) = me.sample() {
                        let e: String = e.chars().take(300).collect();
                        let mut err = me.error.lock().unwrap();
                        if err.as_deref() != Some(&e) {
                            log::warn!("Sample failed: {e}"); // once per distinct error
                        }
                        *err = Some(e);
                    }
                    let wait = (me.interval() - start.elapsed().as_secs_f64()).max(0.1);
                    let until = Instant::now() + Duration::from_secs_f64(wait);
                    while Instant::now() < until && !me.stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            .expect("monitor thread");
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.capture.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::temp;
    use std::net::TcpListener;

    #[test]
    fn live_socket_is_observed_and_retained() {
        let (store, dir) = temp();
        let store = Arc::new(store);
        let events = Arc::new(Mutex::new(vec![]));
        let ev = events.clone();
        let monitor = Monitor::new(store.clone(), Arc::new(move |e: &str, _| ev.lock().unwrap().push(e.to_string())));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let _server = listener.accept().unwrap();
        monitor.sample().unwrap();
        let snap = monitor.snapshot();
        let me = std::process::id();
        let rows: Vec<&Value> = snap["connections"].as_array().unwrap().iter().filter(|c| c["pid"] == me && c["local_port"] == port).collect();
        assert!(!rows.is_empty(), "real local socket missing from OS telemetry");
        assert!(store.history(rows[0]["app_id"].as_str().unwrap(), 0, 50).unwrap()["total"].as_i64().unwrap() >= 1);
        assert!(events.lock().unwrap().contains(&"status".to_string()));
        monitor.sample().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn terminate_refuses_core_and_self() {
        let (store, dir) = temp();
        let monitor = Monitor::new(Arc::new(store), Arc::new(|_: &str, _| {}));
        let me = std::process::id();
        let core = App { id: "core".into(), name: "lsass.exe".into(), pids: vec![me], ..Default::default() };
        assert!(monitor.terminate_app(&core, false).unwrap_err().contains("core operating-system"));
        let selfish = App { id: "self".into(), name: "beaver".into(), pids: vec![me], ..Default::default() };
        assert!(monitor.terminate_app(&selfish, false).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn app_ids_match_python() {
        // sha256(os.path.normcase(r"C:\Windows\System32\svchost.exe"))[:24] as computed by the Python service
        if cfg!(windows) {
            assert_eq!(app_id(&normcase("C:\\Windows\\System32\\svchost.exe")), "3201a28fcf51c575d238c6bb");
        }
    }
}
