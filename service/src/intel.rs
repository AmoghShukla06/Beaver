//! Local matching against public threat feeds, and optional local GeoIP.
//! Observed endpoints never leave the device; refreshes are plain HTTPS downloads.
use crate::net;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

pub const USER_AGENT: &str = "Beaver/1.4 (+https://github.com/AmoghShukla06/Beaver; local threat matching)";

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Ip,
    Cidr,
    Domain,
}
#[derive(Clone, Copy, PartialEq)]
pub enum Format {
    Feodo,
    Spamhaus,
    Lines,
}

pub struct Feed {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: Kind,
    pub format: Format,
    /// Contribution of one match. Feeds below 80 cannot raise High on their own.
    pub points: i32,
    pub url: &'static str,
    pub home: &'static str,
    pub category: &'static str,
    pub refresh: f64,
    pub max_age: f64,
    pub limit: u64,
}

const H: f64 = 3600.0;
const D: f64 = 86400.0;
pub const FEEDS: &[Feed] = &[
    Feed { id: "feodo", name: "Feodo Tracker botnet C2", kind: Kind::Ip, format: Format::Feodo, points: 90,
           url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", home: "https://feodotracker.abuse.ch/blocklist/",
           category: "Botnet command-and-control server", refresh: H, max_age: 6.0 * H, limit: 4_000_000 },
    Feed { id: "spamhaus-drop", name: "Spamhaus DROP (IPv4)", kind: Kind::Cidr, format: Format::Spamhaus, points: 80,
           url: "https://www.spamhaus.org/drop/drop_v4.json", home: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
           category: "Hijacked or criminal-operated network", refresh: 12.0 * H, max_age: 4.0 * D, limit: 4_000_000 },
    Feed { id: "spamhaus-drop-v6", name: "Spamhaus DROP (IPv6)", kind: Kind::Cidr, format: Format::Spamhaus, points: 80,
           url: "https://www.spamhaus.org/drop/drop_v6.json", home: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
           category: "Hijacked or criminal-operated network", refresh: 12.0 * H, max_age: 4.0 * D, limit: 2_000_000 },
    Feed { id: "threat-domains", name: "HaGeZi Threat Intelligence domains", kind: Kind::Domain, format: Format::Lines, points: 80,
           url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
           home: "https://github.com/hagezi/dns-blocklists", category: "Malware, phishing or C2 domain",
           refresh: 12.0 * H, max_age: 4.0 * D, limit: 12_000_000 },
    Feed { id: "et-compromised", name: "Emerging Threats compromised hosts", kind: Kind::Ip, format: Format::Lines, points: 45,
           url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", home: "https://rules.emergingthreats.net/",
           category: "Known compromised host", refresh: 12.0 * H, max_age: 4.0 * D, limit: 4_000_000 },
    Feed { id: "ipsum", name: "IPsum (on 4+ blocklists)", kind: Kind::Ip, format: Format::Lines, points: 40,
           url: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt", home: "https://github.com/stamparm/ipsum",
           category: "Repeatedly reported attacker or scanner", refresh: 12.0 * H, max_age: 4.0 * D, limit: 4_000_000 },
];

#[cfg(test)]
pub fn feed(id: &str) -> Option<&'static Feed> {
    FEEDS.iter().find(|f| f.id == id)
}

pub fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Stable 64-bit FNV-1a: domain lists are stored as a sorted array of hashes (~1.7 MB for 212k domains).
pub fn domain_hash(name: &str) -> u64 {
    name.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

pub enum Data {
    Ips(HashSet<u128>),
    Ranges(Vec<(u128, u128)>),
    Domains(Vec<u64>),
}
impl Data {
    fn len(&self) -> usize {
        match self {
            Data::Ips(s) => s.len(),
            Data::Ranges(r) => r.len(),
            Data::Domains(d) => d.len(),
        }
    }
}

/// Parse one feed body into its lookup structure. Rejects unexpected content instead of half-loading it.
pub fn parse(feed: &Feed, raw: &[u8]) -> Result<Data, String> {
    let text = String::from_utf8_lossy(raw);
    let values: Vec<String> = match feed.format {
        Format::Feodo => {
            let rows: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let rows = rows.as_array().ok_or("Unexpected threat feed format")?;
            if rows.len() > 100_000 {
                return Err("Unexpected threat feed format".into());
            }
            rows.iter()
                .map(|r| r.get("ip_address").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "Invalid threat entry".to_string()))
                .collect::<Result<_, _>>()?
        }
        Format::Spamhaus => text
            .lines()
            .filter(|l| l.trim_start().starts_with("{\"cidr\""))
            .map(|l| serde_json::from_str::<Value>(l).ok().and_then(|v| v["cidr"].as_str().map(str::to_string)).ok_or_else(|| "Invalid range".to_string()))
            .collect::<Result<_, _>>()?,
        Format::Lines => text
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
            .filter(|v| !v.is_empty() && !v.starts_with('!') && !v.starts_with('['))
            .collect(),
    };
    if values.len() > 1_000_000 {
        return Err("Threat feed exceeds entry limit".into());
    }
    Ok(match feed.kind {
        Kind::Ip => {
            let mut set = HashSet::with_capacity(values.len());
            for v in &values {
                let ip: IpAddr = v.split_whitespace().next().unwrap_or("").parse().map_err(|_| format!("Invalid address {v}"))?;
                if !net::is_global(&ip) {
                    return Err("Non-public address in public feed".into());
                }
                set.insert(net::key(&ip));
            }
            Data::Ips(set)
        }
        Kind::Cidr => {
            let mut ranges = Vec::with_capacity(values.len());
            for v in &values {
                let (first, last, prefix, addr) = net::cidr(v).ok_or_else(|| format!("Invalid network {v}"))?;
                if prefix < 8 || !net::is_global(&addr) {
                    return Err("Implausible network in public feed".into());
                }
                ranges.push((first, last));
            }
            ranges.sort_unstable();
            Data::Ranges(ranges)
        }
        Kind::Domain => {
            let mut hashes: Vec<u64> = values
                .iter()
                .map(|v| v.to_lowercase())
                .filter(|v| v.contains('.') && v.len() <= 253)
                .map(|v| domain_hash(v.trim_end_matches('.')))
                .collect();
            hashes.sort_unstable();
            hashes.dedup();
            Data::Domains(hashes)
        }
    })
}

#[derive(Clone, Serialize)]
pub struct Hit {
    pub feed: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub points: i32,
    pub source: &'static str,
    pub malware: &'static str,
    pub value: String,
}
fn hit(f: &'static Feed, value: &str) -> Hit {
    Hit { feed: f.id, name: f.name, category: f.category, points: f.points, source: f.home, malware: f.category, value: value.to_string() }
}

#[derive(Default)]
struct Loaded {
    data: HashMap<&'static str, Data>,
    updated: HashMap<&'static str, f64>,
}

pub struct Intelligence {
    dir: PathBuf,
    loaded: RwLock<Loaded>,
    pub errors: Mutex<HashMap<&'static str, String>>,
    disabled: RwLock<HashSet<String>>,
    cache: Mutex<HashMap<String, Vec<Hit>>>,
    refreshing: AtomicBool,
}

impl Intelligence {
    pub fn new(directory: &Path, disabled: &[String]) -> Intelligence {
        let dir = directory.join("feeds");
        let _ = std::fs::create_dir_all(&dir);
        let intel = Intelligence {
            dir,
            loaded: RwLock::default(),
            errors: Mutex::default(),
            disabled: RwLock::new(disabled.iter().cloned().collect()),
            cache: Mutex::default(),
            refreshing: AtomicBool::new(false),
        };
        for f in FEEDS {
            let raw = std::fs::read(intel.dir.join(format!("{}.txt", f.id)));
            let meta = std::fs::read_to_string(intel.dir.join(format!("{}.json", f.id)));
            if let (Ok(raw), Ok(meta)) = (raw, meta) {
                let updated = serde_json::from_str::<Value>(&meta).ok().and_then(|m| m["updated"].as_f64());
                if let (Some(updated), Ok(data)) = (updated, parse(f, &raw)) {
                    intel.install(f, data, updated);
                }
            }
        }
        intel
    }

    fn install(&self, f: &'static Feed, data: Data, updated: f64) {
        let mut l = self.loaded.write().unwrap();
        l.data.insert(f.id, data);
        l.updated.insert(f.id, updated);
        self.cache.lock().unwrap().clear();
    }

    fn fetch(&self, f: &'static Feed) -> Result<(), String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .max_redirects(0) // a moved feed fails safely rather than following an unexpected host
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        let mut response = agent.get(f.url).header("User-Agent", USER_AGENT).call().map_err(|e| e.to_string())?;
        let raw = response.body_mut().with_config().limit(f.limit).read_to_vec().map_err(|e| e.to_string())?;
        let data = parse(f, &raw)?;
        let updated = now();
        let path = self.dir.join(format!("{}.txt", f.id));
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &raw).and_then(|_| std::fs::rename(&tmp, &path)).map_err(|e| e.to_string())?;
        std::fs::write(self.dir.join(format!("{}.json", f.id)), json!({ "updated": updated }).to_string()).map_err(|e| e.to_string())?;
        self.install(f, data, updated);
        self.errors.lock().unwrap().remove(f.id);
        Ok(())
    }

    /// Download enabled feeds one at a time. A failed feed keeps its previous cache.
    pub fn refresh(&self, only_due: bool) -> Result<Value, String> {
        if self.refreshing.swap(true, Ordering::SeqCst) {
            return Err("A feed refresh is already running".into());
        }
        let now = now();
        let disabled = self.disabled.read().unwrap().clone();
        for f in FEEDS {
            let updated = self.loaded.read().unwrap().updated.get(f.id).copied().unwrap_or(0.0);
            if disabled.contains(f.id) || (only_due && now - updated < f.refresh) {
                continue;
            }
            if let Err(e) = self.fetch(f) {
                log::warn!("Feed {} failed: {e}", f.id);
                self.errors.lock().unwrap().insert(f.id, e.chars().take(300).collect());
            }
        }
        self.refreshing.store(false, Ordering::SeqCst);
        let errors = self.errors.lock().unwrap();
        if !only_due && !errors.is_empty() && errors.len() == FEEDS.len() - disabled.len() {
            return Err(format!("No threat feed could be refreshed: {}", errors.values().next().unwrap()));
        }
        drop(errors);
        Ok(self.status())
    }

    fn fresh_ids(&self) -> Vec<&'static str> {
        let now = now();
        let l = self.loaded.read().unwrap();
        let disabled = self.disabled.read().unwrap();
        FEEDS.iter()
            .filter(|f| !disabled.contains(f.id) && l.data.contains_key(f.id) && now - l.updated[f.id] <= f.max_age)
            .map(|f| f.id)
            .collect()
    }

    pub fn fresh(&self) -> bool {
        !self.fresh_ids().is_empty()
    }

    pub fn status(&self) -> Value {
        let fresh = self.fresh_ids();
        let l = self.loaded.read().unwrap();
        let disabled = self.disabled.read().unwrap();
        let errors = self.errors.lock().unwrap();
        let feeds: Vec<Value> = FEEDS
            .iter()
            .map(|f| {
                json!({ "id": f.id, "name": f.name, "kind": match f.kind { Kind::Ip => "ip", Kind::Cidr => "cidr", Kind::Domain => "domain" },
                        "category": f.category, "home": f.home, "points": f.points,
                        "entries": l.data.get(f.id).map(Data::len).unwrap_or(0), "updated": l.updated.get(f.id),
                        "fresh": fresh.contains(&f.id), "enabled": !disabled.contains(f.id), "error": errors.get(f.id) })
            })
            .collect();
        let updated = l.updated.values().cloned().fold(None, |a: Option<f64>, b| Some(a.map_or(b, |a| a.max(b))));
        let entries: usize = FEEDS.iter().filter(|f| fresh.contains(&f.id)).map(|f| l.data.get(f.id).map(Data::len).unwrap_or(0)).sum();
        let error: Vec<String> = FEEDS.iter().filter(|f| !disabled.contains(f.id)).filter_map(|f| errors.get(f.id).map(|e| format!("{}: {e}", f.name))).collect();
        json!({ "source": "Public threat feeds", "url": FEEDS[0].home, "updated": updated, "entries": entries, "fresh": !fresh.is_empty(),
                "error": if error.is_empty() { Value::Null } else { Value::from(error.join("; ")) },
                "refreshing": self.refreshing.load(Ordering::SeqCst), "feeds": feeds })
    }

    /// All fresh feed hits for an IP, strongest first; cached until the next feed change.
    pub fn match_ip(&self, ip: &str) -> Vec<Hit> {
        if let Some(hits) = self.cache.lock().unwrap().get(ip) {
            return hits.clone();
        }
        let mut hits = vec![];
        if let Ok(addr) = ip.parse::<IpAddr>() {
            if net::is_global(&addr) {
                let value = net::key(&addr);
                let fresh = self.fresh_ids();
                let l = self.loaded.read().unwrap();
                for f in FEEDS.iter().filter(|f| fresh.contains(&f.id)) {
                    let found = match l.data.get(f.id) {
                        Some(Data::Ips(set)) => set.contains(&value),
                        Some(Data::Ranges(r)) => {
                            let i = r.partition_point(|(start, _)| *start <= value);
                            i > 0 && value <= r[i - 1].1
                        }
                        _ => false,
                    };
                    if found {
                        hits.push(hit(f, ip));
                    }
                }
                hits.sort_by_key(|h| -h.points);
            }
        }
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 20_000 {
            cache.clear();
        }
        cache.insert(ip.to_string(), hits.clone());
        hits
    }

    /// A listed domain also matches its subdomains.
    pub fn match_domain(&self, domain: Option<&str>) -> Vec<Hit> {
        let Some(domain) = domain else { return vec![] };
        let lower = domain.to_lowercase();
        let labels: Vec<&str> = lower.trim_end_matches('.').split('.').collect();
        let candidates: Vec<u64> = (0..labels.len().saturating_sub(1)).map(|i| domain_hash(&labels[i..].join("."))).collect();
        let fresh = self.fresh_ids();
        let l = self.loaded.read().unwrap();
        FEEDS.iter()
            .filter(|f| f.kind == Kind::Domain && fresh.contains(&f.id))
            .filter(|f| matches!(l.data.get(f.id), Some(Data::Domains(d)) if candidates.iter().any(|c| d.binary_search(c).is_ok())))
            .map(|f| hit(f, domain))
            .collect()
    }

    pub fn disabled(&self) -> HashSet<String> {
        self.disabled.read().unwrap().clone()
    }

    pub fn set_disabled(&self, disabled: &[String]) {
        *self.disabled.write().unwrap() = disabled.iter().cloned().collect();
        self.cache.lock().unwrap().clear();
    }

    #[cfg(test)]
    pub fn install_for_test(&self, id: &str, raw: &[u8], updated: f64) {
        let f = feed(id).unwrap();
        self.install(f, parse(f, raw).unwrap(), updated);
    }
}

// ---- GeoIP ---------------------------------------------------------------------------------------

pub struct Geolocation {
    reader: Option<maxminddb::Reader<maxminddb::Mmap>>,
    pub path: String,
    pub error: Option<String>,
    cache: HashMap<String, Option<Value>>,
}

impl Geolocation {
    pub fn new() -> Geolocation {
        Geolocation { reader: None, path: String::new(), error: None, cache: HashMap::new() }
    }

    pub fn configure(&mut self, path: &str) {
        if path == self.path {
            return;
        }
        *self = Geolocation::new();
        self.path = path.to_string();
        if !path.is_empty() {
            // SAFETY: Beaver never modifies a database while it is mapped; a replacement is written to a new file.
            match unsafe { maxminddb::Reader::open_mmap(path) } {
                Ok(r) => self.reader = Some(r),
                Err(e) => self.error = Some(e.to_string().chars().take(200).collect()),
            }
        }
    }

    pub fn available(&self) -> bool {
        self.reader.is_some()
    }

    pub fn provider(&self) -> Option<String> {
        self.reader.as_ref().map(|r| r.metadata().database_type.clone())
    }

    pub fn lookup(&mut self, ip: &str) -> Option<Value> {
        let reader = self.reader.as_ref()?;
        let addr: IpAddr = ip.parse().ok()?;
        if !net::is_global(&addr) {
            return None;
        }
        if let Some(v) = self.cache.get(ip) {
            return v.clone();
        }
        let result = reader.lookup(addr).ok().and_then(|r| r.decode::<maxminddb::geoip2::City>().ok().flatten()).and_then(|c| {
            Some(json!({ "country": c.country.names.english.unwrap_or("Unknown"), "code": c.country.iso_code.unwrap_or("??"),
                         "lat": c.location.latitude?, "lon": c.location.longitude?, "city": c.city.names.english,
                         "accuracy_km": c.location.accuracy_radius }))
        });
        if self.cache.len() > 10_000 {
            self.cache.clear();
        }
        self.cache.insert(ip.to_string(), result.clone());
        result
    }
}

/// Validate that a file is a MaxMind-format City database with coordinates.
pub fn validate_city_db(path: &str) -> Result<(), String> {
    let reader = maxminddb::Reader::open_readfile(path).map_err(|e| e.to_string())?;
    if !reader.metadata().database_type.contains("City") {
        return Err("Choose a MaxMind-compatible City database with coordinates".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers_accept_formats_and_reject_poison() {
        assert!(matches!(parse(feed("feodo").unwrap(), b"[]"), Ok(Data::Ips(s)) if s.is_empty()));
        assert!(matches!(parse(feed("feodo").unwrap(), br#"[{"ip_address":"1.1.1.1"}]"#), Ok(Data::Ips(s)) if s.len() == 1));
        for bad in [&b"{}"[..], br#"[{}]"#, br#"[{"ip_address":"127.0.0.1"}]"#, br#"[{"ip_address":"nope"}]"#] {
            assert!(parse(feed("feodo").unwrap(), bad).is_err());
        }
        assert!(matches!(parse(feed("spamhaus-drop").unwrap(), b"{\"cidr\":\"1.10.16.0/20\"}\n{\"type\":\"metadata\"}\n"), Ok(Data::Ranges(r)) if r[0].1 - r[0].0 == 4095));
        assert!(parse(feed("spamhaus-drop").unwrap(), b"{\"cidr\":\"0.0.0.0/0\"}").is_err());
        assert!(matches!(parse(feed("ipsum").unwrap(), b"# c\n8.8.4.4\n\n9.9.9.9 7\n"), Ok(Data::Ips(s)) if s.len() == 2));
    }

    #[test]
    fn matching_and_staleness() {
        let dir = std::env::temp_dir().join(format!("bv-intel-{}", std::process::id()));
        let intel = Intelligence::new(&dir, &[]);
        intel.install_for_test("spamhaus-drop", b"{\"cidr\":\"1.10.16.0/20\"}\n", now());
        intel.install_for_test("threat-domains", b"# h\nevil.example\n", now());
        intel.install_for_test("feodo", br#"[{"ip_address":"5.5.5.5"}]"#, now() - 7.0 * H);
        assert_eq!(intel.match_ip("1.10.31.255")[0].feed, "spamhaus-drop");
        assert!(intel.match_ip("1.10.32.0").is_empty() && intel.match_ip("10.0.0.1").is_empty() && intel.match_ip("x").is_empty());
        assert!(intel.match_ip("5.5.5.5").is_empty(), "stale feed must not match");
        assert_eq!(intel.match_domain(Some("cdn.Evil.example"))[0].points, 80);
        assert!(intel.match_domain(Some("example")).is_empty());
        intel.set_disabled(&["spamhaus-drop".into()]);
        assert!(intel.match_ip("1.10.16.1").is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
