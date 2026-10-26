//! Opt-in metadata-only capture. Headers are parsed in place; packet bytes and payloads are never retained.
use crate::intel::now;
use crate::pcap::{self, live::Pcap, Packet};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub type FlowKey = (String, String, String, u16, String, u16); // app, protocol, local ip, local port, remote ip, remote port
type Tuple = (String, String, u16);

#[derive(Default)]
struct Tables {
    owners: HashMap<(String, String, u16, String, u16), HashSet<String>>,
    bindings: HashMap<Tuple, HashSet<String>>,
    totals: HashMap<String, [u64; 2]>,
    flows: HashMap<FlowKey, f64>,
    domains: HashMap<String, (String, f64)>,
    hellos: HashMap<(IpAddr, u16, IpAddr, u16), (Vec<u8>, f64)>,
}

pub struct Capture {
    tables: Mutex<Tables>,
    pub enabled: AtomicBool,
    running: Arc<AtomicBool>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    pub error: Mutex<Option<String>>,
    packets: AtomicU64,
    attributed: AtomicU64,
    server_names: AtomicU64,
    interfaces: AtomicU64,
}

pub struct Owner<'a> {
    pub app_id: &'a str,
    pub protocol: &'a str,
    pub local_ip: &'a str,
    pub local_port: u16,
    pub remote: Option<(&'a str, u16)>,
}

impl Capture {
    pub fn new() -> Arc<Capture> {
        Arc::new(Capture {
            tables: Mutex::default(),
            enabled: AtomicBool::new(false),
            running: Arc::new(AtomicBool::new(false)),
            threads: Mutex::default(),
            error: Mutex::default(),
            packets: AtomicU64::new(0),
            attributed: AtomicU64::new(0),
            server_names: AtomicU64::new(0),
            interfaces: AtomicU64::new(0),
        })
    }

    pub fn update_owners(&self, owners: &[Owner]) {
        let (mut by_tuple, mut bindings): (HashMap<_, HashSet<String>>, HashMap<Tuple, HashSet<String>>) = Default::default();
        for o in owners {
            let key = (o.protocol.to_string(), o.local_ip.to_string(), o.local_port);
            bindings.entry(key.clone()).or_default().insert(o.app_id.to_string());
            if let Some((ip, port)) = o.remote {
                by_tuple.entry((key.0, key.1, key.2, ip.to_string(), port)).or_default().insert(o.app_id.to_string());
            }
        }
        let mut t = self.tables.lock().unwrap();
        t.owners = by_tuple;
        t.bindings = bindings;
    }

    fn owner(t: &Tables, proto: &str, local: &str, lp: u16, remote: &str, rp: u16) -> Option<String> {
        let exact = t.owners.get(&(proto.into(), local.into(), lp, remote.into(), rp));
        if let Some(set) = exact.filter(|s| s.len() == 1) {
            return set.iter().next().cloned();
        }
        if proto == "UDP" {
            let mut candidates = HashSet::new();
            for addr in [local, "0.0.0.0", "::"] {
                if let Some(s) = t.bindings.get(&(proto.into(), addr.into(), lp)) {
                    candidates.extend(s.iter().cloned());
                }
            }
            if candidates.len() == 1 {
                return candidates.into_iter().next();
            }
        }
        None
    }

    /// Account one frame. `data` may be a header-only prefix; `full` returns the whole frame and is only
    /// called for DNS responses and TLS handshakes.
    pub fn handle(&self, dlt: i32, data: &[u8], full: &dyn Fn() -> Vec<u8>) {
        let Some(Packet { tcp, src, sport, dst, dport, size, l4 }) = pcap::parse(dlt, data) else { return };
        let now = now();
        let proto = if tcp { "TCP" } else { "UDP" };
        let mut answers = vec![];
        let mut sni = None;
        let mut t = self.tables.lock().unwrap();
        if !tcp && sport == pcap::DNS_PORT {
            answers = pcap::dns_answers(&full(), l4);
        } else if tcp {
            let flow = (src, sport, dst, dport);
            if let Some(start) = pcap::tcp_payload(data, l4).filter(|s| *s < data.len()) {
                if data[start] == 0x16 || t.hellos.contains_key(&flow) {
                    let frame = full();
                    let mut payload = frame.get(start..).unwrap_or_default().to_vec();
                    if let Some((head, _)) = t.hellos.remove(&flow) {
                        payload = [head, payload].concat();
                    }
                    if let Some((needed, name)) = pcap::client_hello(&payload) {
                        sni = name.clone();
                        if name.is_none() && needed > payload.len() && payload.len() < 16384 {
                            if t.hellos.len() > 256 {
                                t.hellos.retain(|_, v| now - v.1 < 5.0);
                            }
                            t.hellos.insert(flow, (payload, now));
                        }
                    }
                }
            }
        }
        self.packets.fetch_add(1, Ordering::Relaxed);
        let (s, d) = (src.to_string(), dst.to_string());
        let outbound = Self::owner(&t, proto, &s, sport, &d, dport);
        let inbound = Self::owner(&t, proto, &d, dport, &s, sport);
        if !(outbound.is_some() && inbound.is_some()) {
            // Local traffic can appear on multiple capture interfaces; count it nowhere.
            if let Some(app) = outbound.clone().or(inbound) {
                self.attributed.fetch_add(1, Ordering::Relaxed);
                t.totals.entry(app.clone()).or_default()[if outbound.is_some() { 0 } else { 1 }] += size as u64;
                let key = if outbound.is_some() { (app, proto.into(), s.clone(), sport, d.clone(), dport) } else { (app, proto.into(), d.clone(), dport, s.clone(), sport) };
                t.flows.insert(key, now);
            }
        }
        for (ip, name, ttl) in answers {
            t.domains.insert(ip.to_string(), (name, now + (ttl.clamp(60, 3600)) as f64));
        }
        if let Some(name) = sni {
            t.domains.insert(d, (name, now + 3600.0));
            self.server_names.fetch_add(1, Ordering::Relaxed);
        }
        if t.flows.len() > 10_000 {
            t.flows.retain(|_, v| now - *v < 10.0);
        }
        if t.domains.len() > 4096 {
            t.domains.retain(|_, v| v.1 > now);
            if t.domains.len() > 4096 {
                t.domains.clear();
            }
        }
    }

    pub fn snapshot(&self) -> (HashMap<String, [u64; 2]>, Vec<FlowKey>, HashMap<String, String>) {
        let now = now();
        let t = self.tables.lock().unwrap();
        (t.totals.clone(),
         t.flows.iter().filter(|(_, seen)| now - **seen < 8.0).map(|(k, _)| k.clone()).collect(),
         t.domains.iter().filter(|(_, v)| v.1 > now).map(|(k, v)| (k.clone(), v.0.clone())).collect())
    }

    pub fn start(self: &Arc<Self>) {
        if self.enabled.swap(true, Ordering::SeqCst) {
            return;
        }
        *self.error.lock().unwrap() = None;
        let result = (|| -> Result<(), String> {
            let lib = Arc::new(Pcap::load()?);
            let names = lib.interfaces()?;
            if names.is_empty() {
                return Err("No capturable network interfaces. Packet capture may require additional permissions.".into());
            }
            let mut handles = vec![];
            let mut failures = vec![];
            for name in &names {
                match lib.open(name) {
                    Ok(h) => handles.push(h),
                    Err(e) => failures.push(e),
                }
            }
            if handles.is_empty() {
                return Err(format!("Capture permission denied or unavailable: {}", failures.first().cloned().unwrap_or_default()));
            }
            self.interfaces.store(handles.len() as u64, Ordering::SeqCst);
            self.running.store(true, Ordering::SeqCst);
            let mut threads = self.threads.lock().unwrap();
            for h in handles {
                let (me, lib, running) = (self.clone(), lib.clone(), self.running.clone());
                threads.push(std::thread::Builder::new().name("beaver-capture".into()).spawn(move || {
                    let dlt = lib.datalink(&h);
                    while running.load(Ordering::SeqCst) {
                        match lib.next(&h) {
                            (1, Some((header, data))) => {
                                let caplen = header.caplen as usize;
                                // SAFETY: libpcap guarantees `caplen` readable bytes until the next pcap_next_ex call.
                                let frame = unsafe { std::slice::from_raw_parts(data, caplen) };
                                // Copy only the headers; the rest is read only for DNS and TLS handshakes.
                                me.handle(dlt, &frame[..caplen.min(128)], &|| frame.to_vec());
                            }
                            (r, _) if r < 0 => {
                                if running.load(Ordering::SeqCst) {
                                    *me.error.lock().unwrap() = Some(lib.error(&h).chars().take(300).collect());
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                    lib.free(&h);
                }).map_err(|e| e.to_string())?);
            }
            Ok(())
        })();
        if let Err(e) = result {
            log::warn!("Capture unavailable: {e}");
            *self.error.lock().unwrap() = Some(e.chars().take(300).collect());
        }
    }

    pub fn active(&self) -> bool {
        self.running.load(Ordering::SeqCst) && self.threads.lock().unwrap().iter().any(|t| !t.is_finished())
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({ "enabled": self.enabled.load(Ordering::SeqCst), "active": self.active(), "error": *self.error.lock().unwrap(),
                            "packets": self.packets.load(Ordering::Relaxed), "interfaces": self.interfaces.load(Ordering::Relaxed),
                            "attributed": self.attributed.load(Ordering::Relaxed), "server_names": self.server_names.load(Ordering::Relaxed),
                            "method": "IP-layer captured bytes; observed tuple ownership only" })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        // Readers notice within the 500 ms pcap timeout and close their own handles.
        for t in self.threads.lock().unwrap().drain(..) {
            let _ = t.join();
        }
        self.interfaces.store(0, Ordering::SeqCst);
        self.enabled.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::tests::{frame, hello};

    fn own<'a>(app: &'a str, proto: &'a str, remote: Option<(&'a str, u16)>, local_ip: &'a str) -> Owner<'a> {
        Owner { app_id: app, protocol: proto, local_ip, local_port: 50000, remote }
    }

    #[test]
    fn tuple_ownership_bytes_and_ambiguity() {
        let cap = Capture::new();
        cap.update_owners(&[own("a", "TCP", Some(("1.1.1.1", 443)), "192.168.1.2")]);
        let out = frame([192, 168, 1, 2], [1, 1, 1, 1], 50000, 443, 6, b"not retained", false);
        cap.handle(1, &out, &|| out.clone());
        let back = frame([1, 1, 1, 1], [192, 168, 1, 2], 443, 50000, 6, b"", true);
        cap.handle(1, &back, &|| back.clone());
        let (totals, flows, _) = cap.snapshot();
        assert!(totals["a"][0] == (out.len() - 14) as u64 && totals["a"][1] > 0 && flows.len() == 1);
        cap.update_owners(&[own("a", "TCP", Some(("1.1.1.1", 443)), "192.168.1.2"), own("b", "TCP", Some(("1.1.1.1", 443)), "192.168.1.2")]);
        let t = cap.tables.lock().unwrap();
        assert!(Capture::owner(&t, "TCP", "192.168.1.2", 50000, "1.1.1.1", 443).is_none());
    }

    #[test]
    fn udp_wildcard_binding_dns_and_split_sni() {
        let cap = Capture::new();
        cap.update_owners(&[own("a", "UDP", None, "0.0.0.0")]);
        assert_eq!(Capture::owner(&cap.tables.lock().unwrap(), "UDP", "192.168.1.2", 50000, "8.8.8.8", 53).as_deref(), Some("a"));
        let h = hello("split.example.net", 1600);
        let first = frame([192, 168, 1, 2], [1, 2, 3, 4], 50001, 443, 6, &h[..1200], false);
        let second = frame([192, 168, 1, 2], [1, 2, 3, 4], 50001, 443, 6, &h[1200..], false);
        cap.handle(1, &first[..128], &|| first.clone());
        assert!(cap.snapshot().2.is_empty());
        cap.handle(1, &second[..128], &|| second.clone());
        assert_eq!(cap.snapshot().2.get("1.2.3.4").map(String::as_str), Some("split.example.net"));
    }
}
