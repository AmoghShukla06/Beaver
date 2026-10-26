//! Packet header parsing (link, IPv4/IPv6, TCP/UDP, DNS answers, TLS ClientHello SNI) and a
//! dynamically loaded libpcap/Npcap binding. Payload contents are never read beyond those headers.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DNS_PORT: u16 = 53;

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub tcp: bool,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    /// IP-layer length from the IP header.
    pub size: u32,
    /// Offset of the TCP/UDP header.
    pub l4: usize,
}

fn u16_at(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(i)?, *d.get(i + 1)?]))
}

/// Offset of the IP header for a data-link type, or None when the frame is not IP.
pub fn link_offset(dlt: i32, d: &[u8]) -> Option<usize> {
    match dlt {
        1 => {
            let (mut off, mut ethertype) = (14, u16_at(d, 12)?);
            while (ethertype == 0x8100 || ethertype == 0x88a8) && d.len() >= off + 4 {
                ethertype = u16_at(d, off + 2)?;
                off += 4;
            }
            (ethertype == 0x0800 || ethertype == 0x86dd).then_some(off)
        }
        0 | 108 => Some(4),
        113 => matches!(u16_at(d, 14)?, 0x0800 | 0x86dd).then_some(16),
        276 => matches!(u16_at(d, 0)?, 0x0800 | 0x86dd).then_some(20),
        12 | 14 | 101 => Some(0),
        _ => None,
    }
}

pub fn parse(dlt: i32, d: &[u8]) -> Option<Packet> {
    let off = link_offset(dlt, d)?;
    if d.len() < off + 20 {
        return None;
    }
    let (proto, src, dst, size, l4);
    match d[off] >> 4 {
        4 => {
            let ihl = ((d[off] & 15) as usize) * 4;
            if u16_at(d, off + 6)? & 0x1fff != 0 {
                return None; // non-first fragment: no transport header
            }
            proto = d[off + 9];
            src = IpAddr::V4(Ipv4Addr::new(d[off + 12], d[off + 13], d[off + 14], d[off + 15]));
            dst = IpAddr::V4(Ipv4Addr::new(d[off + 16], d[off + 17], d[off + 18], d[off + 19]));
            size = u16_at(d, off + 2)? as u32;
            l4 = off + ihl;
        }
        6 if d.len() >= off + 40 => {
            let mut p = d[off + 6];
            let mut at = off + 40;
            let a: [u8; 16] = d[off + 8..off + 24].try_into().ok()?;
            let b: [u8; 16] = d[off + 24..off + 40].try_into().ok()?;
            for _ in 0..4 {
                if matches!(p, 0 | 43 | 60) && d.len() >= at + 2 {
                    let (next, len) = (d[at], d[at + 1]);
                    p = next;
                    at += (len as usize + 1) * 8;
                } else if p == 44 && d.len() >= at + 8 {
                    p = d[at];
                    at += 8;
                } else {
                    break;
                }
            }
            proto = p;
            src = IpAddr::V6(Ipv6Addr::from(a));
            dst = IpAddr::V6(Ipv6Addr::from(b));
            size = 40 + u16_at(d, off + 4)? as u32;
            l4 = at;
        }
        _ => return None,
    }
    if !(proto == 6 || proto == 17) || d.len() < l4 + 4 {
        return None;
    }
    Some(Packet { tcp: proto == 6, src, sport: u16_at(d, l4)?, dst, dport: u16_at(d, l4 + 2)?, size, l4 })
}

pub fn tcp_payload(d: &[u8], l4: usize) -> Option<usize> {
    Some(l4 + ((*d.get(l4 + 12)? >> 4) as usize) * 4)
}

/// TLS ClientHello: (bytes the hello needs, server name). Needed > payload length means the hello
/// continues in a later segment. None when the payload is not a ClientHello.
pub fn client_hello(p: &[u8]) -> Option<(usize, Option<String>)> {
    if p.len() < 6 || p[0] != 0x16 || p[1] != 3 || p[5] != 1 {
        return None;
    }
    let needed = 5 + u16_at(p, 3)? as usize;
    let name = (|| {
        let mut pos = 5 + 4 + 2 + 32;
        pos += 1 + *p.get(pos)? as usize;
        pos += 2 + u16_at(p, pos)? as usize;
        pos += 1 + *p.get(pos)? as usize;
        let end = pos + 2 + u16_at(p, pos)? as usize;
        pos += 2;
        while pos + 4 <= end.min(p.len()) {
            let (kind, size) = (u16_at(p, pos)?, u16_at(p, pos + 2)? as usize);
            pos += 4;
            if kind == 0 && pos + 5 <= p.len() {
                let len = u16_at(p, pos + 3)? as usize;
                if p[pos + 2] == 0 && pos + 5 + len <= p.len() {
                    let name = String::from_utf8_lossy(&p[pos + 5..pos + 5 + len]).to_lowercase();
                    let name = name.trim_end_matches('.');
                    return name.contains('.').then(|| name.chars().take(253).collect());
                }
            }
            pos += size;
        }
        None
    })();
    Some((needed, name))
}

fn read_name(d: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let (mut labels, mut jumped, mut end) = (Vec::new(), false, pos);
    for _ in 0..64 {
        let len = *d.get(pos)?;
        if len & 0xc0 == 0xc0 {
            if !jumped {
                end = pos + 2;
            }
            pos = (((len & 0x3f) as usize) << 8) | *d.get(pos + 1)? as usize;
            jumped = true;
            continue;
        }
        if len == 0 {
            return Some((labels.join(".").to_lowercase(), if jumped { end } else { pos + 1 }));
        }
        labels.push(String::from_utf8_lossy(d.get(pos + 1..pos + 1 + len as usize)?).into_owned());
        pos += 1 + len as usize;
    }
    None
}

/// (ip, question name, ttl) from a DNS response whose UDP header starts at `l4`.
pub fn dns_answers(d: &[u8], l4: usize) -> Vec<(IpAddr, String, u32)> {
    (|| {
        let base = l4 + 8;
        let (flags, qd, an) = (u16_at(d, base + 2)?, u16_at(d, base + 4)?, u16_at(d, base + 6)?);
        if flags & 0x8000 == 0 || qd != 1 {
            return Some(vec![]);
        }
        let (question, mut pos) = read_name(d, base + 12)?;
        pos += 4;
        let question: String = question.chars().take(253).collect();
        let mut out = Vec::new();
        for _ in 0..an.min(64) {
            pos = read_name(d, pos)?.1;
            let kind = u16_at(d, pos)?;
            let ttl = u32::from_be_bytes(d.get(pos + 4..pos + 8)?.try_into().ok()?);
            let size = u16_at(d, pos + 8)? as usize;
            pos += 10;
            let data = d.get(pos..pos + size)?;
            match (kind, size) {
                (1, 4) => out.push((IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])), question.clone(), ttl)),
                (28, 16) => out.push((IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)), question.clone(), ttl)),
                _ => {}
            }
            pos += size;
        }
        Some(out)
    })()
    .unwrap_or_default()
}

// ---- libpcap / Npcap, loaded at runtime so Beaver starts without it -----------------------------

pub mod live {
    use libloading::{Library, Symbol};
    use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};

    #[repr(C)]
    struct Interface {
        next: *mut Interface,
        name: *const c_char,
        description: *const c_char,
        addresses: *mut c_void,
        flags: c_uint,
    }
    #[repr(C)]
    pub struct Header {
        ts_sec: std::ffi::c_long,
        ts_usec: std::ffi::c_long,
        pub caplen: u32,
        pub len: u32,
    }
    #[repr(C)]
    struct Program {
        len: c_uint,
        insns: *mut c_void,
    }

    pub struct Pcap {
        lib: Library,
    }
    pub struct Handle(pub *mut c_void);
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}

    const SKIP_LINUX: [&str; 7] = ["any", "lo", "nflog", "nfqueue", "dbus", "bluetooth", "usbmon"];

    impl Pcap {
        pub fn load() -> Result<Pcap, String> {
            #[cfg(windows)]
            {
                let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
                let dir = format!("{root}\\System32\\Npcap");
                let dll = format!("{dir}\\wpcap.dll");
                if !std::path::Path::new(&dll).exists() {
                    return Err("Npcap is required for packet capture on Windows. Install it from https://npcap.com/, then restart Beaver.".into());
                }
                // Packet.dll lives beside wpcap.dll; load it first so wpcap resolves it.
                let _ = unsafe { Library::new(format!("{dir}\\Packet.dll")) }.map(std::mem::forget);
                unsafe { Library::new(dll) }.map(|lib| Pcap { lib }).map_err(|e| e.to_string())
            }
            #[cfg(not(windows))]
            {
                for name in ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"] {
                    if let Ok(lib) = unsafe { Library::new(name) } {
                        return Ok(Pcap { lib });
                    }
                }
                Err("libpcap is required for packet capture. Install libpcap (e.g. apt install libpcap0.8).".into())
            }
        }

        pub fn interfaces(&self) -> Result<Vec<String>, String> {
            unsafe {
                let find: Symbol<unsafe extern "C" fn(*mut *mut Interface, *mut c_char) -> c_int> =
                    self.lib.get(b"pcap_findalldevs").map_err(|e| e.to_string())?;
                let free: Symbol<unsafe extern "C" fn(*mut Interface)> = self.lib.get(b"pcap_freealldevs").map_err(|e| e.to_string())?;
                let mut devices: *mut Interface = std::ptr::null_mut();
                let mut err = [0 as c_char; 256];
                if find(&mut devices, err.as_mut_ptr()) != 0 {
                    return Err(format!("Capture interfaces unavailable: {}", CStr::from_ptr(err.as_ptr()).to_string_lossy()));
                }
                let mut names = vec![];
                let mut item = devices;
                while !item.is_null() {
                    let dev = &*item;
                    let name = CStr::from_ptr(dev.name).to_string_lossy().into_owned();
                    let up = dev.flags & 0x2 != 0 || cfg!(windows);
                    if dev.flags & 0x1 == 0 && !dev.addresses.is_null() && up && !SKIP_LINUX.iter().any(|s| name.starts_with(s)) {
                        names.push(name);
                    }
                    item = dev.next;
                }
                free(devices);
                Ok(names)
            }
        }

        pub fn open(&self, name: &str) -> Result<Handle, String> {
            unsafe {
                let open: Symbol<unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void> =
                    self.lib.get(b"pcap_open_live").map_err(|e| e.to_string())?;
                let compile: Symbol<unsafe extern "C" fn(*mut c_void, *mut Program, *const c_char, c_int, u32) -> c_int> =
                    self.lib.get(b"pcap_compile").map_err(|e| e.to_string())?;
                let setfilter: Symbol<unsafe extern "C" fn(*mut c_void, *mut Program) -> c_int> = self.lib.get(b"pcap_setfilter").map_err(|e| e.to_string())?;
                let freecode: Symbol<unsafe extern "C" fn(*mut Program)> = self.lib.get(b"pcap_freecode").map_err(|e| e.to_string())?;
                let c_name = CString::new(name).map_err(|e| e.to_string())?;
                let mut err = [0 as c_char; 256];
                let handle = open(c_name.as_ptr(), 2048, 0, 500, err.as_mut_ptr());
                if handle.is_null() {
                    return Err(CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned());
                }
                let mut program = Program { len: 0, insns: std::ptr::null_mut() };
                let filter = CString::new("ip or ip6").unwrap();
                if compile(handle, &mut program, filter.as_ptr(), 1, 0xffff_ffff) == 0 {
                    setfilter(handle, &mut program);
                    freecode(&mut program);
                }
                Ok(Handle(handle))
            }
        }

        pub fn datalink(&self, h: &Handle) -> i32 {
            unsafe { self.lib.get::<unsafe extern "C" fn(*mut c_void) -> c_int>(b"pcap_datalink").map(|f| f(h.0)).unwrap_or(1) }
        }

        /// 1 = packet, 0 = timeout, negative = error/end. Blocks up to the open timeout.
        pub fn next<'a>(&self, h: &Handle) -> (i32, Option<(&'a Header, *const u8)>) {
            unsafe {
                let Ok(next) = self.lib.get::<unsafe extern "C" fn(*mut c_void, *mut *mut Header, *mut *const u8) -> c_int>(b"pcap_next_ex") else {
                    return (-1, None);
                };
                let mut header: *mut Header = std::ptr::null_mut();
                let mut data: *const u8 = std::ptr::null();
                let r = next(h.0, &mut header, &mut data);
                if r == 1 && !header.is_null() {
                    (1, Some((&*header, data)))
                } else {
                    (r, None)
                }
            }
        }

        pub fn error(&self, h: &Handle) -> String {
            unsafe {
                self.lib
                    .get::<unsafe extern "C" fn(*mut c_void) -> *const c_char>(b"pcap_geterr")
                    .map(|f| CStr::from_ptr(f(h.0)).to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "Capture stopped".into())
            }
        }

        pub fn free(&self, h: &Handle) {
            unsafe {
                if let Ok(f) = self.lib.get::<unsafe extern "C" fn(*mut c_void)>(b"pcap_close") {
                    f(h.0)
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, proto: u8, payload: &[u8], vlan: bool) -> Vec<u8> {
        let mut l4 = vec![];
        l4.extend(sport.to_be_bytes());
        l4.extend(dport.to_be_bytes());
        if proto == 6 {
            l4.extend([0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        } else {
            l4.extend(((8 + payload.len()) as u16).to_be_bytes());
            l4.extend([0, 0]);
        }
        l4.extend(payload);
        let mut f = vec![0u8; 12];
        if vlan {
            f.extend([0x81, 0, 0, 7]);
        }
        f.extend([8, 0, 0x45, 0]);
        f.extend(((20 + l4.len()) as u16).to_be_bytes());
        f.extend([0, 0, 0, 0, 64, proto, 0, 0]);
        f.extend(src);
        f.extend(dst);
        f.extend(l4);
        f
    }

    pub fn hello(name: &str, padding: usize) -> Vec<u8> {
        let sni = name.as_bytes();
        let mut server_name = vec![];
        server_name.extend(((sni.len() + 3) as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend((sni.len() as u16).to_be_bytes());
        server_name.extend(sni);
        let mut ext = vec![];
        if padding > 0 {
            ext.extend(21u16.to_be_bytes());
            ext.extend((padding as u16).to_be_bytes());
            ext.extend(vec![0; padding]);
        }
        ext.extend(0u16.to_be_bytes());
        ext.extend((server_name.len() as u16).to_be_bytes());
        ext.extend(server_name);
        let mut body = vec![3, 3];
        body.extend([0x11; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(ext);
        let mut hs = vec![1];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn parses_ipv4_tcp_with_vlan() {
        let f = frame([192, 168, 1, 2], [1, 1, 1, 1], 50000, 443, 6, b"x", true);
        let p = parse(1, &f).unwrap();
        assert!(p.tcp && p.sport == 50000 && p.dport == 443 && p.dst.to_string() == "1.1.1.1");
        assert_eq!(p.size as usize, f.len() - 18);
    }

    #[test]
    fn parses_ipv6_raw_and_rejects_garbage() {
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v6.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend("2606:4700::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend([0x14, 0xe9, 0, 53, 0, 8, 0, 0]);
        let p = parse(101, &v6).unwrap();
        assert!(!p.tcp && p.src.to_string() == "2001:db8::1" && p.dport == 53);
        assert!(parse(1, &[0; 13]).is_none() && parse(1, &[0xff; 60]).is_none() && parse(999, &v6).is_none());
    }

    #[test]
    fn dns_answers_with_compression_and_garbage() {
        let mut dns = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for l in "Evil.Example.com".split('.') {
            dns.push(l.len() as u8);
            dns.extend(l.as_bytes());
        }
        dns.extend([0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 9, 9, 9, 9]);
        let f = frame([8, 8, 8, 8], [192, 168, 1, 2], 53, 5000, 17, &dns, false);
        let p = parse(1, &f).unwrap();
        assert_eq!(dns_answers(&f, p.l4), vec![("9.9.9.9".parse().unwrap(), "evil.example.com".into(), 300)]);
        let bad = frame([8, 8, 8, 8], [192, 168, 1, 2], 53, 5000, 17, &[0, 1, 0x81, 0x80, 0, 1, 0, 5, 0xc0, 0x0c], false);
        assert!(dns_answers(&bad, parse(1, &bad).unwrap().l4).is_empty());
    }

    #[test]
    fn tls_server_name() {
        assert_eq!(client_hello(&hello("Login.Example.org", 0)).unwrap().1.as_deref(), Some("login.example.org"));
        assert!(client_hello(&[0x17, 3, 3, 0, 16]).is_none());
        let h = hello("split.example.net", 1600);
        let (needed, name) = client_hello(&h[..1200]).unwrap();
        assert!(needed > 1200 && name.is_none());
    }
}
