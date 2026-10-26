//! Address helpers. std's `IpAddr::is_global` is unstable, so the public-address test lives here.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_global(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 shared address space
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240)
}

fn v6_global(a: Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return v4_global(v4);
    }
    let s = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link local
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x2001 && s[1] < 0x0200) // IETF protocol assignments
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // discard-only
        || (s[0] == 0x64 && s[1] == 0xff9b)) // NAT64
}

pub fn is_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_global(*a),
        IpAddr::V6(a) => v6_global(*a),
    }
}

pub fn public(ip: &str) -> bool {
    ip.parse::<IpAddr>().map(|a| is_global(&a)).unwrap_or(false)
}

/// One integer key space for both families (IPv4 as IPv4-mapped IPv6).
pub fn key(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u128::from(a.to_ipv6_mapped()),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => u128::from(v4.to_ipv6_mapped()),
            None => u128::from(*a),
        },
    }
}

/// (first, last) addresses of a CIDR block in the `key` space, with its prefix length.
pub fn cidr(text: &str) -> Option<(u128, u128, u8, IpAddr)> {
    let (addr, prefix) = text.trim().split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let (bits, base) = match addr {
        IpAddr::V4(_) if prefix <= 32 => (prefix as u32 + 96, key(&addr)),
        IpAddr::V6(a) if prefix <= 128 => (prefix as u32, u128::from(a)),
        _ => return None,
    };
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    let first = base & mask;
    Some((first, first | !mask, prefix, addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn global_ranges() {
        for p in ["1.1.1.1", "45.33.32.156", "2606:4700:4700::1111"] {
            assert!(public(p), "{p}");
        }
        for p in ["10.0.0.1", "192.168.1.9", "127.0.0.1", "100.64.1.1", "203.0.113.9", "224.0.0.251", "::1", "fe80::1", "fd00::1", "2001:db8::1", "::ffff:10.0.0.1", "junk"] {
            assert!(!public(p), "{p}");
        }
        let (a, b, n, _) = cidr("1.10.16.0/20").unwrap();
        assert_eq!((b - a, n), (4095, 20));
        assert!(cidr("1.2.3.4/33").is_none());
    }
}
