//! Read-only view of the Windows DNS client cache. Uses cache-only queries; never sends DNS on the wire.
use std::collections::HashMap;

pub struct DnsCache {
    pub available: bool,
    pub error: Option<String>,
}

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::Dns::{DnsFree, DnsFreeFlat, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_NO_WIRE_QUERY, DNS_RECORDW};

    #[repr(C)]
    struct CacheEntry {
        next: *mut CacheEntry,
        name: *mut u16,
        kind: u16,
        length: u16,
        flags: u32,
    }

    fn wide_to_string(p: *const u16) -> String {
        let mut len = 0;
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// Names in the cache via the undocumented (but long-stable) DnsGetCacheDataTable export.
    fn names() -> Result<Vec<String>, String> {
        let lib = unsafe { libloading::Library::new("dnsapi.dll") }.map_err(|e| e.to_string())?;
        let table: libloading::Symbol<unsafe extern "system" fn(*mut *mut CacheEntry) -> i32> =
            unsafe { lib.get(b"DnsGetCacheDataTable") }.map_err(|e| e.to_string())?;
        let mut head: *mut CacheEntry = std::ptr::null_mut();
        if unsafe { table(&mut head) } == 0 {
            return Ok(vec![]); // empty, or reading the cache needs elevation on recent Windows 11 builds
        }
        let mut out = vec![];
        let mut entry = head;
        while !entry.is_null() && out.len() < 4096 {
            unsafe {
                let next = (*entry).next;
                if !(*entry).name.is_null() {
                    out.push(wide_to_string((*entry).name));
                    DnsFree((*entry).name as _, DnsFreeFlat);
                }
                DnsFree(entry as _, DnsFreeFlat);
                entry = next;
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    pub fn read() -> Result<HashMap<String, String>, String> {
        let mut map = HashMap::new();
        for name in names()? {
            if name.len() > 253 || name.ends_with(".local") || name.ends_with(".arpa") || name.ends_with(".lan") {
                continue;
            }
            let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
            for kind in [1u16, 28] {
                let mut records: *mut DNS_RECORDW = std::ptr::null_mut();
                let status = unsafe { DnsQuery_W(wide.as_ptr(), kind, DNS_QUERY_NO_WIRE_QUERY, std::ptr::null_mut(), &mut records as *mut _ as _, std::ptr::null_mut()) };
                if status != 0 {
                    continue;
                }
                let mut r = records;
                while !r.is_null() {
                    unsafe {
                        match (*r).wType {
                            1 => {
                                let ip = (*r).Data.A.IpAddress;
                                map.insert(Ipv4Addr::from(ip.to_ne_bytes()).to_string(), name.to_lowercase());
                            }
                            28 => {
                                let bytes = (*r).Data.AAAA.Ip6Address.IP6Byte;
                                map.insert(Ipv6Addr::from(bytes).to_string(), name.to_lowercase());
                            }
                            _ => {}
                        }
                        r = (*r).pNext;
                    }
                }
                unsafe { DnsFree(records as _, DnsFreeRecordList) };
            }
        }
        Ok(map)
    }
}

impl DnsCache {
    pub fn new() -> DnsCache {
        if cfg!(windows) {
            DnsCache { available: true, error: None }
        } else {
            DnsCache { available: false, error: Some("DNS cache reading is available on Windows only".into()) }
        }
    }

    /// {ip: domain} from cached A/AAAA answers. Errors leave the mapping empty.
    pub fn read(&mut self) -> HashMap<String, String> {
        #[cfg(windows)]
        {
            match imp::read() {
                Ok(m) => {
                    self.error = None;
                    m
                }
                Err(e) => {
                    self.error = Some(e.chars().take(200).collect());
                    HashMap::new()
                }
            }
        }
        #[cfg(not(windows))]
        HashMap::new()
    }
}
