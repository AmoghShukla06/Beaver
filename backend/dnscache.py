"""Read-only view of the Windows DNS client cache. Never sends a DNS query on the wire."""
import ctypes
import ipaddress
import platform
from ctypes import wintypes

DNS_QUERY_NO_WIRE_QUERY = 0x10
DNS_FREE_FLAT, DNS_FREE_RECORD_LIST = 0, 1

class CacheEntry(ctypes.Structure):
    pass
CacheEntry._fields_ = [("next", ctypes.POINTER(CacheEntry)), ("name", ctypes.c_void_p),
                       ("type", wintypes.WORD), ("length", wintypes.WORD), ("flags", wintypes.DWORD)]

class RecordData(ctypes.Union):
    _fields_ = [("raw", ctypes.c_ubyte * 16), ("pointer", ctypes.c_void_p)]  # pointer member forces native union alignment

class Record(ctypes.Structure):
    pass
Record._fields_ = [("next", ctypes.POINTER(Record)), ("name", wintypes.LPWSTR), ("type", wintypes.WORD),
                   ("length", wintypes.WORD), ("flags", wintypes.DWORD), ("ttl", wintypes.DWORD),
                   ("reserved", wintypes.DWORD), ("data", RecordData)]

class DnsCache:
    def __init__(self):
        self.api = None; self.error = None
        if platform.system() != "Windows":
            self.error = "DNS cache reading is available on Windows only"
            return
        try:
            api = ctypes.WinDLL("dnsapi")
            api.DnsGetCacheDataTable.argtypes = [ctypes.POINTER(ctypes.POINTER(CacheEntry))]
            api.DnsGetCacheDataTable.restype = wintypes.BOOL
            api.DnsQuery_W.argtypes = [wintypes.LPCWSTR, wintypes.WORD, wintypes.DWORD, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.POINTER(Record)), ctypes.c_void_p]
            api.DnsQuery_W.restype = ctypes.c_long
            api.DnsFree.argtypes = [ctypes.c_void_p, ctypes.c_int]
            api.DnsFree.restype = None
            self.api = api
        except (OSError, AttributeError) as exc:
            self.error = str(exc)[:200]

    def names(self):
        head = ctypes.POINTER(CacheEntry)()
        if not self.api.DnsGetCacheDataTable(ctypes.byref(head)):
            return []
        result = set(); entry = head
        while entry:
            item = entry.contents; following = item.next
            if item.name:
                result.add(ctypes.wstring_at(item.name)); self.api.DnsFree(item.name, DNS_FREE_FLAT)
            self.api.DnsFree(ctypes.addressof(item), DNS_FREE_FLAT)
            entry = following
        return list(result)[:4096]

    def read(self):
        """Return {ip: domain} from cached A/AAAA answers. Errors leave the mapping empty."""
        if not self.api:
            return {}
        mapping = {}
        try:
            for name in self.names():
                if len(name) > 253 or name.endswith((".local", ".arpa", ".lan")):
                    continue
                for qtype in (1, 28):
                    records = ctypes.POINTER(Record)()
                    if self.api.DnsQuery_W(name, qtype, DNS_QUERY_NO_WIRE_QUERY, None, ctypes.byref(records), None):
                        continue
                    record = records
                    while record:
                        item = record.contents
                        if item.type == 1:
                            mapping[str(ipaddress.IPv4Address(bytes(item.data.raw[:4])))] = name.lower()
                        elif item.type == 28:
                            mapping[str(ipaddress.IPv6Address(bytes(item.data.raw[:16])))] = name.lower()
                        record = item.next
                    self.api.DnsFree(records, DNS_FREE_RECORD_LIST)
            self.error = None
        except (OSError, ValueError) as exc:
            self.error = str(exc)[:200]
        return mapping
