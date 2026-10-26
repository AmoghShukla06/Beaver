"""Minimal libpcap/Npcap binding and header parser. Reads only link, IP, TCP/UDP and DNS headers; never payloads."""
import ctypes
import ctypes.util
import os
import platform
import socket
import struct

ERRBUF = 256
IF_LOOPBACK, IF_UP = 0x1, 0x2
SKIP_LINUX = ("any", "lo", "nflog", "nfqueue", "dbus", "bluetooth", "usbmon")
DNS_PORT = 53

class Timeval(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("usec", ctypes.c_long)]

class PacketHeader(ctypes.Structure):
    _fields_ = [("ts", Timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]

class Address(ctypes.Structure):
    pass
Address._fields_ = [("next", ctypes.POINTER(Address)), ("addr", ctypes.c_void_p), ("netmask", ctypes.c_void_p),
                    ("broadaddr", ctypes.c_void_p), ("dstaddr", ctypes.c_void_p)]

class Interface(ctypes.Structure):
    pass
Interface._fields_ = [("next", ctypes.POINTER(Interface)), ("name", ctypes.c_char_p), ("description", ctypes.c_char_p),
                      ("addresses", ctypes.POINTER(Address)), ("flags", ctypes.c_uint32)]

class Program(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint), ("insns", ctypes.c_void_p)]

def load():
    """Return the pcap library or raise RuntimeError with an actionable message."""
    if platform.system() == "Windows":
        folder = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "Npcap")
        if not os.path.exists(os.path.join(folder, "wpcap.dll")):
            raise RuntimeError("Npcap is required for packet capture on Windows. Install it from https://npcap.com/, then restart Beaver.")
        os.add_dll_directory(folder)
        lib = ctypes.CDLL(os.path.join(folder, "wpcap.dll"))
    else:
        name = ctypes.util.find_library("pcap") or "libpcap.so.1"
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            try:
                lib = ctypes.CDLL("libpcap.so.0.8")
            except OSError:
                raise RuntimeError("libpcap is required for packet capture. Install libpcap (e.g. apt install libpcap0.8).") from None
    lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(Interface)), ctypes.c_char_p]
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(Interface)]
    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(Program), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(Program)]
    lib.pcap_freecode.argtypes = [ctypes.POINTER(Program)]
    lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(PacketHeader)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    lib.pcap_datalink.argtypes = [ctypes.c_void_p]
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    lib.pcap_breakloop.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p
    return lib

def interfaces(lib):
    devices = ctypes.POINTER(Interface)(); err = ctypes.create_string_buffer(ERRBUF)
    if lib.pcap_findalldevs(ctypes.byref(devices), err) != 0:
        raise RuntimeError("Capture interfaces unavailable: " + err.value.decode(errors="replace"))
    names = []; item = devices
    while item:
        dev = item.contents; name = dev.name.decode(errors="replace")
        if not dev.flags & IF_LOOPBACK and dev.addresses and not name.startswith(SKIP_LINUX) and (dev.flags & IF_UP or platform.system() == "Windows"):
            names.append(name)
        item = dev.next
    lib.pcap_freealldevs(devices)
    return names

def open_live(lib, name, snaplen=768, timeout_ms=500):
    err = ctypes.create_string_buffer(ERRBUF)
    handle = lib.pcap_open_live(name.encode(), snaplen, 0, timeout_ms, err)
    if not handle:
        raise RuntimeError(err.value.decode(errors="replace") or "Could not open " + name)
    program = Program()
    if lib.pcap_compile(handle, ctypes.byref(program), b"ip or ip6", 1, 0xffffffff) == 0:
        lib.pcap_setfilter(handle, ctypes.byref(program)); lib.pcap_freecode(ctypes.byref(program))
    return handle

def link_offset(dlt, data):
    """Offset of the IP header for a data-link type, or None when not IP."""
    if dlt == 1:  # Ethernet, with up to two VLAN tags
        off, ethertype = 14, struct.unpack_from("!H", data, 12)[0]
        while ethertype in (0x8100, 0x88a8) and len(data) >= off + 4:
            ethertype = struct.unpack_from("!H", data, off + 2)[0]; off += 4
        return off if ethertype in (0x0800, 0x86dd) else None
    if dlt in (0, 108):  # BSD loopback / Npcap loopback: 4-byte address family
        return 4
    if dlt == 113:  # Linux cooked v1
        return 16 if struct.unpack_from("!H", data, 14)[0] in (0x0800, 0x86dd) else None
    if dlt == 276:  # Linux cooked v2
        return 20 if struct.unpack_from("!H", data, 0)[0] in (0x0800, 0x86dd) else None
    if dlt in (12, 14, 101):  # raw IP
        return 0
    return None

def parse(dlt, data):
    """(protocol, src, sport, dst, dport, ip_length, l4_offset) or None. ip_length is the IP-layer size."""
    try:
        off = link_offset(dlt, data)
        if off is None or len(data) < off + 20:
            return None
        version = data[off] >> 4
        if version == 4:
            ihl = (data[off] & 15) * 4; total = struct.unpack_from("!H", data, off + 2)[0]
            if struct.unpack_from("!H", data, off + 6)[0] & 0x1fff:
                return None  # non-first fragment: no transport header
            proto = data[off + 9]; src = socket.inet_ntop(socket.AF_INET, bytes(data[off + 12:off + 16]))
            dst = socket.inet_ntop(socket.AF_INET, bytes(data[off + 16:off + 20])); l4 = off + ihl
        elif version == 6 and len(data) >= off + 40:
            total = 40 + struct.unpack_from("!H", data, off + 4)[0]; proto = data[off + 6]; l4 = off + 40
            src = socket.inet_ntop(socket.AF_INET6, bytes(data[off + 8:off + 24]))
            dst = socket.inet_ntop(socket.AF_INET6, bytes(data[off + 24:off + 40]))
            for _ in range(4):  # hop-by-hop, routing, destination options, fragment
                if proto in (0, 43, 60) and len(data) >= l4 + 2:
                    proto, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
                elif proto == 44 and len(data) >= l4 + 8:
                    proto, l4 = data[l4], l4 + 8
                else:
                    break
        else:
            return None
        if proto not in (6, 17) or len(data) < l4 + 4:
            return None
        sport, dport = struct.unpack_from("!HH", data, l4)
        return ("TCP" if proto == 6 else "UDP"), src, sport, dst, dport, total, l4
    except (struct.error, ValueError, IndexError):
        return None

def read_name(data, pos, limit=0):
    labels = []; jumped = False; end = pos
    for _ in range(64):
        length = data[pos]
        if length & 0xc0 == 0xc0:
            if not jumped:
                end = pos + 2
            pos = ((length & 0x3f) << 8) | data[pos + 1]; jumped = True
            continue
        if length == 0:
            return ".".join(labels).lower(), (end if jumped else pos + 1)
        labels.append(bytes(data[pos + 1:pos + 1 + length]).decode("ascii", "replace")); pos += 1 + length
    raise ValueError("DNS name loop")

def dns_answers(data, offset):
    """[(ip, question_name, ttl)] from a DNS response starting at the UDP header offset."""
    try:
        base = offset + 8
        flags, qd, an = struct.unpack_from("!HHH", data, base + 2)
        if not flags & 0x8000 or qd != 1:
            return []
        question, pos = read_name(data, base + 12); pos += 4
        answers = []
        for _ in range(min(an, 64)):
            _, pos = read_name(data, pos)
            rtype, _, ttl, size = struct.unpack_from("!HHIH", data, pos); pos += 10
            if rtype == 1 and size == 4:
                answers.append((socket.inet_ntop(socket.AF_INET, bytes(data[pos:pos + 4])), question[:253], ttl))
            elif rtype == 28 and size == 16:
                answers.append((socket.inet_ntop(socket.AF_INET6, bytes(data[pos:pos + 16])), question[:253], ttl))
            pos += size
        return answers
    except (struct.error, ValueError, IndexError):
        return []
