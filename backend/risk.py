"""Transparent, deterministic rules, not malware verdicts. Geography never contributes to risk.

Threat-intelligence evidence is never suppressed by an allowlist. Behavioral evidence is suppressed by an
application allowlist and reduced by a verified publisher signature. Every rule documents a benign explanation."""
import functools
import ipaddress
import os
import platform
from collections import defaultdict

from .binaries import location

SYSTEM_ROOT = os.environ.get("SystemRoot", "C:\\Windows").replace("\\", "/").lower().rstrip("/")
SYS32, WOW64 = SYSTEM_ROOT + "/system32", SYSTEM_ROOT + "/syswow64"
# Windows binaries malware commonly impersonates, and the only directories they ship from.
PROTECTED = {name: (SYS32,) for name in ("lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
                                         "services.exe", "lsm.exe", "spoolsv.exe", "searchindexer.exe", "fontdrvhost.exe")}
PROTECTED |= {name: (SYS32, WOW64) for name in ("svchost.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe",
                                                "rundll32.exe", "regsvr32.exe", "taskmgr.exe", "wmiprvse.exe", "sihost.exe")}
PROTECTED["explorer.exe"] = (SYSTEM_ROOT, WOW64)
LINUX_KERNEL_NAMES = ("kworker", "kthreadd", "ksoftirqd", "migration", "rcu_", "kswapd", "watchdog")
# Signed system tools that download or execute remote content (living-off-the-land binaries).
LOLBINS = {"mshta.exe": 35, "regsvr32.exe": 35, "certutil.exe": 35, "bitsadmin.exe": 30, "installutil.exe": 35,
           "msbuild.exe": 30, "wscript.exe": 30, "cscript.exe": 30, "rundll32.exe": 30, "regasm.exe": 30,
           "regsvcs.exe": 30, "msxsl.exe": 35, "cmstp.exe": 35, "powershell.exe": 15, "pwsh.exe": 15}
RAT_PORTS = {4444: "Metasploit default", 1604: "DarkComet default", 4782: "Quasar RAT default", 5552: "njRAT default",
             6606: "AsyncRAT default", 7707: "AsyncRAT default", 8808: "AsyncRAT default", 1337: "common backdoor",
             31337: "common backdoor", 6667: "IRC (legacy botnet C2)", 6668: "IRC (legacy botnet C2)", 6669: "IRC (legacy botnet C2)"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
          "visio.exe", "acrord32.exe", "acrobat.exe", "wordpad.exe", "hwp.exe"}
TOR_PORTS = {9001, 9030, 9050, 9051, 9150}
QUIET_PORTS = {53, 123, 5353, 1900}
# Remote-control software: legitimate support tools that are also the primary instrument of tech-support scams.
REMOTE_TOOLS = {"anydesk": "AnyDesk", "teamviewer": "TeamViewer", "teamviewer_service": "TeamViewer", "tv_w32": "TeamViewer",
                "tv_x64": "TeamViewer", "rustdesk": "RustDesk", "screenconnect.clientservice": "ConnectWise ScreenConnect",
                "screenconnect.windowsclient": "ConnectWise ScreenConnect", "srservice": "Splashtop", "strwinclt": "Splashtop",
                "tvnserver": "TightVNC", "winvnc": "UltraVNC", "vncserver": "VNC server", "vncserver-x11": "RealVNC",
                "x11vnc": "x11vnc", "x0vncserver": "TigerVNC", "ateraagent": "Atera", "client32": "NetSupport Manager",
                "rutserv": "Remote Utilities", "rfusclient": "Remote Utilities", "aa_v3": "Ammyy Admin", "ammyy_admin": "Ammyy Admin",
                "supremo": "Supremo", "supremoservice": "Supremo", "lmiguardian": "LogMeIn", "logmein": "LogMeIn",
                "remotepcservice": "RemotePC", "remoting_host": "Chrome Remote Desktop", "rserver3": "Radmin", "dwagent": "DWService",
                "getscreen": "Getscreen.me", "meshagent": "MeshCentral", "quickassist": "Windows Quick Assist",
                "msra": "Windows Remote Assistance", "ngrok": "ngrok tunnel", "ultraviewer": "UltraViewer",
                "ultraviewer_service": "UltraViewer", "zohoassist": "Zoho Assist", "aeroadmin": "AeroAdmin", "romserver": "LiteManager",
                "simplehelp": "SimpleHelp", "iperiusremote": "Iperius Remote", "hoptodesk": "HopToDesk"}
REMOTE_PORTS = {22: "SSH", 23: "Telnet", 3389: "Remote Desktop (RDP)", 5900: "VNC", 5901: "VNC", 5902: "VNC", 5903: "VNC",
                5938: "TeamViewer", 5985: "WinRM", 5986: "WinRM", 7070: "AnyDesk"}
INBOUND_SENSITIVE = REMOTE_PORTS | {445: "SMB file sharing", 135: "Windows RPC", 139: "NetBIOS"}
SHELLS = {"cmd.exe", "bash", "sh", "dash", "zsh", "ksh", "fish", "ash", "busybox", "bash.exe", "sh.exe"}
NET_TOOLS = {"nc", "ncat", "netcat", "socat", "nc.exe", "ncat.exe", "nc64.exe", "socat.exe", "telnet", "telnet.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "chrome",
            "chromium", "firefox", "firefox-bin", "brave", "opera", "vivaldi-bin", "msedge", "librewolf", "waterfox", "arc.exe", "zen.exe"}
EXFIL_DOMAINS = {"api.telegram.org": ("Telegram Bot API", 35), "transfer.sh": ("transfer.sh file sharing", 25),
                 "file.io": ("file.io file sharing", 25), "gofile.io": ("GoFile file sharing", 25), "anonfiles.com": ("AnonFiles", 25),
                 "bashupload.com": ("bashupload", 25), "temp.sh": ("temp.sh file sharing", 25), "catbox.moe": ("Catbox file sharing", 25),
                 "0x0.st": ("0x0.st file sharing", 25), "uguu.se": ("Uguu file sharing", 25), "filebin.net": ("Filebin", 25),
                 "pastebin.com": ("Pastebin", 20), "paste.ee": ("Paste.ee", 20), "webhook.site": ("webhook.site", 25),
                 "ngrok.io": ("ngrok tunnel", 20), "ngrok-free.app": ("ngrok tunnel", 20), "trycloudflare.com": ("Cloudflare quick tunnel", 20)}
MESSENGERS = ("telegram", "ayugram", "kotatogram", "unigram", "64gram")

def remote_tool(name):
    key = (name or "").lower().removesuffix(".exe")
    return REMOTE_TOOLS.get(key) or next((v for k, v in REMOTE_TOOLS.items() if len(k) > 5 and key.startswith(k)), None)

def exfil_channel(domain):
    domain = (domain or "").lower()
    return next((v for k, v in EXFIL_DOMAINS.items() if domain == k or domain.endswith("." + k)), None)

@functools.lru_cache(maxsize=8192)
def public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except (TypeError, ValueError):
        return False

def beacon(starts):
    """Mean interval when new connections start on a steady schedule (low jitter), else None."""
    if len(starts) < 6:
        return None
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    mean = sum(gaps) / len(gaps)
    if not 20 <= mean <= 3600:
        return None
    deviation = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** .5
    return mean if deviation <= max(3, .15 * mean) else None

def masquerade(name, path, system):
    if not name or not path:
        return None
    n = name.lower(); p = path.replace("\\", "/").lower(); folder = p.rsplit("/", 1)[0]
    if system == "Windows" and n in PROTECTED and folder not in PROTECTED[n]:
        return f"{name} normally runs only from {PROTECTED[n][0].replace('/', chr(92))}, but this copy runs from {path}."
    if system == "Linux" and n.startswith(LINUX_KERNEL_NAMES):
        return f"{name} is a kernel-thread name, but this process has a user-space executable at {path}."
    return None

def rule(evidence, rule_id, points, title, detail, category, technique=None, **extra):
    evidence.append({"rule": rule_id, "points": points, "title": title, "detail": detail, "category": category,
                     "technique": technique} | extra)
    return points

def assess(app, connections, intelligence, observations=0, allowlisted=False, allowed_endpoints=None, context=None):
    context = context or {}; system = context.get("system") or platform.system()
    allowed_endpoints = allowed_endpoints or set(); evidence = []
    listening = context.get("listening") or set()
    binary = context.get("binary") or {}
    name = app.get("name") or ""; lname = name.lower(); path = app.get("path")

    # 1. Threat intelligence: strongest hit per endpoint; additional malicious endpoints add a little.
    per_endpoint = {}
    for c in connections:
        ip = c.get("remote_ip")
        if not ip or ip in per_endpoint or not public(ip):
            continue
        hits = intelligence.match(ip) + intelligence.match_domain(c.get("domain"))
        if not hits:
            continue
        best = max(hits, key=lambda h: h["points"])
        inbound = (c.get("protocol"), c.get("local_port")) in listening
        points = best["points"] if not inbound or best["points"] >= 80 else best["points"] // 4
        per_endpoint[ip] = (points, best, inbound, c, hits)
    ranked = sorted(per_endpoint.items(), key=lambda kv: -kv[1][0])
    intel_score = ranked[0][1][0] + min(15, 5 * (len(ranked) - 1)) if ranked else 0
    for ip, (points, best, inbound, c, hits) in ranked[:5]:
        target = best["value"]
        lists = ", ".join(sorted({h["name"] for h in hits}))
        rule(evidence, "intel-domain" if target != ip else "known-c2" if best["feed"] == "feodo" else "threat-intel",
             points, best["category"] + (" (inbound)" if inbound and points < best["points"] else ""),
             f"{target}{' (' + ip + ')' if target != ip else ''} is listed by {lists}. "
             + ("The remote host connected to a listening port, which usually indicates scanning rather than compromise. " if inbound else "")
             + "A list match is evidence for investigation, not proof that this application is malicious.",
             "intel", "T1071", source=best["source"], endpoint=ip, feeds=[h["feed"] for h in hits])

    behavior = 0; trust = 0; exposure = 0; product = remote_tool(name)
    if not allowlisted:
        # 2. Remote control and data theft. A valid signature does not reduce these: abused tools are signed.
        public_live = [c for c in connections if c.get("remote_ip") and public(c["remote_ip"])
                       and c.get("status") in ("ESTABLISHED", "OBSERVED", "SYN_SENT")]
        if product and public_live:
            exposure += rule(evidence, "remote-access-tool", 30, f"Remote-control software is connected ({product})",
                             f"{product} lets another person see and control this computer. If you did not start it yourself, especially after an "
                             "unexpected call, pop-up or message asking you to install it, end the session now and change your passwords. "
                             f"If you use {product} intentionally, allowlist it.", "remote", "T1219", endpoint=public_live[0]["remote_ip"])
        inbound_remote = next((c for c in public_live if c.get("protocol") == "TCP" and (c["protocol"], c.get("local_port")) in listening
                               and c.get("local_port") in INBOUND_SENSITIVE), None)
        if inbound_remote:
            service = INBOUND_SENSITIVE[inbound_remote["local_port"]]
            exposure += rule(evidence, "inbound-remote-login", 80, f"{service} session from the internet",
                             f"{inbound_remote['remote_ip']} is connected to the {service} service on port {inbound_remote['local_port']}. "
                             "Unless you expected a remote login from that address, someone outside your network may be accessing this computer. "
                             "Disconnect it and block the port from Firewall.", "remote", "T1021", endpoint=inbound_remote["remote_ip"])
        exposed = sorted({c["local_port"] for c in connections if c.get("status") == "LISTEN" and c.get("local_port") in REMOTE_PORTS
                          and not str(c.get("local_ip", "")).startswith(("127.", "::1"))})
        if exposed:
            exposure += rule(evidence, "exposed-remote-service", 15, "Remote-access service is reachable from the network",
                             "Listening on " + ", ".join(f"{p} ({REMOTE_PORTS[p]})" for p in exposed) + ". Attackers scan for these services. "
                             "Use Remote access lockdown in Firewall if you do not need incoming remote logins.", "remote", "T1133", ports=exposed)
        shell_link = next((c for c in public_live if (c.get("protocol"), c.get("local_port")) not in listening), None)
        if shell_link and lname in SHELLS:
            exposure += rule(evidence, "reverse-shell", 70, "Command shell connected directly to the internet",
                             f"{name} holds a network connection to {shell_link['remote_ip']}:{shell_link['remote_port']}. Shells do not normally open "
                             "sockets themselves; this is the signature of a reverse shell that gives an attacker interactive control.",
                             "remote", "T1059", endpoint=shell_link["remote_ip"])
        elif shell_link and lname in NET_TOOLS:
            exposure += rule(evidence, "raw-network-tool", 40, f"{name} is connected to the internet",
                             f"{name} can pipe a command shell over the network. Administrators also use it for testing.",
                             "remote", "T1059", endpoint=shell_link["remote_ip"])
        if lname not in BROWSERS:
            for c in connections:
                channel = exfil_channel(c.get("domain"))
                if channel and not (channel[0].startswith("Telegram") and lname.startswith(MESSENGERS)):
                    behavior += rule(evidence, "exfil-channel", channel[1], f"Sends data to {channel[0]}",
                                     f"{c['domain']} ({c['remote_ip']}) is a service infostealers use to upload stolen passwords, cookies and files. "
                                     "Some bots, scripts and backup tools use it legitimately.", "exfil", "T1567", endpoint=c["remote_ip"])
                    break

        # 3. Identity and integrity.
        detail = masquerade(name, path, system)
        if detail:
            behavior += rule(evidence, "masquerading", 60, "Impersonates a Windows system process" if system == "Windows" else "Impersonates a kernel thread",
                             detail + " Malware commonly copies trusted process names to hide.", "identity", "T1036.005")
        if context.get("fileless"):
            behavior += rule(evidence, "fileless", 60, "Runs from an in-memory file", "The executable is an anonymous memory file (memfd), "
                             "a technique used to run code without writing it to disk. Some sandboxes and JIT runtimes also do this.", "identity", "T1620")
        elif context.get("deleted"):
            behavior += rule(evidence, "deleted-executable", 45, "Executable was deleted while running",
                             "The program file no longer exists on disk. Malware deletes itself to hinder analysis; package upgrades can also cause this briefly.", "identity", "T1070.004")
        signature = binary.get("signature")
        if signature == "tampered":
            behavior += rule(evidence, "tampered-signature", 50, "Digital signature does not match the file",
                             "The file was modified after it was signed. This indicates tampering or corruption.", "identity", "T1554")
        elif signature == "untrusted":
            behavior += rule(evidence, "untrusted-signature", 20, "Signed by an untrusted certificate",
                             "The signing certificate does not chain to a trusted root. Self-signed developer builds also look like this.", "identity", "T1553.002")
        elif signature == "unsigned":
            behavior += rule(evidence, "unsigned", 10, "No digital signature",
                             "The executable is not Authenticode-signed. This is common for open-source, scripting and developer tools.", "identity")
        elif signature == "valid" and binary.get("publisher"):
            trust = 10
            rule(evidence, "verified-publisher", -10, "Verified publisher: " + binary["publisher"],
                 "The Authenticode signature is valid. Signed software can still be abused, so this only reduces behavioral signals.", "trust")
        where = binary.get("location") or (location(path, system) if path else None)
        if where == "memory":
            behavior += rule(evidence, "shared-memory-executable", 40, "Runs from shared memory (/dev/shm)",
                             "Executables in /dev/shm leave no persistent file. Legitimate software rarely does this.", "identity", "T1620")
        elif where == "staging":
            behavior += rule(evidence, "temporary-executable", 20, "Runs from a temporary or download folder",
                             "A network-active executable is in temporary or download storage. Installers and portable apps also run from these locations.", "identity", "T1204.002")

        # 4. Network behavior on non-allowlisted, public endpoints.
        outbound = [c for c in connections if c.get("remote_ip") and c["remote_ip"] not in allowed_endpoints
                    and (c.get("protocol"), c.get("local_port")) not in listening]
        ports = defaultdict(set)
        for c in connections:
            if c.get("remote_ip") and c["remote_ip"] not in allowed_endpoints:
                ports[c["remote_ip"]].add(c["remote_port"])
        if any(len(p) >= 30 for p in ports.values()):
            behavior += rule(evidence, "port-fanout", 35, "Unusual port fan-out",
                             "At least 30 distinct ports on one endpoint are observable at once. Scanners and development tools can legitimately do this.", "behavior", "T1046")
        if len(ports) >= 100:
            behavior += rule(evidence, "endpoint-fanout", 20, "Many simultaneous destinations",
                             "At least 100 distinct remote IPs are observable. Browsers, peer-to-peer clients and update tools can legitimately do this.", "behavior")
        public_out = [c for c in outbound if public(c["remote_ip"])]
        if lname in LOLBINS and public_out:
            behavior += rule(evidence, "lolbin-network", LOLBINS[lname], f"{name} is contacting the internet",
                             f"{name} is a built-in Windows tool that attackers use to download or run remote code. "
                             f"Observed endpoint: {public_out[0]['remote_ip']}:{public_out[0]['remote_port']}. Administrators and scripts also use it.",
                             "behavior", "T1218" if LOLBINS[lname] >= 30 else "T1059.001", endpoint=public_out[0]["remote_ip"])
        parent = (context.get("parent") or "").lower()
        if parent in OFFICE and (lname in LOLBINS or lname in ("mshta.exe", "wscript.exe", "cscript.exe")) and public_out:
            behavior += rule(evidence, "document-spawned", 40, f"Started by {context['parent']} and contacting the internet",
                             f"{name} was launched by a document application. Malicious documents use this to download a second stage. "
                             "Some macros and add-ins do this legitimately.", "behavior", "T1204.002")
        rat = next((c for c in public_out if c.get("remote_port") in RAT_PORTS), None)
        if rat:
            behavior += rule(evidence, "suspicious-port", 20, "Connects to a port associated with remote-access malware",
                             f"{rat['remote_ip']}:{rat['remote_port']} uses the {RAT_PORTS[rat['remote_port']]} port. Some games and services reuse these ports.",
                             "behavior", "T1571", endpoint=rat["remote_ip"])
        tor = next((c for c in public_out if c.get("remote_port") in TOR_PORTS), None)
        if tor and not lname.startswith(("tor", "firefox")):
            behavior += rule(evidence, "tor-port", 15, "Connects to a Tor relay port",
                             f"{tor['remote_ip']}:{tor['remote_port']} is a default Tor port. Malware uses Tor to hide its command server; privacy tools use it legitimately.",
                             "behavior", "T1090.003", endpoint=tor["remote_ip"])
        steady = []
        for (ip, port), starts in (context.get("beacons") or {}).items():
            if ip in allowed_endpoints or port in QUIET_PORTS or not public(ip):
                continue
            interval = beacon(starts)
            if interval:
                steady.append((ip, port, interval))
        if steady:
            ip, port, interval = steady[0]
            behavior += rule(evidence, "beaconing", 25, "Contacts a server on a fixed schedule",
                             f"New connections to {ip}:{port} start every {interval:.0f} seconds with very little variation. "
                             "Malware beacons to command servers this way; update checks and telemetry can too.", "behavior", "T1071", endpoint=ip)
        totals = context.get("totals")
        if totals and totals[0] > 200 * 1024 * 1024 and totals[0] > 8 * (totals[1] + 1):
            behavior += rule(evidence, "upload-volume", 20, "Uploads far more than it downloads",
                             f"{totals[0] / 1048576:.0f} MB sent versus {totals[1] / 1048576:.0f} MB received this session. "
                             "Backups, cloud sync and video calls also upload heavily.", "behavior", "T1041")

    score = min(100, intel_score + max(0, behavior - trust) + exposure)
    if score >= 80:
        level = "High"
    elif score >= 30:
        level = "Medium"
    elif not path or observations < 3 or not intelligence.fresh():
        level = "Unknown"
    else:
        level = "Low"
    strongest = max((e for e in evidence if e["points"] > 0), key=lambda e: e["points"], default=None)
    reason = {"High": "Strong threat evidence needs investigation.",
              "Medium": "Behavior deserves review; legitimate explanations are possible.",
              "Low": "No strong signals in the observable activity. This is not a safety guarantee.",
              "Unknown": "Insufficient identity, observation time, or fresh threat intelligence to assess confidently."}[level]
    if strongest and level in ("High", "Medium"):
        reason += " Strongest signal: " + strongest["title"] + "."
    return {"level": level, "score": score if level != "Unknown" else None, "evidence": evidence, "reason": reason,
            "allowlisted": allowlisted, "intel_score": intel_score, "behavior_score": max(0, behavior - trust) + exposure,
            "remote_tool": product}
