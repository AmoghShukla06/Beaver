# Detection

Beaver scores each network-active application every 2 seconds with deterministic, explainable rules (`backend/risk.py`). Every rule records its points, a human explanation, the legitimate reasons it can fire, and a MITRE ATT&CK technique where one applies.

## Score composition

```
score = threat_intel + max(0, behavior − publisher_trust) + remote_exposure      (capped at 100)
```

| Level | Score | Meaning |
|---|---|---|
| High | 80–100 | Strong evidence. Always recorded and notified. |
| Medium | 30–79 | Deserves review. Recorded; notified if *Also notify for Medium risk* is on, or if it involves remote access. |
| Low | 0–29 | Nothing strong is observable. Not a safety guarantee. |
| Unknown | — | Executable unknown, fewer than 3 observations, or no fresh threat feed. |

- **Threat intelligence** is never suppressed by an allowlist. The strongest hit per endpoint counts; each additional malicious endpoint adds 5, up to 15 more.
- **Behavior** is suppressed by an application allowlist and reduced by 10 when the executable has a valid Authenticode signature.
- **Remote exposure** is suppressed by an allowlist but **not** reduced by a signature, because the remote-access tools abused in scams are legitimately signed.

## Threat intelligence

Feeds are downloaded over HTTPS with host-pinned redirects, size limits and schema validation, then matched in memory. Stale feeds stop producing matches. Indicators that only appear on **inbound** connections to a listening port (typically internet scanners) are discounted to a quarter, unless the feed is strong enough to raise High on its own.

| Feed | Type | Points | Refresh / stale after |
|---|---|---|---|
| abuse.ch Feodo Tracker (recommended) | Botnet C2 IPs | 90 | 1 h / 6 h |
| Spamhaus DROP v4 + v6 | Hijacked/criminal networks (CIDR) | 80 | 12 h / 4 d |
| HaGeZi Threat Intelligence (mini) | Malware, phishing, C2 domains | 80 | 12 h / 4 d |
| Emerging Threats compromised IPs | Compromised hosts | 45 | 12 h / 4 d |
| IPsum level 4 | IPs on 4+ blocklists | 40 | 12 h / 4 d |

Domain matching uses observed DNS answers (packet capture) and, where the OS permits, the Windows DNS client cache. A listed domain also matches its subdomains. Domains are stored as 64-bit hashes in a sorted array (about 1.7 MB for 212k domains).

## Rules

### Remote access and data theft

| Rule | Points | ATT&CK | Fires when | Legitimate explanation |
|---|---|---|---|---|
| `remote-access-tool` | 30 | T1219 | A known remote-control tool (40+ products) has a live internet connection | You or your IT team use it; allowlist it |
| `inbound-remote-login` | 80 | T1021 | A public IP is connected to a local RDP/VNC/SSH/Telnet/WinRM/SMB listener | You intentionally expose remote login |
| `exposed-remote-service` | 15 | T1133 | A remote-login service listens on a non-loopback address | LAN administration |
| `reverse-shell` | 70 | T1059 | `cmd.exe`, `bash`, `sh` or another shell itself holds an internet socket | Very rare |
| `raw-network-tool` | 40 | T1059 | `nc`, `ncat`, `socat` or `telnet` holds an internet socket | Admin testing |
| `exfil-channel` | 20–35 | T1567 | A non-browser app talks to the Telegram Bot API, anonymous file-sharing, paste sites, webhook.site or quick tunnels | Bots, scripts, backups |
| `upload-volume` | 20 | T1041 | More than 200 MB sent and more than 8× download this session (capture) | Backups, cloud sync, video calls |

### Identity and integrity

| Rule | Points | ATT&CK | Fires when |
|---|---|---|---|
| `masquerading` | 60 | T1036.005 | A protected Windows process name (`svchost.exe`, `lsass.exe`, `explorer.exe` …) runs outside its only legitimate folder, or a kernel-thread name has a user-space executable on Linux |
| `tampered-signature` | 50 | T1554 | The Authenticode hash does not match the file |
| `untrusted-signature` | 20 | T1553.002 | Signed by a certificate that does not chain to a trusted root |
| `unsigned` | 10 | — | No Authenticode signature (Windows) |
| `verified-publisher` | −10 | — | Valid signature; reduces behavioral points only |
| `temporary-executable` | 20 | T1204.002 | Runs from Temp, Downloads, Public or the Recycle Bin, or `/tmp`, `/var/tmp`, `~/.cache` |
| `shared-memory-executable` | 40 | T1620 | Runs from `/dev/shm` |
| `fileless` | 60 | T1620 | Linux `memfd:` executable |
| `deleted-executable` | 45 | T1070.004 | Linux executable deleted while running |

### Network behavior

| Rule | Points | ATT&CK | Fires when |
|---|---|---|---|
| `lolbin-network` | 15–35 | T1218 / T1059.001 | `mshta`, `regsvr32`, `certutil`, `bitsadmin`, `msbuild`, `rundll32`, script hosts or PowerShell contact a public IP |
| `document-spawned` | 40 | T1204.002 | Such a tool was started by Word, Excel, Outlook, a PDF reader and so on, and contacts the internet |
| `beaconing` | 25 | T1071 | 6+ new TCP connections to one endpoint at a steady 20 s–1 h interval (jitter ≤ max(3 s, 15%)) |
| `suspicious-port` | 20 | T1571 | Outbound to Metasploit, Quasar, njRAT, AsyncRAT, DarkComet, IRC or backdoor default ports |
| `tor-port` | 15 | T1090.003 | Outbound to default Tor relay ports from a non-Tor app |
| `port-fanout` | 35 | T1046 | 30+ ports on one remote host at once |
| `endpoint-fanout` | 20 | — | 100+ simultaneous remote IPs |

Geography never contributes to risk.

## Alerts

- High and Medium assessments create alerts. Deduplication key: application + level + significant rules (≥ 15 points), plus endpoints for threat-intel evidence. The same evidence is recorded once per 12 hours; new evidence escalates immediately.
- Medium alerts wait until executable inspection finishes, so a late signature result cannot create a duplicate.
- The service pushes each alert to the desktop process, which coalesces bursts into one notification every 8 seconds.

## Active protection

Off by default. When on, a **High** alert for an app that is **not validly signed** and **not an OS binary**, with at least one of `reverse-shell`, `masquerading`, `fileless`, `tampered-signature`, a threat-intel match, or `exfil-channel`, terminates that app's processes. The PID and process start time are re-verified first. Beaver itself, PID 0/4 and core Windows processes are always refused. The alert records the outcome and the notification says what happened.

## Evaluating changes

Every rule has unit tests in `tests/test_core.py`, including negative cases: LAN versus internet, Telegram's own client, browsers and file-sharing, the real `svchost` path, and timing jitter. A rule change must include its false-positive explanation and a test.
