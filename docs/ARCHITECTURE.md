# Architecture

## Processes and trust boundaries

```text
React renderer (sandboxed, no Node, strict CSP, no remote content)
  └─ narrow preload bridge; main process validates sender frame and URL
Electron main (tray, notifications, login item, firewall/dialog brokering)
  └─ private line-delimited JSON over stdin/stdout (requests + pushed events)
Python service (current user, below-normal priority)
  ├─ psutil socket inventory every 2 s + interface counters
  ├─ optional libpcap/Npcap header capture (ctypes, no payloads)
  ├─ Windows DNS client cache (read-only, cache-only queries)
  ├─ executable inspector: SHA-256 + Authenticode (batched PowerShell), cached per path/size/mtime
  ├─ threat feeds: 6 HTTPS sources → in-memory sets, CIDR ranges, domain-hash array
  ├─ risk engine (pure rules) → alerts (dedup, escalation) → pushed events
  ├─ bounded SQLite (WAL): connections, alerts, rules journal, allowlist, binaries, settings
  ├─ local MaxMind-format City database (maxminddb)
  └─ per-action OS authorization → Windows Defender Firewall / nftables
```

The installed app has no HTTP service or listening socket. The Vite preview (`npm run dev`) is development-only, loopback-only, read-only, and checks Host/Origin/fetch-site.

## Background efficiency

- **No polling when hidden.** The service pushes `alert` and `status` events. The main process updates the tray, badge and notifications from them. The renderer polls `snapshot` only while it is visible.
- **The window is destroyed, not hidden**, when closed to the tray. Launch at login uses `--hidden` and creates no renderer at all.
- **GPU acceleration is disabled.** The UI is static SVG and tables, and this saves about 100 MB in a long-lived process.
- **Identity caching.** `psutil.create_time()` falls back to a full process snapshot (~4 ms) for protected processes, so those PIDs are revalidated every 30 s and fast ones every sample.
- **Interface counters** (~25 ms on Windows) are read every third sample while no window is visible.
- **Incremental persistence.** New connections are inserted immediately, ended ones are closed, and live rows are checkpointed every 30 s.
- **Slow RPCs** (feed refresh, firewall prompts, downloads) run on worker threads so snapshots never stall.
- The service sets `BELOW_NORMAL_PRIORITY_CLASS` (Windows) or `nice 10` (Linux).

## Attribution

Applications are grouped by executable path. PID plus process start time distinguishes lifetimes and guards termination. Ownerless/PID 0 sockets are "Unattributed". Capture joins packet 5-tuples to the latest socket inventory. UDP can join a unique local binding. Ambiguous tuples and local flows with two owners are not counted.

## Capture

`backend/pcap.py` binds `pcap_findalldevs`, `pcap_open_live`, `pcap_compile/setfilter` (`ip or ip6`) and `pcap_next_ex` with ctypes, one reader thread per interface (snaplen 768, 500 ms timeout; the GIL is released while waiting). It parses Ethernet (VLAN/QinQ), BSD/Npcap loopback, Linux cooked v1/v2 and raw IP; IPv4 (fragment-aware) and IPv6 (extension headers); TCP/UDP ports; and DNS responses (A/AAAA with name compression and loop protection). Byte counts are IP-layer lengths from the IP header.

## Risk and alerts

See [DETECTION.md](DETECTION.md). Risk is a pure function of the app, its connections, feed matches and context (binary inspection, listening ports, beacon timings, capture totals, parent process). Failed samples keep the last good inventory instead of falsely closing every socket.

## Firewall

- **Windows:** Beaver creates exact program, IP or inbound-port Block rules named `Beaver-<hash>-In/Out` in group `Beaver`. A fixed, literal-escaped PowerShell script is base64-encoded and elevated through UAC once per action, and partial failures roll back.
- **Linux:** a dedicated `inet beaver_<hash>` nftables table per rule, applied atomically through `pkexec nft -f -`. Removal deletes only that table. No ruleset flush or policy change.
- The rule journal is written before mutation. `verify_rules` reconciles with the OS (Windows reads rules unprivileged; Linux needs root) and marks missing rules. Missing rules can be re-applied.
- **Remote access lockdown** is one inbound TCP rule for ports 23, 3389, 5900–5903, 5938, 5985 and 5986. SSH is deliberately excluded to avoid locking out servers.

## Packaging

PyInstaller builds a one-folder `beaver-service`, which electron-builder ships under `resources/backend`. Releases are built by `.github/workflows/release.yml` on Windows and Ubuntu 22.04 (for glibc compatibility) when a `v*` tag is pushed. The workflow publishes the NSIS installer, AppImage, .deb and SHA-256 sums.
