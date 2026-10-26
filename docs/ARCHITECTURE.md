# Architecture

## Processes and trust boundaries

```text
React UI in the system WebView (WebView2 / WebKitGTK; strict CSP, no remote content)
  └─ Tauri IPC: one capability, a fixed command allowlist, navigation limited to the app origin
Tauri shell, Rust (tray, notifications with actions, login item, updater, exe icons, dialogs)
  └─ private line-delimited JSON over stdin/stdout (requests + pushed events)
beaver-service, Rust (current user, below-normal priority)
  ├─ socket inventory every 2 s (netstat2) + process identity (sysinfo) + interface counters
  ├─ optional libpcap/Npcap capture (loaded at runtime): headers, DNS answers, TLS server name (SNI)
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
- **GPU acceleration is disabled** in WebView2. The UI is static SVG and tables.
- **Cheap identity checks.** A PID's start time is read directly (`GetProcessTimes` / `/proc/<pid>/stat`); the full process refresh runs only for new or reused PIDs. A sample costs about 8 ms.
- **Interface counters** come from `GetIfTable2Ex` (raw table, no per-interface queries) or `/proc/net/dev`, and are read every third sample while no window is visible.
- **Incremental persistence.** New connections are inserted immediately, ended ones are closed, and live rows are checkpointed every 30 s.
- **Battery-aware sampling**: 4 s instead of 2 s while on battery with no window open.
- **Slow RPCs** (feed refresh, firewall prompts, downloads) run on worker threads so snapshots never stall. A service panic exits with code 70 and the shell restarts it (at most 5 times in 10 minutes).
- The service sets `BELOW_NORMAL_PRIORITY_CLASS` (Windows) or `nice 10` (Linux).

## Attribution

Applications are grouped by executable path. PID plus process start time distinguishes lifetimes and guards termination. Ownerless/PID 0 sockets are "Unattributed". Capture joins packet 5-tuples to the latest socket inventory. UDP can join a unique local binding. Ambiguous tuples and local flows with two owners are not counted.

## Capture

`service/src/pcap.rs` loads `wpcap.dll` / `libpcap.so` at runtime and binds `pcap_findalldevs`, `pcap_open_live`, `pcap_compile/setfilter` (`ip or ip6`) and `pcap_next_ex`, one reader thread per interface (500 ms timeout). Without the library, Beaver runs without capture. It parses Ethernet (VLAN/QinQ), BSD/Npcap loopback, Linux cooked v1/v2 and raw IP; IPv4 (fragment-aware) and IPv6 (extension headers); TCP/UDP ports; and DNS responses (A/AAAA with name compression and loop protection). Byte counts are IP-layer lengths from the IP header. Each frame is copied as a 128-byte prefix; the full frame (snaplen 2048) is copied only for DNS responses and TLS handshakes. ClientHello records split across two segments are reassembled per flow (bounded to 256 pending flows, 16 KB, 5 s).

## Risk and alerts

See [DETECTION.md](DETECTION.md). Risk is a pure function of the app, its connections, feed matches and context (binary inspection, listening ports, beacon timings, capture totals, parent process). Failed samples keep the last good inventory instead of falsely closing every socket.

## Firewall

- **Windows:** Beaver creates exact program, IP or inbound-port Block rules named `Beaver-<hash>-In/Out` in group `Beaver`. A fixed, literal-escaped PowerShell script is base64-encoded and elevated through UAC once per action, and partial failures roll back.
- **Linux:** a dedicated `inet beaver_<hash>` nftables table per rule, applied atomically through `pkexec nft -f -`. Removal deletes only that table. No ruleset flush or policy change.
- The rule journal is written before mutation. `verify_rules` reconciles with the OS (Windows reads rules unprivileged; Linux needs root) and marks missing rules. Missing rules can be re-applied.
- **Remote access lockdown** is one inbound TCP rule for ports 23, 3389, 5900–5903, 5938, 5985 and 5986. SSH is deliberately excluded to avoid locking out servers.

## Packaging and updates

Tauri bundles the shell with `beaver-service` as a sidecar: an NSIS installer on Windows (`packaging/installer.nsi`, Tauri's template plus Beaver's welcome, startup, finish and uninstall pages), and a .deb and AppImage on Linux (`packaging/linux/postinst.sh`, `postrm.sh`).

The updater checks GitHub Releases 30 s after start and every 6 hours. On Windows it downloads the `-setup.exe`, refuses it unless its SHA-256 matches the release's `SHA256SUMS.txt`, and offers *Restart to update*, which runs the installer silently with `/UPDATE` (rules, data and the startup choice are kept). On Linux it links to the release page. Debug builds and test profiles never check.

Releases are built by `.github/workflows/release.yml` on Windows and Ubuntu 22.04 (for glibc compatibility) when a `v*` tag is pushed.
