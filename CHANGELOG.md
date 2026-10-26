# Changelog

## 1.2.0

### Polish
- Real application icons in the app list, investigations and notifications.
- New brand mark (shield with beaver teeth) across the app icon, tray and sidebar.
- Much shorter UI copy; caveats moved to docs. No "Settings saved" toasts; actions report their own result ("Session ended…").
- System, idle and ownerless sockets are grouped in one collapsible row. Score chips only appear at Medium and above.
- Relative times ("3 min ago") throughout.
- The sidebar shows the real version.

### Reliability and support
- Local rotating logs for the service and the app (errors and lifecycle only), plus *Open logs*.
- Settings → About: version, update status, *Check for updates* / *Restart to update*, *Copy diagnostics* (usernames and IPs redacted), release notes, licenses and issue links.
- "What's new" banner after an update.
- Windows uninstaller offers to remove Beaver's firewall rules (never during auto-update).
- Linux: firewall rules applied before the last reboot are shown as inactive with *Re-apply*, since nftables runtime rules do not survive a restart.

### Fixes
- Dialog backdrops rendered mirrored under software compositing; the blur has been removed.

## 1.1.0

### New
- **First-run setup**: three steps for start at sign-in, packet capture (detects Npcap/libpcap and links to it), and notifications with a test button.
- **New-app alerts**: one notification the first time a program reaches the internet, with publisher and destination. Existing apps are learned silently for 10 minutes; Windows components are skipped. *New apps* alert filter.
- **Notification buttons** (Windows): *End session* on remote-access alerts, *Block app* on High risk and new apps, *Looks fine* to acknowledge.
- **Website names from TLS**: the server name in the TLS handshake is read during capture, so HTTPS sites are named even when DNS is encrypted. Handshakes split across segments are reassembled.
- **Auto-update** from GitHub Releases (Windows installer, AppImage), with a tray *Restart to update* item and a setting to turn it off.

### Performance
- Capture copies only the first 128 bytes of each frame; full frames only for DNS and TLS handshakes.
- Sampling slows to 4 s on battery when no window is open.

## 1.0.0

### Detection
- Six local threat feeds (Feodo C2, Spamhaus DROP v4/v6, HaGeZi threat domains, Emerging Threats, IPsum) totalling 225k+ indicators, with CIDR and domain-suffix matching, per-feed freshness and toggles.
- Remote access and data-theft shield: 40+ remote-control tools, internet logins to RDP/VNC/SSH/WinRM/SMB, exposed remote-login services, reverse shells, netcat-style tools, Telegram-bot and file-sharing exfiltration, lopsided uploads.
- Identity checks: Authenticode status and publisher, tampered or untrusted signatures, process masquerading, staging-folder executables, Linux fileless, deleted and `/dev/shm` executables.
- Behavior: living-off-the-land binaries, document-spawned tools, C2 beaconing, RAT and Tor ports, port and endpoint fan-out. MITRE ATT&CK mapping for every rule.
- Inbound scanner hits are discounted; a valid publisher signature reduces behavioral points only.

### Response
- End session / End process with PID and start-time verification and protected-process refusal.
- Remote access lockdown: one inbound firewall rule for Telnet, RDP, VNC, TeamViewer direct and WinRM ports.
- Opt-in Active protection that stops unsigned programs showing confirmed High-risk behavior.
- Firewall rule verification against the OS; missing rules can be re-applied.

### Notifications and tray
- Push-based alerts (no polling), burst coalescing, remote-access alerts always on, optional Medium notifications, pause for 1 hour from the tray, click-through to the exact investigation, persistent critical toasts, alert tray icon and taskbar badge.
- Alerts deduplicate by evidence for 12 hours and escalate when new evidence appears. Acknowledge all.
- Start at login (Windows login item, Linux XDG autostart) in tray-only mode.
- Automatic restart of the monitoring service if it crashes (bounded).

### Performance
- Monitoring service idle CPU reduced from 7.8% to about 1% of one core; per-sample cost from 165 ms to 24 ms (10 ms without a window).
- Closing to tray unloads the renderer; GPU acceleration is disabled. Tray-mode memory is about 280 MB, down from about 650 MB.
- Scapy replaced by a native libpcap/Npcap binding (25× faster start, about 5 MB overhead); geoip2 replaced by maxminddb. The Python bundle and dependency tree are much smaller.
- Incremental SQLite writes, below-normal process priority, slow RPCs off the request loop.

### UI
- New Remote shield and Connections pages, risk distribution strip, sortable application table with scores and signature badges, executable panel (publisher, SHA-256, VirusTotal lookup, parent process, first seen), evidence with ATT&CK links, alert filters and responses, feed list, new settings.

### Licensing
- Removed the GPL-2.0 Scapy dependency from the Apache-2.0 distribution.
