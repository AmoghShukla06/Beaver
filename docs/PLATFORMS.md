# Platform setup

## Windows

Windows 10/11 x64, standard user account.

- **Packet capture:** install [Npcap](https://npcap.com/) (keep "WinPcap API-compatible mode" unchecked; the default is fine). It enables per-app speeds and domain names from DNS answers. If Npcap was installed with "restrict to administrators", capture reports an access error. Npcap is licensed separately and is not bundled.
- **Signatures:** Authenticode status and publisher are read with `Get-AuthenticodeSignature`, which includes catalog-signed system files. One batched PowerShell process runs per group of newly seen executables, and results are cached.
- **DNS cache:** Beaver reads the DNS client cache with cache-only queries. Recent Windows 11 builds restrict this to administrators, in which case domains come from capture only.
- **Firewall:** each change triggers UAC. Cancelling is never reported as success. Rules outlive the app; the uninstaller offers to remove them (group `Beaver` in Windows Defender Firewall).
- **Notifications:** Focus Assist / Do Not Disturb can hide them. Use *Send test notification* in Settings. Installed builds register the `org.beaver.security` AppUserModelID through the Start-menu shortcut.
- **Start at login** uses the standard Run-key login item with `--hidden`. The installer's *Start Beaver when I sign in* box is applied on first launch.
- **Uninstall** from *Settings → Apps*. The uninstaller asks whether to remove Beaver's firewall rules and whether to delete your data (`%APPDATA%\Beaver`). Installing 2.0 removes Beaver 1.x automatically and keeps its history, settings and rules.

## Linux

Ubuntu 22.04+, Debian 12+, Fedora 38+ and similar x64 desktops (X11 or Wayland).

```bash
sudo apt install libpcap0.8 nftables policykit-1      # Debian/Ubuntu
sudo dnf install libpcap nftables polkit                # Fedora
```

- **Tray:** GNOME needs the AppIndicator extension. Without a tray, closing the window quits Beaver.
- **Socket visibility:** without root, the kernel hides the owners of other users' sockets. Those appear as *Unattributed sockets*. Your own apps are fully visible.
- **Packet capture without root:** grant the bundled service raw-socket capability once. This applies to the .deb install; AppImages mount read-only, so use the .deb for capture.
  ```bash
  sudo setcap cap_net_raw+ep /usr/bin/beaver-service
  ```
  Grant it only to `beaver-service`, never to the `beaver` UI, and don't run the UI as root.
- **Firewall:** endpoint and inbound-port rules use nftables through `pkexec`, so a polkit agent must be running. Executable-path blocking is not available in nftables. Beaver deliberately does not substitute UID-wide blocks.
- **Rule verification** requires root, so on a normal desktop the recorded state reflects the last successful action. nftables rules added at runtime do not survive a reboot. Beaver marks rules applied before the last boot as *inactive* and offers *Re-apply*.
- **Fileless and deleted executables** are detected through `/proc/<pid>/exe`.
- **Start at login** writes `~/.config/autostart/Beaver.desktop`.
- **Uninstall:** `sudo apt remove beaver` deletes Beaver's nftables tables and autostart entries. Your history stays in `~/.config/Beaver`; use *Settings → About → Delete data* first if you want it gone.

Build Linux packages on Linux (`npm run tauri:build`) with `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev` and `librsvg2-dev` installed.

## Geolocation

Use *Download free City database* (DB-IP City Lite, CC BY 4.0, about 130 MB once a month) or choose any MaxMind-format City `.mmdb`. Country-only databases are rejected. Private and reserved IPs stay unlocated. Natural Earth borders are illustrative, not a legal determination.
