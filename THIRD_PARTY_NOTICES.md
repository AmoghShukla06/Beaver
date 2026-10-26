# Third-party notices

Beaver source code is licensed under Apache-2.0. Bundled components keep their own licenses.

## Bundled software

| Component | License |
|---|---|
| Electron (Chromium, Node.js) | MIT; ships its own third-party notices (`LICENSES.chromium.html`) |
| React, React DOM | MIT |
| lucide-react | ISC |
| d3-geo, topojson-client | ISC |
| world-atlas (Natural Earth geometry) | ISC packaging; Natural Earth data is public domain |
| Python (bundled interpreter) | PSF License |
| psutil | BSD-3-Clause |
| maxminddb | Apache-2.0 |
| PyInstaller bootloader | GPL-2.0 with bootloader exception (permits distribution of bundled apps under any license) |

## Not bundled (installed separately by the user)

- **Npcap** (Windows packet capture): Npcap license; free for personal use, redistribution restricted.
- **libpcap** (Linux): BSD-3-Clause, from the distribution.
- **GeoIP databases**: DB-IP City Lite (CC BY 4.0, attribution "IP Geolocation by DB-IP") when downloaded from Settings, or the user's own licensed MaxMind-format database.

## Threat-intelligence data

Feeds are downloaded at runtime to the user's device and never redistributed with Beaver.

| Feed | Terms |
|---|---|
| abuse.ch Feodo Tracker | https://abuse.ch/terms-of-use/ |
| Spamhaus DROP | https://www.spamhaus.org/blocklists/do-not-route-or-peer/ (see Spamhaus terms of use) |
| HaGeZi DNS Blocklists (Threat Intelligence Feeds) | GPL-3.0 data license, https://github.com/hagezi/dns-blocklists |
| Emerging Threats compromised IPs | https://rules.emergingthreats.net/ (BSD-style, Proofpoint) |
| IPsum | Unlicense, https://github.com/stamparm/ipsum |

This inventory is not a full SBOM or legal review. `package-lock.json` and `requirements.lock` identify resolved versions.
