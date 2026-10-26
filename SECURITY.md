# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security → Report a vulnerability). Do not open public issues containing exploits, connection histories, hashes of private files or credentials. Reports are acknowledged as soon as a maintainer is available. There is no paid SLA.

## What Beaver is and is not

Beaver is a network-behavior monitor with threat intelligence and response actions. It is **not** a signature antivirus, it does not inspect file contents for malware, and it cannot see inside encrypted traffic. *Low risk* and an empty alert list do not prove a computer is uncompromised.

## Threat model

**Protected against:** renderer command abuse; remote content gaining Node privileges; malformed or hostile feed content; command injection into firewall scripts; accidental broad blocks; stale intelligence producing false High alerts; misattributed process termination.

**Trusted:** the OS account, the kernel, the installed Beaver files and their provenance. Same-user malware can tamper with Beaver's history, settings and process. SQLite is not encrypted by Beaver; use full-disk encryption.

## Controls

- Electron sandbox, context isolation, no Node integration, CSP, denied navigation, popups, permissions and webviews. IPC accepts only the trusted main frame at the expected URL, with a fixed method allowlist and size limits.
- External links open only for an allowlist of documentation, feed and VirusTotal-hash URLs.
- Service RPC over private stdio; no listening sockets.
- Feeds use HTTPS with certificate verification, host-pinned redirects, size limits and schema validation. Public-address checks reject poisoned private or reserved entries.
- Firewall: validated IP literals and digit-only port lists, single-quoted PowerShell literals, base64-encoded fixed scripts, per-action UAC or polkit, a journal before mutation, verification, and rollback on partial failure. Beaver only modifies its own named rules and tables.
- Termination re-verifies PID and process start time and refuses Beaver itself, PID 0/4 and core Windows processes. Active protection never stops validly signed or OS binaries.
- Packet capture parses headers only and never stores payloads or packet objects.

## Known gaps

- Installers are not yet code-signed and builds are not reproducible.
- Linux elevation authorizes `nft` itself rather than a constrained helper.
- Linux capture without root relies on a file capability the user grants.
- Detection quality has been unit-tested and validated live, but has not been evaluated on a labelled malware corpus.
