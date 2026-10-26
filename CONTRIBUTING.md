# Contributing

Thanks for helping make Beaver better.

1. Read [README.md](README.md), [SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DETECTION.md](docs/DETECTION.md), [DESIGN.md](DESIGN.md) and [UX-CONTRACT.md](UX-CONTRACT.md).
2. Set up from source (see README) and run `npm run test:service`, `npm run typecheck`, `npm run build` and, for UI or desktop changes, `npm run tauri:debug` then `npm run test:app`.
3. Test against real socket activity and real failure paths.

## Rules of the road

- Synthetic fixtures belong only in tests, never in production fallbacks. Missing data shows as "—", never as an estimate.
- Do not widen the Tauri capability or command allowlist, relax the CSP, add arbitrary shell IPC, upload observed endpoints, score countries, or estimate per-app rates from interface totals.
- **Detection changes** need: points, a legitimate-use explanation in the evidence text, an ATT&CK technique where one applies, and positive and negative tests.
- **Firewall changes** need precise scope, input validation and platform-specific evidence.
- Keep background cost low: anything that runs every sample must be measured (see the profiling notes in `docs/ARCHITECTURE.md`).

## Releasing

Bump `version` in `package.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, `service/Cargo.toml` and `CHANGELOG.md`, then push a tag `vX.Y.Z`. The release workflow builds Windows and Linux installers and publishes them with SHA-256 sums.
