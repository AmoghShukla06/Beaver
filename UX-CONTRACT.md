# Beaver UX contract

## Canonical owners
App shell: src/App.tsx. Runtime tokens: src/styles.css. Shared controls, confirmations, search and tables: src/components.tsx. Data bridge: src/api.ts. Desktop authority: desktop/main.cjs. Backend validation: backend/service.py.

## State and navigation
Eight primary pages retain app search/filter/page state in App; sensitive process queries are intentionally not stored in URLs, browser history or localStorage. Detail drawer is nonmodal with explicit Close. Native HTML dialog provides modal confirmation and focus restoration. Settings commit immediately. Native select is intentional.

## Security actions
Blocking requires a named target and scope confirmation. OS elevation occurs only for a chosen native firewall action. No automatic firewall blocking. Opt-in Active protection may terminate unsigned processes with confirmed High-risk behavior; it never stops signed or OS binaries. Allowlisting suppresses heuristic scores only, never fresh threat intelligence. Removing an allowlist re-enables scoring. Endpoint rules affect all apps; Windows program rules cover the exact executable path. Linux exposes endpoint rules and explicitly marks program rules unavailable. No global firewall reset.

## Privacy
Local SQLite history, default seven-day retention, bounded rows. No analytics or remote IP lookups. User enables scheduled threat feed downloads; a refresh transmits no observed endpoints. GeoIP database is chosen locally. Domain names are DNS observations, never claimed as verified server identity.

## Accessibility and resilience
Semantic buttons, visible focus, polite status messages, risk text and icons. Empty, denied, disconnected and loading states remain actionable. Failures preserve last data with stale label. Tables horizontally scroll on narrow screens. Main page scrolls vertically. Reduced motion respected. Single outstanding refresh avoids response reordering.

## Canonical UI Map
| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Select/Listbox | Native select in App.tsx | DESIGN.md | native | Desktop keyboard and selection tests |
| Scrollbar | Global styles.css | DESIGN.md | global baseline | Responsive browser checks |
| Toast | App shared status system | UX-CONTRACT.md | success, error | Desktop action tests |
| CRUD | Service dispatch, Store, shared Confirm | UX-CONTRACT.md | allowlist, firewall | Allowlist lifecycle and backend failure tests |
