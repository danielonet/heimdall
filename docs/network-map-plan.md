# Network Map — a new tab implementing the BIFRÖST concept

## Context

Follow-up to the BIFRÖST concept artifact (radial network map: distance from
the center encodes urgency, angle encodes network segment). The user wants
this built as a real, permanent tab in the app — "on top of what we have,"
i.e. a new page alongside the existing DASHBOARD/DEVICES/ALERTS/... tabs,
not a replacement for any of them. This plan translates the concept's demo
(18 hand-placed fake nodes, hardcoded hex colors) into something bound to
real device/alert data, using the app's real theme tokens, and scoped down
from the concept doc's own honest "what this would cost" list to what's
actually buildable now.

**Explicit scope cuts from the concept doc**, stated up front so they're a
decision, not a surprise:
- **No block/quarantine actions on the map itself.** Clicking a node
  navigates to its existing `/devices/<mac>` detail page, which already has
  Block/Quarantine buttons. Building full inline action menus on 100+ SVG
  nodes is a materially bigger, riskier scope than "show the map, click
  through to act."
- **No ambient service-health glow tying into all 13 `ServiceStatusPanel`
  rows** — that's a nice-to-have from the pitch, not core to "a map of my
  devices." One cheap piece of it *is* kept: the center glow tints red/amber
  if `useHealth()` reports degraded (Postgres/Redis down, scheduler stopped,
  poll erroring), since that's a single existing boolean already fetched
  app-wide, not new plumbing.
- **Desktop-only.** The concept was explicitly framed around "wide screen
  display." `useLayoutMode()` gates it: on mobile, the route renders a short
  "best viewed on a wider screen" message instead of attempting the SVG at
  phone width. Not added to `MobileShell.jsx`'s nav at all.
- **No JS unit tests** — this frontend has no test runner/config anywhere in
  the repo (confirmed: no `vitest`/`jest` in `package.json`, no `*.test.jsx`
  files exist), so this follows that existing convention like every other
  frontend change this session — verified via `npm run lint`/`npm run build`
  plus a manual browser check (which I can't do myself — no browser access
  in this sandbox, same caveat as every other frontend change this
  session).

## Real data → the concept's two axes

**Sector (angle)**: reuse `groupByAp`/`apGroupKey` from
`frontend/src/lib/apGroups.js` verbatim — the exact same PRIV0/VID1/
GUEST2G/GUEST5G/AP_BACKHAUL/WIRED/NOT ASSOCIATED grouping the Devices page's
"GROUP BY AP" toggle already uses, so segment meaning stays consistent
app-wide rather than inventing a second grouping scheme.

**Urgency tier (radius ring)**, computed per device from `useDevices()`
(`frontend/src/hooks/useDevices.js`) crossed with `useAlertGroups({
acknowledged: 'false' })` (`frontend/src/hooks/useAlertGroups.js`, already
used by the Alerts page's grouped view) reduced client-side to "worst open
alert severity per device_mac":
- **THREAT** (innermost): worst open alert severity is CRITICAL
- **WATCH** (middle): worst open alert is WARNING, OR `device.is_quarantined`,
  OR (`!device.is_trusted && device.is_online`) — an online SUSPECT device
  with no alert yet still deserves a watchful ring, matching the existing
  TRUSTED/SUSPECT badge concept elsewhere in the app
- **CALM** (outer): everything else, including offline/never-connected
  devices (dimmed, same visual treatment the concept doc used)

**Node visual status** (color + bridge line style), all via the live theme
tokens (`var(--color-accent-red)` etc. from `frontend/src/index.css`) so it
respects the Slate SOC / Amber CRT toggle already built, never hardcoded hex
like the concept demo:
- `is_blocked` → bridge severed (dashed, dim, small "×"), status = danger
- `is_quarantined` → bridge half-severed (dashed but not dimmed)
- open CRITICAL/WARNING alert → red/amber, pulsing, flowing bridge
- otherwise online → green/primary accent, flowing bridge
- offline → muted, static bridge, dimmed label

## Layout algorithm (the real engineering risk, addressed head-on)

The concept demo hand-placed 18 nodes and admitted collision above ~40-60.
The user's own live deployment has **109 devices** — this has to actually
work at that scale, not just at demo scale. New pure helper module
`frontend/src/lib/networkMapLayout.js`, exporting
`computeNodeLayout(devices, alertGroups) -> [{mac, x, y, angle, tier,
sector, status, ...}]`, separated from rendering so the positioning logic
is easy to reason about on its own:

1. Bucket devices by `(sector, tier)` — same shape as `groupByAp`'s
   existing bucketing, one level deeper.
2. Within each bucket, spread nodes evenly across that sector's 90° (or
   360°/sector-count) angular wedge at the tier's base radius.
3. **Graceful degradation for dense buckets**: once a bucket exceeds a
   threshold (~14 nodes, tuned so a 109-device/7-sector/3-tier spread stays
   legible), split it into two concentric sub-rings a few px apart within
   the same tier band instead of letting dots overlap — doubles a bucket's
   effective capacity without needing a real force-directed/WebGL engine.
   This is the one piece of "what this would cost" from the concept doc
   that gets *actually solved* here, not just caveated.
4. A small deterministic radius jitter (keyed by MAC, not random per
   render) avoids nodes landing exactly on top of each other at the same
   angle/ring.

## Component structure

- **`frontend/src/pages/NetworkMapPage.jsx`** — route-level: `useDevices()`,
  `useAlertGroups({ acknowledged: 'false' })`, `useHealth()`,
  `useLayoutMode()`. Mobile → short fallback message. Desktop → renders the
  map component with computed layout.
- **`frontend/src/components/network-map/NetworkMap.jsx`** — the SVG,
  structurally mirroring the concept artifact (urgency rings, sector
  dividers/labels, bezier bridge paths, node circles + labels, center
  glow), but every node comes from `computeNodeLayout()`'s real output, and
  every color comes from CSS custom properties. Click → `navigate('/devices/'
  + mac)` (same `useNavigate` pattern `AlertFeed.jsx` already uses). Hover →
  a lightweight tooltip (native `<title>` for v1 — simplest, no new
  component, upgradeable later).
- **`frontend/src/lib/networkMapLayout.js`** — the pure layout function
  above, importing `apGroupKey`/`groupByAp` from `./apGroups.js`.

## Routing & nav

- **`frontend/src/App.jsx`**: add `<Route path="/map" element={<NetworkMapPage />} />`
  inside the existing `<Route element={<Shell />}>` block, next to the
  other authenticated routes.
- **`frontend/src/layouts/desktop/DesktopShell.jsx`**: add `{ to: '/map',
  label: 'MAP' }` to `NAV_ITEMS`, positioned right after DASHBOARD (it's a
  dashboard alternative, not a device/alert/settings-tier page).
- `MobileShell.jsx` — intentionally not touched (see scope cuts above).

## Verification

- `python3 -m py_compile` is N/A (frontend-only change).
- `npm run lint && npm run build`.
- Manual browser check needed on the user's side (no browser access in this
  sandbox): confirm the MAP tab appears in desktop nav, renders against
  live device/alert data, ring/sector placement looks sane at ~109 devices,
  clicking a node navigates to its device detail page, and toggling the
  Slate/Amber palette re-colors the map like everything else.
