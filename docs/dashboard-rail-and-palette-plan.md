# Independent Rail dashboard layout + Slate SOC / Amber CRT palette toggle

> **Amendment**: shipped with **Amber CRT** in place of Arctic Ops (the
> user's preference after seeing both live) — same plan and mechanism
> otherwise, only the second palette's values changed. Table below reflects
> what actually shipped.

## Context

Follow-up to the dashboard layout/palette review artifact. Two decisions
came out of it:
- **Layout**: implement "Independent Rail" — split the desktop Dashboard
  into a main operational column (metrics, hosts, alerts, ports) and a
  persistent right rail (bandwidth + service status) that scrolls on its
  own axis, so `ServiceStatusPanel`'s unbounded row count (13 rows as of
  the Suricata addition) can never again stretch the rest of the grid or
  push Ports below the fold.
- **Palette**: replace the single fixed Terminal Green palette with a
  runtime toggle between exactly two of the reviewed options — **Slate
  SOC** and **Amber CRT** (Arctic Ops was the original pick, swapped for
  Amber CRT after review — see amendment above). Terminal Green is
  retired, not kept as a third choice.

**Two small additions bundled in, flagged here rather than silently
included:**
- Connected Hosts still hard-truncates to 8 devices with no indication
  more exist (a separate finding from the same review). Fixing this is a
  two-line addition once the rail restructure is already touching this
  file, so it's included — a "+N more · view all" link to `/devices`.
- Six components use hardcoded hex colors for Recharts (`TrafficBarChart`,
  `AlertHistogram`, `PortHistorySparkline`, `AnomalyScoreChart`,
  `TrafficTimelineChart`, plus the shared tooltip styling) — not just the
  one on the Dashboard. A palette toggle that only recolors CSS-driven
  elements and leaves 5 other pages' charts stuck on the old blue/green
  would look broken the moment someone switches to Slate SOC and navigates
  to Device Detail or Ports. All six get their literal hex values swapped
  for `var(--color-*)` so the toggle is consistent app-wide, not just on
  the page that prompted it.

## Palette values

Both keep the existing 4 semantic accent slots (`green`=success/online,
`blue`=info/primary highlight, `amber`=warn, `red`=critical) so **no
component code needs to change for color logic** — only the hex values
behind each CSS variable change per palette, plus the two files above that
currently bypass CSS variables entirely.

| Token | Slate SOC | Amber CRT |
|---|---|---|
| `--color-bg` | `#10141a` | `#12100a` |
| `--color-surface` | `#161b23` | `#1a170f` |
| `--color-surface-elevated` | `#1c2330` | `#221d13` |
| `--color-border` | `rgba(120,150,190,0.22)` | `rgba(255,176,45,0.30)` |
| `--color-border-active` | `rgba(120,150,190,0.42)` | `rgba(255,176,45,0.50)` |
| `--color-accent-green` | `#6fbf8f` | `#ffb02d` |
| `--color-accent-blue` | `#7fb2e0` | `#c97a3d` |
| `--color-accent-amber` | `#d9a556` | `#ffd23a` |
| `--color-accent-red` | `#e6707f` | `#ff5a3a` |
| `--color-text-primary` | `#cdd6e2` | `#e8dcc8` |
| `--color-text-secondary` | `#93a3b8` | `#c4b190` |
| `--color-text-muted` | `#7186a3` | `#a3854d` |

## Palette toggle — implementation

**`frontend/src/index.css`**: keep `@theme` declaring the same variable
names (so every existing Tailwind utility class like `text-accent-green`
keeps working unchanged), set its values to the Arctic Ops set as the
pre-JS default, then add two attribute-scoped override blocks:
```css
:root[data-palette="slate"] { --color-bg: #10141a; /* ...full table above... */ }
:root[data-palette="arctic"] { --color-bg: #080d12; /* ...full table above... */ }
```
`:root[data-palette=x]` has higher specificity than the bare `:root` rule
`@theme` compiles to, so this overrides cleanly — standard Tailwind v4
runtime-theming pattern, no build-time changes needed.

**New `frontend/src/store/themeStore.js`** — mirrors
`frontend/src/store/authStore.js`'s localStorage pattern exactly:
```js
import { create } from 'zustand'
const PALETTE_KEY = 'heimdall_palette'
const initial = localStorage.getItem(PALETTE_KEY) || 'arctic'
document.documentElement.setAttribute('data-palette', initial) // module-load-time, before first paint — avoids a flash

export const useThemeStore = create((set) => ({
  palette: initial,
  setPalette(palette) {
    localStorage.setItem(PALETTE_KEY, palette)
    document.documentElement.setAttribute('data-palette', palette)
    set({ palette })
  },
}))
```

**New small toggle control** (a two-state pill, mirroring the existing
`GROUP BY AP` / Alerts-page `ViewToggle` button styling — `border px-2 py-1
text-[9px] tracking-wider`, active state highlighted): add directly inline
in `frontend/src/layouts/desktop/DesktopShell.jsx` (header, next to the
LOGOUT button) and in `frontend/src/layouts/mobile/MobileShell.jsx`'s
existing status-chip row (the `XMO LIVE` / `N ALERTS` chips right below the
header, lines 56-73 — same chip visual style) — both read/write
`useThemeStore`.

**Six Recharts files** — replace every hardcoded hex with the matching CSS
variable via `var(--color-*)`, e.g. `stroke="#1a2535"` → `stroke="var(--color-border)"`,
`fill="#00aaff"` → `fill="var(--color-accent-blue)"`, tooltip `background`/`border`
→ `var(--color-surface)` / `var(--color-border)`. SVG/inline-style `var()`
references re-resolve live on the palette attribute change, same as any
other CSS consumer — no component logic changes, pure value swaps in:
`components/dashboard/TrafficBarChart.jsx`, `components/alerts/AlertHistogram.jsx`,
`components/ports/PortHistorySparkline.jsx`, `components/device-detail/AnomalyScoreChart.jsx`,
`components/device-detail/TrafficTimelineChart.jsx`.

## Independent Rail — implementation

**`frontend/src/pages/dashboard/DesktopDashboard.jsx`** restructured from a
stack of natural-height grid rows into a height-bounded two-column split:

```jsx
<div className="flex h-full flex-col overflow-hidden">
  <div className="grid flex-shrink-0 grid-cols-3 gap-px bg-border">
    {/* MetricCards — unchanged */}
  </div>

  <div className="flex flex-1 gap-px overflow-hidden bg-border">
    {/* MAIN COLUMN */}
    <div className="flex flex-[7] flex-col gap-px overflow-hidden">
      <div className="flex-shrink-0 border border-border bg-surface p-4">
        {/* CONNECTED HOSTS — same 8-item cap, + "N more · view all" link when truncated */}
      </div>
      <div className="flex flex-1 gap-px overflow-hidden">
        <div className="flex-[2] border border-border bg-surface p-4">{/* OPEN ALERTS */}</div>
        <div className="flex-1">{/* CriticalAlertBanner */}</div>
      </div>
      <div className="flex-shrink-0 border border-border bg-surface p-4">{/* PORTS */}</div>
    </div>

    {/* RAIL */}
    <div className="flex flex-[3] flex-col gap-px overflow-hidden">
      <div className="flex-shrink-0 border border-border bg-surface p-4">{/* BANDWIDTH — fixed 180px chart */}</div>
      <div className="flex-1 overflow-hidden">
        <ServiceStatusPanel health={health} />
      </div>
    </div>
  </div>
</div>
```

Depends on `h-full` actually resolving to a real height: `DesktopShell.jsx`'s
`<main className="flex-1 overflow-auto">` already gives `<main>` a definite
height (it's a flex item in a `flex h-screen flex-col` ancestor), and
`DashboardPage.jsx` renders `<DesktopDashboard>` with no wrapping div, so
`h-full` on the Dashboard's root resolves correctly with **no changes
needed to `DesktopShell.jsx` or any other route** — every other page keeps
relying on `<main>`'s own `overflow-auto` exactly as today, since only the
Dashboard route opts into the internal `h-full overflow-hidden` layout.

**`ServiceStatusPanel.jsx`**: change its root wrapper from a plain `<div
className="border border-border bg-surface p-4">` to a flex column that
fills the rail's remaining height and scrolls its row list internally —
header (`SERVICES` label) stays `flex-shrink-0`, the `Row` list moves into
a `flex-1 overflow-y-auto` wrapper. This is the one panel that actually
needs internal scroll — Connected Hosts/Alerts/Ports are all
naturally bounded already (8-item cap, `AlertFeed`'s existing `limit=6`,
fixed 5-port grid), so no other panel needs the same treatment.

**Not touched**: `MobileDashboard.jsx` and every other desktop route
(Devices/Alerts/Ports/Threats/Rules/Settings) — this restructure is scoped
to the Dashboard's desktop view only, matching the original "wide screen"
complaint.

## Verification

- `npm run lint && npm run build`.
- Manual check in a browser (dev server): confirm at a wide/short viewport
  (e.g. 1920×900) that Ports stays visible without scrolling `<main>`, and
  that the Service Status rail scrolls internally past its ~13 rows
  without moving Connected Hosts/Bandwidth.
- Toggle the palette control on the Dashboard, then navigate to Device
  Detail, Ports, and Alerts to confirm their charts re-color too (not just
  CSS-driven elements).
- Reload the page after toggling — confirm the palette persists
  (localStorage) and there's no visible flash of the other palette before
  the stored one applies.
- Confirm Terminal Green's old hex values are fully gone from
  `index.css`/the six chart files (`grep` for the old literals like
  `#00dc8c`, `#00aaff`, `#1a2535`, `#5a7090`) — this is a full replacement,
  not an additional third option.
