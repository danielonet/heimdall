# UI Design Brief

## Aesthetic direction

**Hacker / network operations centre (NOC)**. Dark background, monospace
typography, terminal-green and electric-blue accents. Feels like a professional
security operations tool, not a consumer app.

## Colour palette

| Role | Value | Usage |
|------|-------|-------|
| Background | `#070b10` | Page background |
| Surface | `#0a0f18` | Cards and panels |
| Surface elevated | `#0f1526` | Topbar, sidebars |
| Border | `rgba(0,220,140,0.12)` | Card borders |
| Border active | `rgba(0,220,140,0.3)` | Hover / focus borders |
| Accent green | `#00dc8c` | Primary accent — online status, headings |
| Accent blue | `#00aaff` | Secondary accent — traffic, info |
| Accent amber | `#f0a030` | Warning states |
| Accent red | `#ff3a5c` | Critical alerts, blocked devices |
| Text primary | `#c8d8e8` | Body text |
| Text secondary | `#5a7090` | Labels, metadata |
| Text muted | `#1a4050` | Disabled, hints |

## Typography

- **Code / data**: `Share Tech Mono` or `JetBrains Mono` — all numeric data,
  IP addresses, MAC addresses, timestamps
- **UI labels**: `Exo 2` or `Rajdhani` — navigation, headings, metric titles
- **Body**: same monospace — maintains the terminal aesthetic throughout

## Visual language

- Thin `1px` card borders (not boxed/raised cards)
- Left accent strip (`3px solid var(--accent)`) on card left edge indicates
  status — green=ok, amber=warn, red=critical
- Top gradient line on cards: `linear-gradient(90deg, transparent, accent, transparent)`
- Dot indicators: `7px` circle with `box-shadow: 0 0 5px color` glow for online
- Pulsing animation on live indicators (`@keyframes pulse`)
- Scanning/blink animation on CRITICAL alerts
- NO gradients on backgrounds — flat dark surfaces only
- NO rounded corners on single-sided borders (left accent strips use `border-radius: 0`)

## Layout variants

Four mockups are available in `docs/frontend/mockups/`. All use the same colour
palette and typography. Choose one as the production layout:

| File | Layout | Best for |
|------|--------|---------|
| `desktop-1-command-bridge.html` | Wide sidebar + content grid | Wide monitors, power users |
| `desktop-2-operator-console.html` | Top navigation + tight grid | Standard 1920px displays |
| `mobile-1-tactical-hud.html` | Alert-forward, bottom tabs | Quick incident response on phone |
| `mobile-2-minimal-recon.html` | Clean tabs, icon-per-device | Daily casual checking on phone |

## Operating mode (NOC / SOC)

The header always shows which mode Heimdall is in, as a two-part switch: **NOC** (green)
only watches and alerts, **SOC** (red) also blocks an offending device automatically. It is
the existing auto-block-on-threat setting, not a second one, so the header and Settings
cannot disagree. A new install starts in NOC; the admin moves to SOC later. Switching to SOC asks for confirmation because it can cut a device off.
On a phone it sits under the title beside the status pills.

## Device status control

A device's trust, quarantine and block are one drop-down (TRUSTED, SUSPECT, QUARANTINED,
BLOCKED), not a row of toggle buttons: green for trusted, amber for suspect or quarantined,
red for blocked. It appears in the same place on the Devices list, on a phone card and on
the device page. The Dashboard keeps its single BLOCK button for a one-click response.

## Phone layout rules

Nothing may be wider than the screen. A table that cannot shrink scrolls sideways inside its
own box; a form grid with fixed columns (device-type profiles) becomes stacked blocks.

## Component conventions

### Status indicators
```
● green  = online / healthy
● amber  = warning / degraded
● red    = critical / blocked
● muted  = offline / unknown
```

### Traffic granularity badge
Wired devices must show a `PORT TOTAL` amber badge next to their traffic figure.
See `docs/router/wired-monitoring-caveat.md`.

### Alert severity chips
```
CRIT  — red background, red border
WARN  — amber background, amber border
INFO  — blue background, blue border
OK    — green background, green border
```

### Blocking button
```
⊘ BLOCK   — red border, red text, red tinted background
✓ UNBLOCK — green border, green text
```

## Responsiveness

- Desktop: sidebar layout (220px fixed) with 4-column content grid
- Tablet: top nav with 2-column grid
- Mobile: single column with bottom tab bar (5 tabs max)
- No horizontal scroll on any viewport

## React component architecture

See `docs/frontend/component-map.md` for the full component tree.

The frontend connects to the Flask backend:
- REST: `http://localhost:5000/api/`
- WebSocket: `http://localhost:5000` (namespace `/sentinel`)
- Auth: JWT Bearer token in `Authorization` header
