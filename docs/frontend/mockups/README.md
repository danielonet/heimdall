# UI Mockups

Four complete HTML mockups showing the Heimdall dashboard design.
Open any file directly in a browser to see the full interactive prototype.

## Desktop layouts

| File | Style | Best for |
|------|-------|---------|
| `sentinel-desktop-1-command-bridge.html` | Fixed left sidebar (220px) + 4-column content grid + live event footer strip | Wide monitors, power users who want sidebar nav always visible |
| `sentinel-desktop-2-operator-console.html` | Horizontal top nav bar + tight borderless grid with 1px dividers + critical action panel | Standard 1920px displays, VS Code / Figma style navigation |

## Mobile layouts

| File | Style | Best for |
|------|-------|---------|
| `sentinel-mobile-1-tactical-hud.html` | Alert-forward (critical alert shown first), large Orbitron metrics, bottom tab bar | Quick incident response — "something's wrong, act now" |
| `sentinel-mobile-2-minimal-recon.html` | Clean horizontal scroll tabs, device icon per row, minimal density | Daily casual checking, quieter aesthetic |

## Shared design language

All four mockups use:
- Background `#070b10` / Surface `#0a0f18`
- Accent green `#00dc8c` (online/healthy)
- Accent blue `#00aaff` (traffic/info)
- Accent amber `#f0a030` (warning)
- Accent red `#ff3a5c` (critical)
- Monospace typography (Share Tech Mono / JetBrains Mono / Orbitron)
- Real device data from the Sagemcom router screenshots

See `../ui-design-brief.md` for the complete colour palette and component conventions.

## Which mockup to implement

**Recommended**: `sentinel-desktop-2-operator-console.html` for desktop
and `sentinel-mobile-2-minimal-recon.html` for mobile.

The operator console aesthetic (top nav, tight grid) is more maintainable as a
React layout and works better at different screen widths. The minimal recon
mobile layout has better usability for routine daily checking.
