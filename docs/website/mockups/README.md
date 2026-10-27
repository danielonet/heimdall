# Website mockups (Phase 2)

Static HTML for review in a browser, before any Astro work. Open `index.html`
from disk; no server or build step. `site.css` holds the tokens and components,
`site.js` the palette toggle, tabs and copy buttons.

| Page | Shows |
|---|---|
| `index.html` | Home: install block (three tiers + `.deb`), dashboard screenshot, the four capability cards, flow diagram, router strip |
| `install.html` | Install page: tiers, requirements, what the installer does and does not change, verify, upgrade, uninstall |
| `security-suricata.html` | The six-block security-product template, with the docs layout (sidebar, on-this-page) |
| `equipment.html` | Equipment table with filters, and the "no supported router" section |

The **◐ Slate / ◐ Amber** button in the top bar switches palettes (same
`data-palette` attribute and `heimdall_palette` key as the product). Amber CRT
is the default.

## What is real and what is placeholder

- Tokens are copied from `frontend/src/index.css`. In the Astro build they are
  generated from it. One deliberate difference: Slate's muted text is lifted to
  `#8095b2` (the product's `#7186a3` is 4.2:1 on elevated surfaces, under the
  4.5:1 minimum).
- Router and tier facts come from the README. The Block and Traffic columns show
  "—" where the catalog does not state it; the generated table must fill or flag
  every cell.
- The screenshot is `docs/images/dashboard.png` (synthetic demo data).
- Fonts are not loaded: the stack falls back to system monospace and a condensed
  sans. The build self-hosts JetBrains Mono, Rajdhani and MedievalSharp.
- Download links assume the `.htaccess` redirects from the plan (`/download/...`).
- `Phase 1 check` notes on the Suricata page mark claims that must be confirmed
  on a running stack before the page is published.
- Not yet mocked: manual page, contribute/AI-kit page, home-security statement,
  mobile menu (the CSS reflows to one column at 640 px but the nav simply wraps).

## Checked

Tags balanced, internal links and anchors resolve, text/background contrast at
least 4.5:1 in both palettes. **Not checked:** visual rendering in a browser (none
was available when these were written), keyboard order, screen-reader output.
