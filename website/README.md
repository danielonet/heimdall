# heimdall.it.com

Static site built with Astro and Starlight. Design and plan: `docs/website-plan.md`;
reviewed mockups: `docs/website/mockups/`.

| Path | What |
|---|---|
| `src/pages/` | Home, install, security, equipment, contribute, about |
| `src/content/docs/manual/` | The user manual (Starlight) |
| `src/data/products.ts` | The security-product pages: one entry, six blocks, per product |
| `src/data/routers.json` | **Generated** from `sentinel/adapter/catalog.py` + `docs/router/equipment-facts.json` |
| `src/styles/tokens.css` | **Generated** from `frontend/src/index.css` (the product's palettes) |
| `public/.htaccess` | HTTPS, the `/download/*` redirects, `/install.sh` handling, security headers |
| `public/install.sh` | **Generated** copy of `install/get-heimdall.sh` |

## Develop

Needs Node 22.23.4 or newer (Astro refuses older) and Python 3.

```bash
cd website
npm ci
npm run dev        # regenerates tokens, routers and assets, then serves http://localhost:4321
npm run build      # same, then builds to dist/
python3 scripts/check-links.py dist
```

When a router is added to the catalog, `npm run build` fails until it has an entry in
`docs/router/equipment-facts.json`. That is deliberate: the equipment table cannot drift.

## Deploy (GitHub Actions, `.github/workflows/website.yml`)

Every push to `main` that touches the site builds it and rsyncs `dist/` to the web host over SSH,
then smoke-tests the live site. Pull requests build only.

One-time setup:

1. **Deploy key.** On your computer: `ssh-keygen -t ed25519 -f heimdall-deploy -C heimdall-site-deploy -N ""`.
   Append `heimdall-deploy.pub` to `~/.ssh/authorized_keys` on the host, with restrictions:
   `restrict,no-pty ssh-ed25519 AAAA... heimdall-site-deploy`. If the host has `rrsync`, prefer
   `command="rrsync /path/to/webroot",restrict ssh-ed25519 ...` so the key can only write the web root.
2. **Host key.** `ssh-keyscan -p 22 your.host` and compare its fingerprint with the one in your hosting panel
   before trusting it. The workflow uses `StrictHostKeyChecking=yes`.
3. **Repository secrets** (Settings → Secrets → Actions), on an environment named `production`:

   | Secret | Value |
   |---|---|
   | `DEPLOY_SSH_KEY` | contents of the private key `heimdall-deploy` |
   | `DEPLOY_KNOWN_HOSTS` | the `ssh-keyscan` line(s) |
   | `DEPLOY_HOST`, `DEPLOY_USER` | the SSH host and user |
   | `DEPLOY_PATH` | the web root directory, e.g. `/home/user/public_html` |
   | `DEPLOY_PORT` | only if not 22 |

   Delete the private key from your computer afterwards. Optionally require your approval on the
   `production` environment.
4. **First deploy** is a push to `main` (or Actions → Website → Run workflow). The smoke test then checks
   HSTS and CSP headers, that `/install.sh` is `text/plain` and identical to the repo's script, that
   `/download/heimdall_all.deb` redirects, and that plain HTTP redirects to HTTPS. If it fails on a header,
   the host probably lacks `mod_headers` or `AllowOverride`; ask the host to enable them.

`rsync --delete` keeps the web root an exact copy of the build. `/apt/` is excluded so a future package
repository can live beside the site. Do not keep anything else in the web root.

## Before the site goes public

- Publish a release (`v0.1.0`) so `/download/*` has something to redirect to; until then the smoke test's
  redirect check fails.
- Point DNS for `heimdall.it.com` at the host and enable its HTTPS certificate.
- The manual chapters carry a "Draft" note until each is checked against a running dashboard.
- Security-product pages carry `check` notes (visible only in `npm run dev`) for facts to confirm on a running stack.
