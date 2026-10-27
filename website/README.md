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

Every push to `main` that touches the site builds it and uploads `dist/` to the web host over **SFTP with a key**
(`scripts/deploy-sftp.sh`, using `lftp`), then smoke-tests the live site. Pull requests build only.
The host is Hetzner web hosting, which offers SFTP but no shell, so there is no rsync.

`deploy-sftp.sh` was tested against a throwaway OpenSSH server: it uploads, deletes files that no longer exist,
re-uploads changed files, leaves `apt/` alone, and refuses to run with a wrong host key, an empty build directory
or an unsafe path.

One-time setup:

1. **Deploy key.** On your computer: `ssh-keygen -t ed25519 -f heimdall-deploy -C heimdall-site-deploy -N ""`.
   In konsoleH open **Services → Login data → Public SFTP Keys → Add** and paste `heimdall-deploy.pub`.
   If it rejects ed25519, use `ssh-keygen -t rsa -b 4096` instead.
2. **Prefer a limited login.** konsoleH lets you add an extra FTP user restricted to one directory. If a key can be
   attached to that user, use it for deploys so a leaked key reaches only the web root. Otherwise the key belongs to
   the main login, which is the whole account: protect it accordingly.
3. **Host key.** `ssh-keyscan -t ed25519,rsa www805.your-server.de` (use your server's name). Compare the fingerprint
   with what Hetzner shows before trusting it. The deploy checks the host key strictly and never auto-accepts.
4. **Repository secrets** (Settings → Secrets → Actions), on an environment named `production`:

   | Secret | Value |
   |---|---|
   | `DEPLOY_SSH_KEY` | contents of the private key `heimdall-deploy` |
   | `DEPLOY_KNOWN_HOSTS` | the `ssh-keyscan` line(s) |
   | `DEPLOY_HOST` | the server name, e.g. `www805.your-server.de` |
   | `DEPLOY_USER` | the FTP login name |
   | `DEPLOY_PATH` | the web root as the SFTP login sees it: usually `public_html` (confirm in WebFTP) |
   | `DEPLOY_PORT` | only if not 22 |

   Delete the private key from your computer afterwards. Optionally require your approval on the
   `production` environment.
5. **First deploy** is a push to `main` (or Actions → Website → Run workflow). The smoke test then checks
   HSTS and CSP headers, that `/install.sh` is `text/plain` and identical to the repo's script, that
   `/download/heimdall_all.deb` redirects, and that plain HTTP redirects to HTTPS. If it fails on a header,
   the host probably ignores `.htaccess` for that setting; ask Hetzner support.

The deploy keeps the web root an exact copy of the build. `apt/` is excluded so a future package repository can
live beside the site. Do not keep anything else in the web root. Files are uploaded one by one, so a visitor can
briefly see a mix of old and new files during the few seconds an upload takes.

## Before the site goes public

- Publish a release (`v0.1.0`) so `/download/*` has something to redirect to; until then the smoke test's
  redirect check fails.
- Point DNS for `heimdall.it.com` at the host and enable its HTTPS certificate.
- The manual chapters carry a "Draft" note until each is checked against a running dashboard.
- Security-product pages carry `check` notes (visible only in `npm run dev`) for facts to confirm on a running stack.
