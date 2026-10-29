# Security Policy

Heimdall is a **home-network monitoring tool in alpha**. It is not a hardened
product, and it is deliberately privileged: several containers use host
networking with `NET_RAW`/`NET_ADMIN` to sniff LAN traffic, and it holds your
router's admin credentials. Run it on a dedicated machine on a network you own
or are authorised to monitor.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately via GitHub's
[private vulnerability reporting](https://github.com/danielonet/heimdall/security/advisories/new)
(Security tab → "Report a vulnerability"). Include what you found, how to
reproduce it, and the version/commit. You'll get an acknowledgement as soon as
the maintainer can manage it; this is a volunteer-run project, so please allow
a reasonable time for a fix before disclosing publicly.

## Supported versions

Only the latest commit on `main` is supported. There are no tagged releases yet.

## Deployment guidance

- **Don't expose the dashboard (port 3000) or API (port 5000) to the internet.**
  Keep them LAN-only or behind a VPN/reverse proxy with its own authentication.
- **Secrets** live in `secrets/` (mode 700) and are mounted as Docker secrets;
  they are never committed (`secrets/` and `.env` are gitignored). The
  installer never asks for or writes a dashboard password. You create the admin account in the
  browser on first visit, and only a salted hash is kept, in the database. Until you do, anyone
  who can reach port 3000 could create it first, so do it straight away. (Installs from before
  this keep the password in `secrets/admin_password.txt`.)
- **Router credentials** give full control of your router. Use a dedicated
  router account where the firmware allows it.
- **Privileged containers.** Anything that can sniff your LAN can read it.
  Treat the Heimdall host (and its Docker socket/group) as a sensitive asset.
- **Active scanning.** The nightly nmap scan and block/quarantine actions
  affect devices on your network. Only enable them on networks you own.
- **Threat-intel and notification integrations** (OTX, ntfy, SMTP) send data
  to third parties if you configure them.

## Scope

In scope: authentication/authorisation flaws in the Flask API and dashboard,
secret leakage, injection (SQL/command/template), unsafe handling of router or
network-supplied data, and container-escape paths introduced by this repo's
compose configuration.

Out of scope: vulnerabilities in third-party images or upstream projects
(Suricata, Zeek, ClamAV, OpenCanary, TimescaleDB — report those upstream),
and attacks that require an already-compromised host or LAN.
