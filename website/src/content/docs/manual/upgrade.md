---
title: Upgrade
description: Move an installed Heimdall to a newer version, and what is kept.
---

Every push to the main branch of the project is released as a new version, so there is no schedule. Upgrade when you want a fix or a feature; nothing forces you to.

## Before you start

- Check what you run now: `sudo heimdall version` (.deb), or `cat VERSION` in the install folder (`~/heimdall` for the script, `/opt/heimdall` for the .deb). The newest is on the [releases page](https://github.com/danielonet/heimdall/releases/latest).
- An upgrade keeps your **secrets**, your **`.env`** (tier, network card, subnet, router choice), your **admin account** and your **database**: devices, alerts, trust decisions and the trained models. It only replaces the program files and the images.
- Heimdall is stopped and started again for a minute or so, and it does not watch the network meanwhile.
- Check the free disk space first. The new images are kept next to the old ones until you remove the old ones. See [Install](/install/) for how much each tier needs.

## Installed with the one-line script

Run the install command again, from any folder:

```bash
curl -fsSL https://heimdall.it.com/install.sh | bash -s -- --tier=intermediate
```

It downloads the newest bundle, checks its SHA-256, unpacks it over the install folder, moves `IMAGE_TAG` in `.env` to the new version, pulls the new images and restarts the containers. If it asks which tier or router you use, answer as before: your existing `.env` is kept and wins. Add `--version=vX.Y.Z` to move to a particular release instead of the newest, and `--dir=PATH` if you installed somewhere other than the default.

## Installed from the .deb

```bash
curl -fsSLO https://heimdall.it.com/download/heimdall_all.deb
sudo apt install ./heimdall_all.deb
sudo heimdall upgrade
```

Installing the newer package moves `IMAGE_TAG` in `.env` and restarts the service if it is running. `sudo heimdall upgrade` then pulls the images for that version, starts them, and creates any new secret file the version needs. There is no apt repository yet, so `apt upgrade` does not find new versions by itself.

## Installed by hand

Download and unpack the newest `heimdall-bundle.tar.gz` as on the [Install](/install/) page, into the same folder, then:

```bash
./setup.sh
sed -i "s/^IMAGE_TAG=.*/IMAGE_TAG=$(tr -d '[:space:]' < VERSION | sed 's/^v//')/" .env
docker compose pull && docker compose up -d
```

`setup.sh` keeps your existing `.env` and secrets and only adds what is new.

## After the upgrade

1. `sudo heimdall status` (.deb) or `docker compose ps` should show every container running.
2. Open the dashboard and sign in as before. The `VERSION` file in the install folder, and the image tags in `docker compose ps`, show the new version.
3. The database changes itself: the backend applies any schema change every time it starts, so there is no extra step.
4. A version can add settings. Look through [Settings](/manual/settings/) after a big upgrade.
5. Release notes are on the [releases page](https://github.com/danielonet/heimdall/releases).

## If something goes wrong

- Read the logs: `sudo heimdall logs sentinel-backend` (.deb) or `docker compose logs sentinel-backend`. A container that keeps restarting is usually a missing secret file or a full disk.
- A full disk shows up as "no space left on device" while pulling. Free space (`docker system prune` removes unused images) and run the upgrade again.
- **Going back is not supported.** A newer version may have changed the database, and the older one cannot read it. Setting `IMAGE_TAG` in `.env` back to the old version and running `docker compose up -d` may work, but it is untested. Keep a copy of the database first if you want a way back: `docker compose exec -T postgres pg_dump -U sentinel sentinel > heimdall-backup.sql`.
