#!/usr/bin/env python
"""seed_baseline.py — Re-establish a healthy device baseline without an alert flood.

Use this after the devices table has been cleared/reset (e.g. a dev reset, or
restoring from a backup that predates current devices) and you don't want
NewDeviceDetector to fire a CRITICAL "new device" alert for every device
already on your LAN.

What it does:
  1. Connects to the router via the same adapter the scheduler uses.
  2. Fetches the currently connected devices.
  3. Upserts them directly into `devices` (marked trusted) and the persistent
     `trusted_macs` registry — bypassing the detection pipeline entirely, so
     no alerts are raised for this batch.

Safe to re-run: existing devices/trusted_macs rows are left untouched, only
missing ones are added. Devices that join *after* this point are still
flagged normally by NewDeviceDetector — this only seeds today's population.

Usage:
    .venv/bin/python scripts/seed_baseline.py
"""
import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask  # noqa: E402

from sentinel.adapter.factory import create_router_adapter  # noqa: E402
from sentinel.db.models import Device  # noqa: E402
from sentinel.db.repositories import TrustedMacRepository  # noqa: E402
from sentinel.db.session import get_engine, get_session, init_db  # noqa: E402
from sentinel.security.mac_vendor import lookup_vendor  # noqa: E402


async def main() -> None:
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)

    adapter = await create_router_adapter()
    trusted_repo = TrustedMacRepository()

    try:
        devices = await adapter.get_connected_devices()
        now = datetime.now(timezone.utc)

        added = 0
        already_known = 0
        retrusted = 0
        async with get_session() as session:
            for snapshot in devices:
                existing = await session.get(Device, snapshot.mac_address)
                if existing is not None:
                    already_known += 1
                    # Re-sync is_trusted even for rows that already exist —
                    # a row can end up incorrectly untrusted (e.g. created
                    # during a brief window where trusted_macs was empty,
                    # such as a race between a reset and this script running)
                    # and nothing else ever revisits it otherwise. See
                    # sentinel/scheduler/jobs.py:_upsert_devices for the same
                    # fix on the regular poll-cycle path.
                    if not existing.is_trusted:
                        existing.is_trusted = True
                        retrusted += 1
                    continue
                session.add(Device(
                    mac_address=snapshot.mac_address,
                    ip_address=snapshot.ip_address,
                    hostname=snapshot.hostname,
                    vendor_name=snapshot.vendor_name or lookup_vendor(snapshot.mac_address),
                    interface_name=snapshot.interface_name,
                    traffic_granularity='per_port' if snapshot.interface_name == 'Ethernet' else 'per_device',
                    is_trusted=True,
                    is_online=snapshot.is_online,
                    # Seeding a device here means "known and trusted as of
                    # right now" — if it's currently online, that counts as
                    # a real connection, not just a sighting. Leaving this at
                    # the column default (False) would make NewDeviceDetector
                    # treat its next poll as a first-ever connection.
                    ever_connected=snapshot.is_online,
                    first_seen=now,
                    last_seen=now,
                ))
                added += 1

        for snapshot in devices:
            await trusted_repo.trust(snapshot.mac_address)

        print(f'Seeded baseline: {added} new device(s) added, {already_known} already known ({retrusted} re-trusted).')
        print(f'{len(devices)} MAC(s) now in the persistent trusted_macs registry.')
        print('These will not trigger NEW_DEVICE alerts, even if the devices table is reset again.')
    finally:
        # aclose() isn't part of the RouterAdapter interface — only
        # SagemcomXmoAdapter has an HTTP client to release.
        aclose = getattr(adapter, 'aclose', None)
        if aclose is not None:
            await aclose()
        await get_engine().dispose()


if __name__ == '__main__':
    asyncio.run(main())
