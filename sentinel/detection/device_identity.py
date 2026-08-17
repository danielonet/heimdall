"""Device-identity linking — recognizes when several device rows sharing one
hostname are almost certainly the same physical device that reconnected
under a fresh randomized WiFi MAC (Apple's Private Wi-Fi Address, Android's
randomized-per-network or non-persistent MAC — both on by default on modern
phones).

Not a BaseDetector: this is a lookback over persisted `devices` rows, not a
per-poll check against one live DeviceSnapshot/TrafficSample — same shape as
sentinel/detection/correlation.py:CrossAlertCorrelator, which is the
precedent for "standalone class, invoked by its own scheduler job, outside
the BaseDetector pipeline" (CLAUDE.md's BaseDetector rule is about per-
device/per-traffic-sample detectors, not this category).

Deliberately does NOT use Device.is_online/last_seen to decide which member
of a hostname group is "the old one" — this router's own Hosts/
AssociatedDevices view has a confirmed, PERSISTENT staleness (see
SagemcomXmoAdapter._to_device_snapshot's is_online docstring: "Hosts' own
Active field appears to lag well behind the device actually going away").
Confirmed in production: is_online stayed pinned True (re-asserted every ~15s
poll) for MACs that had been physically gone for hours, which meant an
earlier is_online-filtered version of this query silently never considered
them at all, no matter how long they'd actually been gone. Which member(s)
of a hostname group are actually still alive is decided purely by direct ARP
confirmation, by the caller (see SentinelScheduler._identity_link_job) — this
class only proposes which groups are worth probing, and has no network I/O
of its own (no scapy/nmap import).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TypedDict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.db.models import Device
from sentinel.security.mac_vendor import is_locally_administered

# Bounds the candidate query so a MAC that hasn't been seen in a very long
# time doesn't get dragged into a fresh probe forever — same reasoning as
# correlation.py's _LOOKBACK_HOURS.
_LOOKBACK_HOURS = 24


class DeviceGroupMember(TypedDict):
    mac_address: str
    ip_address: str | None


class DeviceGroup(TypedDict):
    hostname: str
    members: list[DeviceGroupMember]


class DeviceIdentityLinker:
    """Stateless between calls — every scan re-derives groups from the
    devices table itself, so nothing needs to survive a process restart."""

    async def find_candidate_groups(self, session: AsyncSession) -> list[DeviceGroup]:
        """Every hostname currently claimed by 2+ not-yet-linked devices,
        all presenting a randomized MAC (is_locally_administered — the
        phenomenon this class exists to resolve; a device with a real
        manufacturer OUI has no reason to be treated as a possible duplicate
        of another MAC). The caller ARP-probes every member and links
        whichever are confirmed unreachable onto the single member that
        answers — see _identity_link_job.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=_LOOKBACK_HOURS)

        rows = (await session.execute(
            select(Device).where(
                Device.linked_to_mac.is_(None),
                Device.hostname.isnot(None),
                Device.hostname != '',
                Device.last_seen >= cutoff,
            )
        )).scalars().all()

        by_hostname: dict[str, list[Device]] = {}
        for row in rows:
            if not is_locally_administered(row.mac_address):
                continue
            by_hostname.setdefault(row.hostname, []).append(row)

        return [
            DeviceGroup(
                hostname=hostname,
                members=[DeviceGroupMember(mac_address=d.mac_address, ip_address=d.ip_address) for d in group],
            )
            for hostname, group in by_hostname.items()
            if len(group) >= 2
        ]
