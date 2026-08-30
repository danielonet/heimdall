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
# correlation.py's _LOOKBACK_HOURS. Also the bound find_ip_continuity_
# candidates uses for its old-device side, below.
_LOOKBACK_HOURS = 24


class DeviceGroupMember(TypedDict):
    mac_address: str
    ip_address: str | None


class DeviceGroup(TypedDict):
    hostname: str
    members: list[DeviceGroupMember]


class IpContinuityCandidate(TypedDict):
    old_mac: str
    new_mac: str
    ip_address: str
    hostname: str  # the OLD device's hostname — carried forward on a successful link


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

    async def find_ip_continuity_candidates(self, session: AsyncSession) -> list[IpContinuityCandidate]:
        """Fallback for a device find_candidate_groups can never catch: a
        rotated MAC whose Host entry has no hostname at all — some devices
        just don't reliably send DHCP option 12, so the router never
        captures one, and a device with a permanently blank hostname can
        never match anything by the hostname rule no matter how many times
        it reconnects. Confirmed live 2026-08-30: exactly this case, on a
        phone Heimdall had already linked once by hostname under a
        different, earlier rotation — the *next* rotation had no hostname
        and kept tripping ARP_SPOOF instead.

        "Vendor OUI" was considered and dropped as a signal here:
        is_locally_administered MACs (the only ones either side of a
        rotation ever are — see find_candidate_groups) have no real OUI by
        definition, so vendor_name is always blank on both sides and adds
        no discriminating power. IP continuity does the real work instead:
        proposes (old_mac, new_mac) pairs where a hostname-having device's
        on-file IP is also the on-file IP of a fresh, hostname-less,
        locally-administered MAC that appeared shortly after — the same
        "old device disappeared, new randomized MAC appeared" shape the
        primary path looks for, anchored on IP continuity instead of a
        shared hostname since there isn't one to share.

        Only a proposal, exactly like find_candidate_groups: the caller
        (_identity_link_job) still has to directly ARP-confirm new_mac is
        the one actually answering for that IP right now before linking
        anything (see ArpLivenessProbe.resolve_mac) — necessary here
        specifically because both rows share the *same* on-file IP, so
        "is this IP reachable" alone can't tell the two apart. That direct
        ARP check is the real safety gate; the DB-side filters below only
        bound the *candidate set* that gets probed, deliberately not relied
        on for correctness on their own.

        Does NOT filter new_row by recency (first_seen/last_seen) the way
        an earlier version of this method did — confirmed live 2026-08-30
        that's actively wrong on a devices table seeded in bulk (see
        scripts/seed_baseline.py): every row from that seed shares the
        exact same first_seen, including ones that have rotated in many
        times since, so a "new_row.first_seen is recent" filter silently
        excluded every real candidate in that (very common) situation. The
        old side still bounds to _LOOKBACK_HOURS via last_seen, same as
        find_candidate_groups, purely to keep the candidate set from
        growing unbounded over a long-running devices table — it does not
        need to be tighter than that, since the ARP probe is what actually
        decides correctness, not this window.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=_LOOKBACK_HOURS)

        new_rows = (await session.execute(
            select(Device).where(
                Device.linked_to_mac.is_(None),
                (Device.hostname.is_(None)) | (Device.hostname == ''),
            )
        )).scalars().all()

        candidates: list[IpContinuityCandidate] = []
        for new_row in new_rows:
            if not new_row.ip_address or not is_locally_administered(new_row.mac_address):
                continue

            old_row = (await session.execute(
                select(Device).where(
                    Device.mac_address != new_row.mac_address,
                    Device.linked_to_mac.is_(None),
                    Device.hostname.isnot(None),
                    Device.hostname != '',
                    Device.ip_address == new_row.ip_address,
                    Device.last_seen >= cutoff,
                ).order_by(Device.last_seen.desc())
            )).scalars().first()
            if old_row is None or not is_locally_administered(old_row.mac_address):
                continue

            candidates.append(IpContinuityCandidate(
                old_mac=old_row.mac_address, new_mac=new_row.mac_address,
                ip_address=new_row.ip_address, hostname=old_row.hostname,
            ))
        return candidates
