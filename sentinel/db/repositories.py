"""Thin async repositories wrapping common read queries.

Used by detectors that need to check persisted registry state independent of
the current poll cycle (e.g. "has this MAC ever been seen before").
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinel.config import settings
from sentinel.db.models import (
    AdminAccount, Alert, AlertSnooze, AppSettings, Device, DeviceTypeProfile, DnsQuery, PortAllowlistEntry, RouterProfile,
    TrafficSample, TrustedMac, WifiNetwork, WifiSighting,
)
from sentinel.db.session import get_session
from sentinel.detection.device_profiles import DEFAULT_PROFILE
from sentinel.security.mac_vendor import lookup_vendor

logger = logging.getLogger(__name__)

_SETTINGS_ROW_ID = 1

# device_type strings DeviceTypeProfileRepository.get_profile() has already
# warned about not matching any configured profile row — see get_profile()'s
# docstring. Module-level (not an instance attribute) because this class is
# instantiated fresh per call (see class docstring) with nothing to hold
# per-process state on; same "log once, not every poll" posture as
# SagemcomXmoAdapter._wan_stats_warned, just at module scope since there's
# no long-lived instance here to hang a flag on.
_unmatched_device_types_warned: set[str] = set()


class DeviceRepository:
    """Read/write access to the devices table."""

    async def exists(self, mac_address: str) -> bool:
        """Return True if this MAC address is already in the device registry.

        Note: a row exists for any MAC the router's Hosts/AssociatedDevices
        tables have ever mentioned, active or not — this is not the same as
        "has this device ever actually connected". See has_connected_before.
        """
        async with get_session() as session:
            return await session.get(Device, mac_address) is not None

    async def has_connected_before(self, mac_address: str) -> bool:
        """Return True if this MAC has ever been seen with is_online=True.

        Used by NewDeviceDetector instead of exists() — a device that's only
        ever been visible-but-not-connected (a stale DHCP reservation, a
        probe, etc.) already has a devices row, but has never really
        connected; exists() alone would wrongly suppress its first real
        NEW_DEVICE alert.
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            return bool(device and device.ever_connected)

    async def get_source_router(self, mac_address: str) -> str | None:
        """Which configured router most recently reported this MAC —
        'sagemcom' | 'miwifi' — or None if this MAC has no devices row yet.
        Used by SentinelScheduler._adapter_for_mac to route block/unblock/
        quarantine actions to the router that actually owns this device
        rather than always assuming the active/primary one. See
        Device.source_router.
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            return device.source_router if device else None

    async def get_first_seen(self, mac_address: str) -> datetime | None:
        """When this MAC's devices row was first created, or None if it has
        no row yet. Used by AnomalousVolumeDetector to gate alerts during the
        post-install/new-device learning period — see Settings.ML_LEARNING_PERIOD_HOURS.
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            return device.first_seen if device else None

    async def is_empty(self) -> bool:
        """True if the devices table has no rows at all — used to distinguish
        a genuine fresh install from a single MAC's row merely being absent."""
        async with get_session() as session:
            result = await session.execute(select(Device.mac_address).limit(1))
            return result.first() is None

    async def list_online(self) -> list[tuple[str, str]]:
        """(mac_address, ip_address) pairs for every device currently online
        with a known IP. Used by SentinelScheduler._spike_ip_enrichment_job
        to build the local-IP set for a household-wide WAN_BANDWIDTH_SPIKE
        alert (which has no device_mac of its own) — deliberately scoped to
        *currently* online devices rather than every device ever seen, since
        a long-offline device's stale ip_address may since have been
        DHCP-reassigned to something else, which would misattribute traffic.
        """
        async with get_session() as session:
            stmt = select(Device.mac_address, Device.ip_address).where(
                Device.is_online.is_(True), Device.ip_address.isnot(None),
            )
            return [(mac, ip) for mac, ip in (await session.execute(stmt)).all()]

    async def get_ap_alias(self, mac_address: str) -> str | None:
        """The AP alias (PRIV0/VID1/GUEST2G/GUEST5G/AP_BACKHAUL) this MAC was
        associated with as of its last persisted poll, or None if it has no
        row yet or was last seen wired/unassociated. Used by
        AccessPointCrossingDetector to compare against the *incoming* poll's
        ap_alias before _upsert_devices overwrites it — must be called before
        that upsert runs, same ordering requirement as has_connected_before
        (see NewDeviceDetector's docstring).
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            return device.ap_alias if device else None

    async def link(self, *, old_mac: str, new_mac: str, reason: str) -> Device | None:
        """Marks old_mac as a stale duplicate of the CURRENT canonical
        device — see sentinel/detection/device_identity.py:DeviceIdentityLinker
        and sentinel/security/liveness.py:ArpLivenessProbe for how a link is
        decided (hostname + reconnect-timing match, ARP-confirmed
        unreachable) before this is ever called.

        "Current canonical" may not literally be new_mac: if new_mac is
        itself already linked away (shouldn't happen given the linker's own
        filters, but defensive), this links onto whatever new_mac ultimately
        resolves to instead — linked_to_mac must never form a multi-hop
        chain, since every reader (list_devices, metrics.py) does a single
        flat WHERE linked_to_mac IS NULL / = :mac check, never a walk.

        Also repoints every row already linked to old_mac (a prior link,
        e.g. A already -> old_mac) onto the same resolved target in the same
        transaction — the other half of the no-chains invariant: old_mac
        itself might currently be someone else's canonical target.

        Idempotent: re-confirming an already-correct link is a no-op write
        (still returns the row). Returns None if old_mac has no row at all.

        Also carries old_mac's nickname forward onto the canonical target,
        if old_mac has one and the target doesn't already — confirmed live
        2026-09-03 this was a real gap: nickname is deliberately durable
        against everything else the poll loop overwrites (see Device.
        nickname's docstring), but link() itself never touched it, so a
        renamed device silently lost its name the moment its MAC rotated
        and got auto-linked. Never overwrites a nickname already set
        directly on the target — a deliberate rename on the current
        identity wins over one inherited from a stale old MAC.
        """
        async with get_session() as session:
            old = await session.get(Device, old_mac)
            if old is None:
                return None

            target = new_mac
            new = await session.get(Device, new_mac)
            if new is not None and new.linked_to_mac:
                target = new.linked_to_mac

            now = datetime.now(timezone.utc)
            await session.execute(
                update(Device)
                .where(Device.linked_to_mac == old_mac)
                .values(linked_to_mac=target, linked_at=now, link_reason=f'repointed after {old_mac} -> {target}')
            )

            if old.linked_to_mac != target:
                old.linked_to_mac = target
                old.linked_at = now
                old.link_reason = reason

            if old.nickname and target != old_mac:
                target_device = await session.get(Device, target)
                if target_device is not None and not target_device.nickname:
                    target_device.nickname = old.nickname

            await session.flush()
            await session.refresh(old)
            return old

    async def canonical_mac(self, mac_address: str) -> str:
        """Resolves mac_address to its canonical identity: itself if unknown
        or unlinked, otherwise whatever it's linked_to_mac (single hop only —
        see link()'s no-multi-hop-chain invariant, which guarantees one hop
        is always enough).

        Used by SentinelScheduler._persist_arp_alert to recognize an ARP
        MAC change between two rows Heimdall has already identity-linked as
        the same physical device (e.g. a stale ARP cache entry, or a
        gratuitous ARP, briefly reintroducing an old rotated-away MAC) —
        that's not spoofing, just noise from an identity Heimdall already
        resolved, and must not re-alert every time it happens. See
        DeviceIdentityLinker for how a link is decided in the first place.
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            if device is None or device.linked_to_mac is None:
                return mac_address
            return device.linked_to_mac

    async def unlink(self, mac_address: str) -> bool:
        """Clears linked_to_mac/linked_at/link_reason on this exact row —
        the manual-undo path (see POST /api/devices/<mac>/unlink). Returns
        False if the row doesn't exist or isn't currently linked.

        Deliberately does not repoint any rows that were linked to
        mac_address onto anything else — unlinking a device only restores
        its own identity, it doesn't retroactively unlink devices that were
        (possibly correctly) linked to it.
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            if device is None or device.linked_to_mac is None:
                return False
            device.linked_to_mac = None
            device.linked_at = None
            device.link_reason = None
            return True

    async def get_linked_into(self, mac_address: str) -> list[Device]:
        """Every row currently linked_to_mac == mac_address, newest-linked
        first — powers a canonical device's 'N devices linked into this
        one' transparency list (see GET /api/devices/<mac>)."""
        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.linked_to_mac == mac_address).order_by(Device.linked_at.desc())
            )
            return list(result.scalars().all())

    async def archive_stale(self, older_than: timedelta) -> int:
        """Soft-archives every device whose last_seen predates the cutoff.
        Exemptions, each a deliberate safety gate:
          - is_trusted: an admin already vouched for this device — a long
            absence (e.g. a vacation-home camera) shouldn't make a trusted
            device disappear on its own.
          - is_blocked / is_quarantined: an active security decision worth
            staying visible, not filed away as routine housekeeping.
          - linked_to_mac IS NOT NULL: already hidden as a stale duplicate
            under link() — a separate mechanism, not this one's concern.
          - already is_archived: idempotent, a repeat sweep is a no-op for it.
        A currently-online device can never match last_seen < cutoff —
        _upsert_devices (sentinel/scheduler/jobs.py) only ever advances
        last_seen while is_online is true — so no explicit is_online guard
        is needed here. Returns the count archived. Used by
        SentinelScheduler._device_archive_sweep_job.
        """
        cutoff = datetime.now(timezone.utc) - older_than
        async with get_session() as session:
            stmt = select(Device).where(
                Device.is_archived.is_(False),
                Device.is_trusted.is_(False),
                Device.is_blocked.is_(False),
                Device.is_quarantined.is_(False),
                Device.linked_to_mac.is_(None),
                Device.last_seen < cutoff,
            )
            rows = (await session.execute(stmt)).scalars().all()
            now = datetime.now(timezone.utc)
            for row in rows:
                row.is_archived = True
                row.archived_at = now
                row.archive_reason = f'No activity for over {older_than.days} days'
            return len(rows)

    async def purge_archived(self, older_than: timedelta) -> list[str]:
        """Permanently deletes every device that has been *archived* (see
        archive_stale above) for longer than `older_than` — the more
        aggressive second stage of the same lifecycle. archive_stale()
        only ever hides a device; nothing about it is removed. This
        actually deletes the device row and its history — alerts, DNS
        query log, traffic samples — a device that's genuinely never
        coming back shouldn't sit in the database forever just because
        "archived" happens to be permanent in practice.

        Deliberately does NOT touch alert_snoozes or port_allowlist,
        unlike history tables — both are explicitly documented (see their
        own model docstrings) to survive even a full devices-table
        purge/reset, same reasoning as trusted_macs: a user-set preference
        for a MAC, meant to still apply if that MAC ever reappears. This
        purge only reaches devices that were never trusted in the first
        place (see the exemption below), but the preference-vs-history
        distinction those two tables were built on applies here just the
        same, so they're left alone.

        Measured from archived_at, not last_seen — this is a second,
        additive countdown that only starts once a device has actually
        been archived, so device_purge_after_days doesn't overlap or
        shorten device_archive_after_days's own window.

        Same exemption set as archive_stale, checked again here as
        defense-in-depth: none of is_trusted/is_blocked/is_quarantined/
        linked_to_mac IS NOT NULL should ever reach this stage (archive_
        stale never archives them in the first place), but a device could
        in principle be manually re-trusted, blocked, or linked *after*
        being archived — this must not delete it out from under that
        later decision.

        Returns the list of purged MAC addresses — the caller (see
        SentinelScheduler._device_archive_sweep_job) uses it to also drop
        each device's in-memory ML state and persisted model file
        (AnomalyEngine.forget()), which this repository has no access to.

        traffic_samples is a TimescaleDB hypertable; a plain scoped DELETE
        (rather than drop_chunks, which is time-range-only and can't
        target specific devices) is fine here — the row count per purged
        device is small next to what _data_retention_job's chunk-level
        drops handle.
        """
        cutoff = datetime.now(timezone.utc) - older_than
        async with get_session() as session:
            stmt = select(Device.mac_address).where(
                Device.is_archived.is_(True),
                Device.is_trusted.is_(False),
                Device.is_blocked.is_(False),
                Device.is_quarantined.is_(False),
                Device.linked_to_mac.is_(None),
                Device.archived_at < cutoff,
            )
            macs = list((await session.execute(stmt)).scalars().all())
            if not macs:
                return []
            await session.execute(delete(Alert).where(Alert.device_mac.in_(macs)))
            await session.execute(delete(DnsQuery).where(DnsQuery.device_mac.in_(macs)))
            await session.execute(delete(TrafficSample).where(TrafficSample.mac_address.in_(macs)))
            await session.execute(delete(Device).where(Device.mac_address.in_(macs)))
            return macs

    async def unarchive(self, mac_address: str) -> bool:
        """Manual undo for archive_stale() — clears is_archived/archived_at/
        archive_reason. False if unknown or not currently archived."""
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            if device is None or not device.is_archived:
                return False
            device.is_archived = False
            device.archived_at = None
            device.archive_reason = None
            return True


class DeviceTypeProfileRepository:
    """Read/write access to the admin-editable device_type_profiles table —
    replaces what used to be sentinel/detection/device_profiles.py's
    hardcoded DEVICE_TYPE_PROFILES dict. get_profile() keeps the exact same
    merge-over-default fallback semantics that dict had (unknown/blank
    device_type -> DEFAULT_PROFILE untouched), just DB-backed and read fresh
    on every call — same "no caching, admin's change takes effect on the
    very next poll" convention as SettingsRepository.
    """

    async def get_profile(self, device_type: str | None) -> dict:
        """Falls back to DEFAULT_PROFILE, untouched, for a blank or
        unmatched device_type — this is an exact-string primary-key lookup,
        so a real mismatch between the router's own classification
        vocabulary and this table's admin-facing keys (confirmed in
        production: a device the router reported as 'NAS' silently missed
        a seeded 'Network Attached Storage' row and got the generic,
        stricter default instead — the admin had tuned the *right* profile,
        it just never applied) fails exactly like a genuinely unrecognized
        type, with nothing surfaced anywhere. Logs once per distinct
        unmatched type per process lifetime — not every poll — so this
        class of mismatch is at least discoverable instead of silent."""
        if not device_type:
            return dict(DEFAULT_PROFILE)
        async with get_session() as session:
            row = await session.get(DeviceTypeProfile, device_type)
        if row is None:
            if device_type not in _unmatched_device_types_warned:
                _unmatched_device_types_warned.add(device_type)
                logger.warning(
                    'device_type %r has no matching device_type_profiles row — falling back to '
                    'DEFAULT_PROFILE. If you meant to tune this type, check Settings -> Device Type '
                    'Profiles for an exact-string match (this is not a fuzzy lookup).', device_type,
                )
            return dict(DEFAULT_PROFILE)
        return {
            **DEFAULT_PROFILE,
            'high_upload_ratio_threshold': row.high_upload_ratio_threshold,
            'volume_sustained_polls': row.volume_sustained_polls,
            'contamination': row.contamination,
        }

    async def get_all_profiles(self) -> list[DeviceTypeProfile]:
        async with get_session() as session:
            result = await session.execute(select(DeviceTypeProfile).order_by(DeviceTypeProfile.device_type))
            return list(result.scalars().all())

    async def upsert_profile(
        self, device_type: str, *,
        high_upload_ratio_threshold: float, volume_sustained_polls: int, contamination: float,
    ) -> DeviceTypeProfile:
        async with get_session() as session:
            row = await session.get(DeviceTypeProfile, device_type)
            if row is None:
                row = DeviceTypeProfile(device_type=device_type)
                session.add(row)
            row.high_upload_ratio_threshold = high_upload_ratio_threshold
            row.volume_sustained_polls = volume_sustained_polls
            row.contamination = contamination
            await session.flush()
            await session.refresh(row)
            return row

    async def delete_profile(self, device_type: str) -> bool:
        """Removes the override row, reverting that type to DEFAULT_PROFILE.
        Returns False if no such row existed (caller can 404)."""
        async with get_session() as session:
            row = await session.get(DeviceTypeProfile, device_type)
            if row is None:
                return False
            await session.delete(row)
            return True


class TrustedMacRepository:
    """Read/write access to the persistent trusted_macs registry.

    Deliberately a separate table from devices.is_trusted — that column lives
    on a row that gets wiped along with the rest of `devices` on a reset;
    this registry is meant to survive that (see the trusted_macs migration).
    """

    async def is_trusted(self, mac_address: str) -> bool:
        async with get_session() as session:
            return await session.get(TrustedMac, mac_address) is not None

    async def trust(self, mac_address: str) -> None:
        """Idempotent: no-op if already trusted."""
        async with get_session() as session:
            if await session.get(TrustedMac, mac_address) is None:
                session.add(TrustedMac(mac_address=mac_address, trusted_at=datetime.now(timezone.utc)))

    async def trust_many(self, mac_addresses: list[str]) -> None:
        """Bulk version of trust() — one statement instead of N sessions, for
        establishing a whole fresh-install baseline at once. Idempotent."""
        if not mac_addresses:
            return
        now = datetime.now(timezone.utc)
        stmt = pg_insert(TrustedMac).values([
            {'mac_address': mac, 'trusted_at': now} for mac in mac_addresses
        ]).on_conflict_do_nothing(index_elements=['mac_address'])
        async with get_session() as session:
            await session.execute(stmt)

    async def untrust(self, mac_address: str) -> None:
        async with get_session() as session:
            existing = await session.get(TrustedMac, mac_address)
            if existing is not None:
                await session.delete(existing)

    async def is_empty(self) -> bool:
        """True if the trusted_macs registry has no entries at all."""
        async with get_session() as session:
            result = await session.execute(select(TrustedMac.mac_address).limit(1))
            return result.first() is None


class AlertRepository:
    """Read/write access to the alerts table's fire/active/resolve
    lifecycle — see the alert lifecycle redesign plan. Every alert-creation
    call site (the detection pipeline, RuleEngine, SentinelScheduler's
    confirmed-attack sources) routes through upsert()/resolve() instead of
    inserting a fresh row on every poll a condition stays true: a still-true
    condition touches the one open row (bumping last_seen/occurrence_count,
    overwriting description/raw_data/severity with the latest values) rather
    than flooding inserts.
    """

    async def upsert(
        self, *, device_mac: str | None, alert_type: str, severity: str, description: str | None,
        raw_data: dict | None = None, mitigation: str | None = None, dedup_key: str | None = None,
    ) -> tuple[Alert | None, bool]:
        """Finds the OPEN (resolved=False) row matching device_mac +
        alert_type + dedup_key. Found -> UPDATE in place (touch) and return
        (alert, False). Not found -> INSERT (the "fire" transition) and
        return (alert, True).

        device_mac and dedup_key are both nullable and matched NULL-safely
        via isnot_distinct_from() — plain `==` never matches SQL NULL, which
        would silently defeat the upsert for e.g. WanBandwidthDetector's
        always-null device_mac.

        A touch MERGES raw_data onto the existing row rather than replacing
        it wholesale (row.raw_data = {**old, **new}, new values winning on
        key conflicts) — confirmed a real bug, not just a theoretical risk:
        SentinelScheduler._spike_ip_enrichment_job annotates a still-open
        HIGH_UPLOAD/ANOMALOUS_VOLUME/WAN_BANDWIDTH_SPIKE alert's raw_data
        with remote_ip/ip_enrichment_done out-of-band (via merge_raw_data,
        itself already a proper merge), entirely independent of the
        detector's own fire/touch cycle. A wholesale replace here meant the
        very next touch of a still-sustained condition (the detector always
        passes its own bare raw_data — ratio/bytes_sent_delta/etc., no
        knowledge the enrichment job exists at all) silently erased that
        annotation, and since ip_enrichment_done went with it, the next
        enrichment sweep saw an apparently-unenriched alert and did the
        work over again — a wasted Zeek/threat-intel lookup every ~5
        minutes for as long as the condition stayed sustained, not just a
        display glitch.

        Snooze check: if (device_mac, alert_type) has an active row in
        alert_snoozes (see AlertSnoozeRepository), this is a complete no-op
        — returns (None, False) without touching or inserting anything, as
        if the condition had never fired at all. This is the single choke
        point every alert-creation path already routes through (see this
        class's own docstring), so gating here covers all of them uniformly
        with no per-detector/per-source special-casing. Every existing
        caller only ever uses the returned Alert when is_new is True, so
        None here is safe — never dereferenced on the snoozed path.
        Household-level alerts (device_mac=None, e.g. WAN_BANDWIDTH_SPIKE)
        have nothing to match against and are never snoozable this way.
        """
        async with get_session() as session:
            if device_mac is not None:
                snooze = await session.get(AlertSnooze, (device_mac, alert_type))
                if snooze is not None and snooze.snoozed_until > datetime.now(timezone.utc):
                    return None, False

            stmt = select(Alert).where(
                Alert.device_mac.isnot_distinct_from(device_mac),
                Alert.alert_type == alert_type,
                Alert.dedup_key.isnot_distinct_from(dedup_key),
                Alert.resolved.is_(False),
            )
            row = (await session.execute(stmt)).scalars().first()
            if row is None:
                row = Alert(
                    device_mac=device_mac, alert_type=alert_type, severity=severity,
                    description=description, raw_data=raw_data, mitigation=mitigation,
                    dedup_key=dedup_key,
                )
                session.add(row)
                await session.flush()
                await session.refresh(row)
                return row, True

            row.severity = severity
            row.description = description
            row.raw_data = {**(row.raw_data or {}), **(raw_data or {})}
            row.mitigation = mitigation
            row.last_seen = datetime.now(timezone.utc)
            row.occurrence_count += 1
            await session.flush()
            await session.refresh(row)
            return row, False

    async def resolve(
        self, *, device_mac: str | None, alert_type: str, dedup_key: str | None = None,
    ) -> bool:
        """UPDATE resolved=true, resolved_at=now() on the still-open row
        matching device_mac + alert_type + dedup_key. Returns whether a row
        was actually closed (False if nothing was open)."""
        async with get_session() as session:
            stmt = select(Alert).where(
                Alert.device_mac.isnot_distinct_from(device_mac),
                Alert.alert_type == alert_type,
                Alert.dedup_key.isnot_distinct_from(dedup_key),
                Alert.resolved.is_(False),
            )
            row = (await session.execute(stmt)).scalars().first()
            if row is None:
                return False
            row.resolved = True
            row.resolved_at = datetime.now(timezone.utc)
            return True

    async def resolve_stale_open(self, older_than: timedelta) -> int:
        """Bulk sweep for sources with no natural "this stopped" signal of
        their own (ArpWatcher/DhcpWatcher/OpenCanary/Zeek/Suricata/nmap
        findings) — closes every open row whose last_seen predates the
        cutoff. Returns the count closed. Used by
        SentinelScheduler._alert_auto_resolve_job.
        """
        cutoff = datetime.now(timezone.utc) - older_than
        async with get_session() as session:
            stmt = select(Alert).where(Alert.resolved.is_(False), Alert.last_seen < cutoff)
            rows = (await session.execute(stmt)).scalars().all()
            now = datetime.now(timezone.utc)
            for row in rows:
                row.resolved = True
                row.resolved_at = now
            return len(rows)

    async def merge_raw_data(self, alert_id: int, extra: dict) -> bool:
        """Shallow-merges extra into an existing alert's raw_data — a one-off
        post-hoc annotation (e.g. SentinelScheduler._spike_ip_enrichment_job),
        not part of the upsert()/resolve() lifecycle above: it doesn't touch
        resolved/last_seen/occurrence_count, and is keyed by primary key
        rather than the (device_mac, alert_type, dedup_key) match upsert()
        uses — the caller already has the exact row, so re-deriving the
        match would risk touching a different, newer occurrence of the same
        open alert. Returns False if the alert no longer exists.

        raw_data is a plain JSONB column (not MutableDict-tracked), so
        SQLAlchemy only detects a whole-value reassignment, never an
        in-place dict mutation — same reasoning as upsert()'s touch path
        above (row.raw_data = raw_data, never row.raw_data.update(...)).
        """
        async with get_session() as session:
            row = await session.get(Alert, alert_id)
            if row is None:
                return False
            row.raw_data = {**(row.raw_data or {}), **extra}
            return True


class AlertSnoozeRepository:
    """Read/write access to the alert_snoozes table — see AlertSnooze's
    docstring and AlertRepository.upsert()'s snooze check, the single
    choke point that actually enforces an active snooze."""

    async def snooze(self, device_mac: str, alert_type: str, until: datetime) -> None:
        """Create or replace the active snooze for (device_mac, alert_type),
        and immediately acknowledge every currently-open, unacknowledged
        alert matching that pair (there can be more than one — e.g. nmap's
        dedup_key=f'port:{port}' means two different high-risk ports open
        on the same device are two separate open rows under the same
        alert_type). Without this, snoozing would only stop *new*
        occurrences from appearing (via AlertRepository.upsert()'s check)
        while whatever's already open kept sitting in every unacknowledged
        view until it happened to resolve on its own — the whole point of
        snoozing is to get it out of the way right now, not just eventually.

        Re-snoozing an already-snoozed pair replaces snoozed_until with the
        new value rather than accumulating rows — same on_conflict_do_update
        shape as TrustedMacRepository.trust_many's on_conflict_do_nothing,
        just updating instead of skipping since a second snooze call is
        meant to move the expiry, not be a no-op."""
        stmt = pg_insert(AlertSnooze).values(
            device_mac=device_mac, alert_type=alert_type, snoozed_until=until,
        ).on_conflict_do_update(
            index_elements=['device_mac', 'alert_type'], set_={'snoozed_until': until},
        )
        async with get_session() as session:
            await session.execute(stmt)
            await session.execute(
                update(Alert)
                .where(
                    Alert.device_mac == device_mac,
                    Alert.alert_type == alert_type,
                    Alert.resolved.is_(False),
                    Alert.acknowledged.is_(False),
                )
                .values(acknowledged=True, acknowledged_at=datetime.now(timezone.utc))
            )

    async def unsnooze(self, device_mac: str, alert_type: str) -> bool:
        """Cancel an active snooze early. Returns whether one existed."""
        async with get_session() as session:
            existing = await session.get(AlertSnooze, (device_mac, alert_type))
            if existing is None:
                return False
            await session.delete(existing)
            return True

    async def list_active(self, device_mac: str) -> list[AlertSnooze]:
        """Every currently-active (not yet expired) snooze for one device —
        powers the device page's "snoozed" badges/cancel buttons. Expired
        rows are left in place rather than swept (harmless clutter, not a
        correctness issue — is_snoozed()/upsert()'s own check already
        ignores them), so this filters snoozed_until > now() rather than
        just listing every row."""
        async with get_session() as session:
            result = await session.execute(
                select(AlertSnooze).where(
                    AlertSnooze.device_mac == device_mac,
                    AlertSnooze.snoozed_until > datetime.now(timezone.utc),
                )
            )
            return list(result.scalars().all())


class PortAllowlistRepository:
    """Read/write access to the port_allowlist table — see
    PortAllowlistEntry's docstring and SentinelScheduler._nmap_scan_job's
    allowed_ports filter, the single enforcement point that actually
    excludes an allowlisted port from HIGH_RISK_PORTS detection."""

    async def allow(self, device_mac: str, port: int, service: str, note: str | None = None) -> PortAllowlistEntry:
        """Create or replace the allowlist entry for (device_mac, port) —
        re-adding an already-allowlisted pair updates service/note rather
        than erroring or duplicating."""
        stmt = pg_insert(PortAllowlistEntry).values(
            device_mac=device_mac, port=port, service=service, note=note,
        ).on_conflict_do_update(
            index_elements=['device_mac', 'port'], set_={'service': service, 'note': note},
        )
        async with get_session() as session:
            await session.execute(stmt)
            return await session.get(PortAllowlistEntry, (device_mac, port))

    async def disallow(self, device_mac: str, port: int) -> bool:
        """Remove an entry — the port resumes normal HIGH_RISK_PORTS
        detection on the device's next nmap scan. Returns whether one existed."""
        async with get_session() as session:
            existing = await session.get(PortAllowlistEntry, (device_mac, port))
            if existing is None:
                return False
            await session.delete(existing)
            return True

    async def allowed_ports_for(self, device_mac: str) -> set[int]:
        """Every port currently allowlisted for one device — batched lookup
        for _nmap_scan_job's per-device port comparison, so checking N
        candidate high-risk ports costs one query, not N."""
        async with get_session() as session:
            result = await session.execute(
                select(PortAllowlistEntry.port).where(PortAllowlistEntry.device_mac == device_mac)
            )
            return set(result.scalars().all())

    async def list_all(self) -> list[PortAllowlistEntry]:
        """Every allowlist entry across every device — powers the Rules
        tab's allowlist section."""
        async with get_session() as session:
            result = await session.execute(
                select(PortAllowlistEntry).order_by(PortAllowlistEntry.created_at.desc())
            )
            return list(result.scalars().all())


class SettingsRepository:
    """Read/write access to the singleton app_settings row — the runtime-
    overridable layer on top of the static, env-backed Settings object (see
    sentinel/config.py). Detectors/jobs read through this rather than
    Settings directly wherever a value must be changeable from the frontend
    Settings tab without restarting the process.
    """

    async def get_all(self) -> dict:
        """Everything the /api/settings GET route needs, one query instead of
        three. Falls back to the matching Settings.* env default per field
        until an admin overrides it (no row yet — e.g. a fresh install)."""
        async with get_session() as session:
            row = await session.get(AppSettings, _SETTINGS_ROW_ID)
            return {
                'ml_learning_period_hours': (
                    row.ml_learning_period_hours if row else settings.ML_LEARNING_PERIOD_HOURS
                ),
                'data_retention_days': row.data_retention_days if row else settings.DATA_RETENTION_DAYS,
                'baseline_established_at': row.baseline_established_at if row else None,
                'armed_retrain_done': row.armed_retrain_done if row else False,
                'sniff_iface': (row.sniff_iface if row and row.sniff_iface else settings.SNIFF_IFACE),
                'router_username': (
                    row.router_username if row and row.router_username else settings.ROUTER_USERNAME
                ),
                'miwifi_ip': row.miwifi_ip if row and row.miwifi_ip else settings.MIWIFI_IP,
                'active_router': row.active_router if row and row.active_router else 'sagemcom',
                'ntfy_url': row.ntfy_url if row and row.ntfy_url else settings.NTFY_URL,
                'smtp_host': row.smtp_host if row and row.smtp_host else settings.SMTP_HOST,
                'smtp_port': row.smtp_port if row and row.smtp_port else settings.SMTP_PORT,
                'smtp_from': row.smtp_from if row and row.smtp_from else settings.SMTP_FROM,
                'smtp_to': row.smtp_to if row and row.smtp_to else settings.SMTP_TO,
                'smtp_username': row.smtp_username if row and row.smtp_username else settings.SMTP_USERNAME,
                'smtp_use_tls': (
                    row.smtp_use_tls if row and row.smtp_use_tls is not None else settings.SMTP_USE_TLS
                ),
                'telegram_chat_id': (
                    row.telegram_chat_id if row and row.telegram_chat_id else settings.TELEGRAM_CHAT_ID
                ),
                'auto_block_on_threat': row.auto_block_on_threat if row else True,
                'auto_block_expiry_hours': row.auto_block_expiry_hours if row else 24,
                'last_digest_sent_at': row.last_digest_sent_at if row else None,
                'alert_stale_hours': row.alert_stale_hours if row else 24,
                'alert_auto_resolve_hours': row.alert_auto_resolve_hours if row else 72,
                'device_archive_after_days': row.device_archive_after_days if row else 90,
                'device_purge_after_days': row.device_purge_after_days if row else 90,
                'wifi_monitor_iface': row.wifi_monitor_iface if row else None,
                'wifi_protected_ssids': list(row.wifi_protected_ssids or []) if row else [],
                'wifi_trusted_bssids': list(row.wifi_trusted_bssids or []) if row else [],
            }

    async def get_ml_learning_period_hours(self) -> int:
        return (await self.get_all())['ml_learning_period_hours']

    async def set_ml_learning_period_hours(self, hours: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.ml_learning_period_hours = hours

    async def get_data_retention_days(self) -> int:
        return (await self.get_all())['data_retention_days']

    async def set_data_retention_days(self, days: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.data_retention_days = days

    async def get_sniff_iface(self) -> str:
        return (await self.get_all())['sniff_iface']

    async def set_sniff_iface(self, iface: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.sniff_iface = iface

    async def get_router_username(self) -> str:
        return (await self.get_all())['router_username']

    async def set_router_username(self, username: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.router_username = username

    async def get_miwifi_ip(self) -> str:
        return (await self.get_all())['miwifi_ip']

    async def set_miwifi_ip(self, ip: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.miwifi_ip = ip

    async def get_active_router(self) -> str:
        return (await self.get_all())['active_router']

    async def set_active_router(self, router: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.active_router = router

    async def get_ntfy_url(self) -> str:
        return (await self.get_all())['ntfy_url']

    async def set_ntfy_url(self, url: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.ntfy_url = url

    async def get_telegram_chat_id(self) -> str:
        return (await self.get_all())['telegram_chat_id']

    async def set_telegram_chat_id(self, chat_id: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.telegram_chat_id = chat_id

    async def get_smtp_settings(self) -> dict:
        """The non-secret SMTP fields — host/port/from/to/username/use_tls.
        smtp_password is deliberately excluded; it lives in Settings.SMTP_PASSWORD
        (sourced from SMTP_PASSWORD_FILE on disk), never in this table."""
        data = await self.get_all()
        return {
            'smtp_host': data['smtp_host'],
            'smtp_port': data['smtp_port'],
            'smtp_from': data['smtp_from'],
            'smtp_to': data['smtp_to'],
            'smtp_username': data['smtp_username'],
            'smtp_use_tls': data['smtp_use_tls'],
        }

    async def set_smtp_settings(
        self, *, smtp_host: str, smtp_port: int, smtp_from: str,
        smtp_to: str, smtp_username: str, smtp_use_tls: bool,
    ) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.smtp_host = smtp_host
            row.smtp_port = smtp_port
            row.smtp_from = smtp_from
            row.smtp_to = smtp_to
            row.smtp_username = smtp_username
            row.smtp_use_tls = smtp_use_tls

    async def get_auto_block_on_threat(self) -> bool:
        return (await self.get_all())['auto_block_on_threat']

    async def set_auto_block_on_threat(self, enabled: bool) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.auto_block_on_threat = enabled

    async def get_auto_block_expiry_hours(self) -> int:
        return (await self.get_all())['auto_block_expiry_hours']

    async def set_auto_block_expiry_hours(self, hours: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.auto_block_expiry_hours = hours

    async def get_last_digest_sent_at(self) -> datetime | None:
        return (await self.get_all())['last_digest_sent_at']

    async def set_last_digest_sent_at(self, ts: datetime | None) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.last_digest_sent_at = ts

    async def get_alert_stale_hours(self) -> int:
        return (await self.get_all())['alert_stale_hours']

    async def set_alert_stale_hours(self, hours: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.alert_stale_hours = hours

    async def get_alert_auto_resolve_hours(self) -> int:
        return (await self.get_all())['alert_auto_resolve_hours']

    async def set_alert_auto_resolve_hours(self, hours: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.alert_auto_resolve_hours = hours

    async def get_device_archive_after_days(self) -> int:
        return (await self.get_all())['device_archive_after_days']

    async def set_device_archive_after_days(self, days: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.device_archive_after_days = days

    async def get_device_purge_after_days(self) -> int:
        return (await self.get_all())['device_purge_after_days']

    async def set_device_purge_after_days(self, days: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.device_purge_after_days = days

    async def set_baseline_established_at(self, ts: datetime | None) -> None:
        """ts=None marks "no baseline yet" — used by POST /api/settings/purge
        to put the system back into a fresh-install LEARNING state. Also
        resets armed_retrain_done — a new baseline (or a cleared one) means
        a new learning cycle, which must retrain from scratch once it arms
        again, not skip the retrain because a *previous* cycle already did
        one."""
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.baseline_established_at = ts
            row.armed_retrain_done = False

    async def get_armed_retrain_done(self) -> bool:
        return (await self.get_all())['armed_retrain_done']

    async def set_armed_retrain_done(self, done: bool) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.armed_retrain_done = done

    async def get_status(self) -> str:
        """'LEARNING' until the current baseline has aged past the
        configured learning period; 'ARMED' afterward.

        A pre-existing install that predates this feature (devices already
        exist but baseline_established_at was never stamped) is
        grandfathered straight to ARMED rather than forcing a fake new
        learning period onto an already-established network — see
        DeviceRepository.is_empty().

        Single source of truth for both GET/PATCH /api/settings (the status
        badge) and the poll cycle's auto-trust-during-learning policy (see
        sentinel/scheduler/jobs.py) — they must never disagree about which
        state the system is in.
        """
        data = await self.get_all()
        baseline_at = data['baseline_established_at']
        if baseline_at is None:
            return 'LEARNING' if await DeviceRepository().is_empty() else 'ARMED'

        age = datetime.now(timezone.utc) - baseline_at
        return 'ARMED' if age >= timedelta(hours=data['ml_learning_period_hours']) else 'LEARNING'

    async def get_wifi_monitor_iface(self) -> str | None:
        return (await self.get_all())['wifi_monitor_iface']

    async def set_wifi_monitor_iface(self, iface: str | None) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.wifi_monitor_iface = iface

    async def get_wifi_protected_ssids(self) -> list[str]:
        return (await self.get_all())['wifi_protected_ssids']

    async def set_wifi_protected_ssids(self, ssids: list[str]) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.wifi_protected_ssids = ssids

    async def get_wifi_trusted_bssids(self) -> list[str]:
        return (await self.get_all())['wifi_trusted_bssids']

    async def set_wifi_trusted_bssids(self, bssids: list[str]) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.wifi_trusted_bssids = [b.lower() for b in bssids]

    async def _get_or_create(self, session) -> AppSettings:
        row = await session.get(AppSettings, _SETTINGS_ROW_ID)
        if row is None:
            row = AppSettings(id=_SETTINGS_ROW_ID)
            session.add(row)
        return row


class RouterProfileRepository:
    """Read/write access to router_profiles — the routers picked on the
    Equipment tab (non-secret fields only; see RouterProfile)."""

    async def list_all(self) -> list[RouterProfile]:
        async with get_session() as session:
            rows = await session.scalars(select(RouterProfile).order_by(RouterProfile.created_at))
            return list(rows)

    async def get(self, router_id: str) -> RouterProfile | None:
        async with get_session() as session:
            return await session.get(RouterProfile, router_id)

    async def upsert(self, router_id: str, *, host: str | None, username: str | None) -> None:
        """Create the profile, or update only the fields that are not None."""
        async with get_session() as session:
            row = await session.get(RouterProfile, router_id)
            if row is None:
                session.add(RouterProfile(router_id=router_id, host=host or '', username=username or ''))
                return
            if host is not None:
                row.host = host
            if username is not None:
                row.username = username
            row.updated_at = datetime.now(timezone.utc)

    async def delete(self, router_id: str) -> None:
        async with get_session() as session:
            await session.execute(delete(RouterProfile).where(RouterProfile.router_id == router_id))


class WifiSightingRepository:
    """Read/write access to wifi_sightings — see sentinel/db/models.py:
    WifiSighting and sentinel/security/wifi_monitor.py. Deliberately
    separate from AlertRepository: a sighting is passive inventory, not an
    attack signal, and has no fire/resolve lifecycle."""

    async def upsert(self, mac: str, *, signal: int | None, probed_ssid: str | None) -> None:
        """Insert on first sighting; on every later one, bump times_seen,
        touch last_seen, update last_probed_ssid, and keep the STRONGEST
        (least negative) signal ever seen rather than overwriting with
        whatever this particular sighting reports — see
        WifiSighting.strongest_signal_dbm's docstring for why."""
        async with get_session() as session:
            row = await session.get(WifiSighting, mac)
            if row is None:
                session.add(WifiSighting(
                    mac_address=mac, vendor_name=lookup_vendor(mac),
                    strongest_signal_dbm=signal, last_probed_ssid=probed_ssid,
                ))
                return
            row.last_seen = datetime.now(timezone.utc)
            row.times_seen += 1
            if probed_ssid:
                row.last_probed_ssid = probed_ssid
            if signal is not None and (row.strongest_signal_dbm is None or signal > row.strongest_signal_dbm):
                row.strongest_signal_dbm = signal

    async def list_recent(self, limit: int = 200) -> list[WifiSighting]:
        async with get_session() as session:
            result = await session.execute(
                select(WifiSighting).order_by(WifiSighting.last_seen.desc()).limit(limit)
            )
            return list(result.scalars().all())

    async def set_mine(self, mac: str, mine: bool) -> bool:
        """Returns False if this MAC has no wifi_sightings row (nothing to
        mark — a sighting is only ever created by the watcher itself, never
        by this endpoint)."""
        async with get_session() as session:
            row = await session.get(WifiSighting, mac)
            if row is None:
                return False
            row.is_mine = mine
            return True


class WifiNetworkRepository:
    """Read/write access to wifi_networks — see WifiNetwork. Passive
    inventory like WifiSightingRepository, not a threat finding (rogue-AP
    detection happens separately, in WifiMonitorWatcher._process)."""

    async def upsert(
        self, bssid: str, *, ssid: str, channel: int | None, signal: int | None, secured: bool,
    ) -> None:
        async with get_session() as session:
            row = await session.get(WifiNetwork, bssid)
            if row is None:
                session.add(WifiNetwork(
                    bssid=bssid, ssid=ssid, vendor_name=lookup_vendor(bssid), channel=channel,
                    strongest_signal_dbm=signal, secured=secured,
                ))
                return
            row.last_seen = datetime.now(timezone.utc)
            row.ssid = ssid
            row.secured = secured
            if channel is not None:
                row.channel = channel
            if signal is not None and (row.strongest_signal_dbm is None or signal > row.strongest_signal_dbm):
                row.strongest_signal_dbm = signal

    async def list_recent(self, limit: int = 300) -> list[WifiNetwork]:
        async with get_session() as session:
            result = await session.execute(select(WifiNetwork).order_by(WifiNetwork.last_seen.desc()).limit(limit))
            return list(result.scalars().all())


class AdminAccountRepository:
    """Read/write access to admin_account — the one dashboard login created on first run."""

    async def get(self) -> AdminAccount | None:
        async with get_session() as session:
            return await session.get(AdminAccount, 1)

    async def create(self, username: str, password_hash: str) -> bool:
        """Insert the account; False if one already exists. The primary key makes this
        safe against two browsers racing through first-run setup: exactly one wins."""
        async with get_session() as session:
            result = await session.execute(
                pg_insert(AdminAccount).values(id=1, username=username, password_hash=password_hash)
                .on_conflict_do_nothing()
            )
            return result.rowcount == 1
