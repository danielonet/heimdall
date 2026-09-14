import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import (
    DeviceSnapshot,
    DhcpLease,
    PortStats,
    RouterInfo,
    TrafficGranularity,
    TrafficSample,
    WanStats,
)
# TrafficDeltaCalculator is a generic cumulative-counter -> per-interval-delta
# helper (see its own docstring) — it has no Sagemcom-specific logic, so it's
# reused here rather than duplicated. It happens to live under the sagemcom
# package because that's the adapter that introduced it first.
from sentinel.adapter.sagemcom.delta import TrafficDeltaCalculator

from .miwifi_auth import MiwifiAuth
from .miwifi_client import MiwifiClient, field

logger = logging.getLogger(__name__)

_SOURCE_ROUTER = 'miwifi'


class MiwifiAdapter(RouterAdapter):
    """RouterAdapter implementation for a Redmi/Xiaomi router on stock MiWiFi
    firmware, talking to its `/cgi-bin/luci/;stok=.../api/...` JSON API.

    ⚠️ Written against MiWiFi's well-known public API conventions (stok-token
    login, `misystem/devicelist`, `xqnetwork/*`), reproduced from independent
    community reverse-engineering of that API — **not yet confirmed live
    against this project's own Redmi unit**. See docs/router/miwifi-api.md
    for the exact endpoints assumed and the curl commands to verify/correct
    them. Every method below degrades gracefully (empty list / None / False)
    rather than raising when a response doesn't have the shape expected, so
    a wrong assumption here shows up as "this field is always blank/zero"
    rather than crashing the poll cycle — same defensive posture as
    SagemcomXmoAdapter's own '_scalar_str'/'_int_field' helpers.

    This is the only module that may communicate with the MiWiFi router.
    Every other sentinel module interacts only with the canonical models in
    adapter.models — see CLAUDE.md rule 1.
    """

    def __init__(self, router_ip: str, password: str, poll_interval_s: int = 15) -> None:
        self._base_url = f'http://{router_ip}'
        self._auth = MiwifiAuth(password)
        self._client = MiwifiClient(self._base_url, self._auth)
        self._delta = TrafficDeltaCalculator()
        self._poll_interval_s = poll_interval_s
        # Logged once, not every poll — see get_router_info()/get_dhcp_leases().
        self._router_info_warned = False

    # ──────────────────────────────────────────────────────────────────────────
    # RouterAdapter interface
    # ──────────────────────────────────────────────────────────────────────────

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Return every client MiWiFi's own device list currently knows
        about (associated or not — `online` distinguishes the two, mirrored
        into is_online here rather than filtering offline ones out, same as
        SagemcomXmoAdapter's Hosts table)."""
        clients = await self._get_device_list()
        return [self._to_device_snapshot(c) for c in clients]

    def invalidate_connected_devices_cache(self) -> None:
        """No-op — get_connected_devices() isn't cached here (this adapter
        is polled on its own independent, already-infrequent cycle rather
        than shared with high-frequency callers). Present only so callers
        never need to know which adapter kind they're holding — see
        RouterAdapter's docstring."""

    async def get_traffic_samples(self) -> List[TrafficSample]:
        """Per-device traffic deltas from each client's cumulative
        `statistics.upload`/`download` counters (bytes since the router's
        own last boot/reset — same counter-reset guard as XMO's, via the
        shared TrafficDeltaCalculator). MiWiFi has no per-port Ethernet
        concept exposed by this API (see get_port_stats), so every sample
        here is PER_DEVICE.
        """
        clients = await self._get_device_list()
        samples: List[TrafficSample] = []
        now = datetime.now(timezone.utc)
        for client in clients:
            mac = _norm_mac(field(client, 'mac'))
            if not mac:
                continue
            stats = field(client, 'statistics', {})
            upload = _to_int(field(stats, 'upload', 0))
            download = _to_int(field(stats, 'download', 0))
            sample = self._delta.compute(
                key=mac, sent_now=upload, recv_now=download,
                granularity=TrafficGranularity.PER_DEVICE, poll_interval_s=self._poll_interval_s,
            )
            samples.append(TrafficSample(
                mac_address=sample.mac_address,
                timestamp=now,
                bytes_sent_delta=sample.bytes_sent_delta,
                bytes_recv_delta=sample.bytes_recv_delta,
                throughput_up_kbps=sample.throughput_up_kbps,
                throughput_dn_kbps=sample.throughput_dn_kbps,
                granularity=TrafficGranularity.PER_DEVICE,
                poll_interval_s=self._poll_interval_s,
                source_router=_SOURCE_ROUTER,
            ))
        return samples

    async def get_port_stats(self) -> List[PortStats]:
        """Consumer MiWiFi firmware exposes no per-port Ethernet counter API
        (unlike Sagemcom's XMO Device/Ethernet/Interfaces tree) — an empty
        list is a valid result under RouterAdapter's contract, not a
        failure."""
        return []

    async def block_device(self, mac: str) -> bool:
        """Add this MAC to MiWiFi's device access blacklist via
        `xqnetwork/set_mac_filter`. ⚠️ Endpoint/parameter names reproduced
        from community documentation of MiWiFi's device-management API, not
        confirmed live against this project's own unit — if this silently
        fails, capture the real request from the router's own web UI (Device
        management -> block this device) via browser devtools while blocking
        a test device by hand, and fix this to match. Returns False (not
        True) on anything other than an explicit success code, same
        "don't claim success we can't confirm" posture as
        SagemcomXmoAdapter.block_device.
        """
        mac = _norm_mac(mac)
        result = await self._client.post('xqnetwork/set_mac_filter', {'mac': mac, 'enable': '1'})
        ok = result.get('code') in (0, '0')
        if not ok:
            logger.error('block_device(%s): set_mac_filter rejected: %s', mac, result)
        else:
            logger.info('Blocked device %s via MiWiFi MAC filter', mac)
        return ok

    async def unblock_device(self, mac: str) -> bool:
        """Remove this MAC from MiWiFi's device access blacklist. Same
        endpoint/caveats as block_device."""
        mac = _norm_mac(mac)
        result = await self._client.post('xqnetwork/set_mac_filter', {'mac': mac, 'enable': '0'})
        ok = result.get('code') in (0, '0')
        if not ok:
            logger.error('unblock_device(%s): set_mac_filter rejected: %s', mac, result)
        else:
            logger.info('Unblocked device %s via MiWiFi MAC filter', mac)
        return ok

    async def quarantine_device(self, mac: str) -> bool:
        """Stock MiWiFi firmware has no confirmed, independently-documented
        WAN-only/LAN-reachable access tier equivalent to Sagemcom's
        Firewall Custom-chain rule (see SagemcomXmoAdapter.quarantine_device)
        — only the all-or-nothing MAC filter block_device already uses.
        Rather than silently no-op a security action as if it succeeded,
        this returns False and logs clearly; callers already treat a False
        return as "not enforced" (see RouterAdapter.quarantine_device's
        docstring) rather than raising.
        """
        logger.warning(
            'quarantine_device(%s): not supported by the MiWiFi adapter — no known WAN-only '
            'access tier on stock MiWiFi firmware; use block_device for a full block instead',
            _norm_mac(mac),
        )
        return False

    async def unquarantine_device(self, mac: str) -> bool:
        """See quarantine_device — nothing was ever created, so there's
        nothing to remove."""
        return False

    async def get_router_info(self) -> RouterInfo:
        """Router metadata from `misystem/status` (hardware/uptime) and
        `xqnetwork/wan_info` (WAN IP/status). ⚠️ Field names reproduced from
        community documentation, not confirmed live — degrades to blank
        fields rather than raising if the shape doesn't match, logging a
        warning once (not every poll)."""
        try:
            status = await self._client.get('misystem/status')
            wan = await self._client.get('xqnetwork/wan_info')
        except Exception:
            if not self._router_info_warned:
                logger.warning('MiWiFi get_router_info() failed — returning a mostly-blank RouterInfo', exc_info=True)
                self._router_info_warned = True
            return RouterInfo(source_router=_SOURCE_ROUTER)

        hardware = field(status, 'hardware', {})
        # CONFIRMED LIVE (2026-09-13) against a unit in AP/bridge mode:
        # `wan_info`'s `info` key is the boolean `False` (not an object) —
        # there's simply no WAN interface to report on in that mode. field()
        # already degrades a non-dict `wan_info` to {} for every lookup
        # below, so wan_ip/wan_mode end up correctly blank rather than
        # raising; wan_status is handled explicitly to avoid falling through
        # to the reply's numeric `code` (an earlier version of this method
        # did that and produced the nonsensical status string '0').
        wan_info = field(wan, 'info', {})
        wan_ip_block = field(wan_info, 'wanIp', {})
        wan_type = field(wan_info, 'wanType', '')
        wan_status_raw = str(field(wan_info, 'status', ''))
        if wan_type or field(wan_ip_block, 'ip', ''):
            wan_status = 'UP'
        elif wan_status_raw:
            wan_status = wan_status_raw.upper()
        else:
            wan_status = 'UNKNOWN'  # includes the confirmed AP-mode case (no WAN interface at all)

        return RouterInfo(
            # `hardware.platform` (e.g. 'RA67') is the model identifier —
            # confirmed live to match this exact unit's 'MiWiFi-RA67'
            # hostname elsewhere on the network. `hardware.version` is a
            # firmware/software version number ('1.4.31'), not a model name
            # — an earlier version of this method had the two swapped, and
            # used the non-existent top-level `rom` key for firmware instead
            # (always blank; this firmware has no such field).
            model=str(field(hardware, 'platform', '')) or 'Redmi router (MiWiFi)',
            firmware=str(field(hardware, 'version', '')),
            serial=str(field(hardware, 'sn', '')),
            wan_ip=str(field(wan_ip_block, 'ip', '')),
            wan_mac=str(field(hardware, 'mac', '')),
            wan_status=wan_status,
            wan_mode=str(wan_type),
            uptime_seconds=_to_int(float(field(status, 'upTime', 0) or 0)),
            ssids=await self._get_ssids(),
            radios=[],
            source_router=_SOURCE_ROUTER,
        )

    async def _get_ssids(self) -> list:
        """SSIDs from `xqnetwork/wifi_diag_detail_all` — CONFIRMED LIVE
        (2026-09-13): each radio's entry carries `ssid` (and, notably, its
        WiFi password in plaintext under `password` — deliberately never
        read here; nothing in this adapter or the models it builds should
        ever carry that value). Best-effort: returns [] rather than raising
        if the shape doesn't match on some other firmware version.
        """
        try:
            resp = await self._client.get('xqnetwork/wifi_diag_detail_all')
            radios = field(resp, 'info', [])
            return list(dict.fromkeys(
                str(field(r, 'ssid', '')) for r in radios if isinstance(r, dict) and field(r, 'ssid', '')
            ))
        except Exception:
            logger.debug('MiWiFi _get_ssids() failed — returning []', exc_info=True)
            return []

    async def get_wan_stats(self) -> Optional[WanStats]:
        """No confirmed cumulative WAN byte-counter endpoint on stock MiWiFi
        firmware (unlike Sagemcom's `.../IP_DATA/Stats`) — returns None,
        same as SagemcomXmoAdapter.get_wan_stats' own unverified-xpath
        fallback. Callers already treat None as "nothing to persist this
        cycle", and household WAN bandwidth tracking only makes sense for
        whichever router is actually the internet gateway in any case."""
        return None

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        """Best-effort MAC<->IP pairings from the device list itself, since
        no distinct DHCP-server-table endpoint is confirmed on this API —
        every currently-online client already carries its MAC/IP/hostname,
        which is the same information DhcpLease exists to carry. No lease
        expiry is available from this source, so lease_expires_at is always
        None (informational only, matching DhcpLease's own "best-effort"
        framing).
        """
        clients = await self._get_device_list()
        leases: List[DhcpLease] = []
        for client in clients:
            if not _to_int(field(client, 'online', 1)):  # see _to_device_snapshot's docstring
                continue
            mac = _norm_mac(field(client, 'mac'))
            ip_entries = field(client, 'ip', [])
            ip = str(field(ip_entries[0], 'ip', '')) if ip_entries else ''
            if not mac or not ip:
                continue
            leases.append(DhcpLease(mac_address=mac, ip_address=ip, hostname=str(field(client, 'oname', ''))))
        return leases

    async def aclose(self) -> None:
        """Release underlying HTTP connections."""
        await self._client.aclose()

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    async def _get_device_list(self) -> List[dict]:
        """Raw client dicts — prefers `misystem/devicelist`'s richer
        per-client shape (ip/hostname/cumulative traffic totals), which
        CONFIRMED LIVE (2026-09-13) is only ever populated when this MiWiFi
        unit is acting as the network's own router/gateway (`xqnetwork/mode`
        == 0). Falls back to `xqnetwork/wifi_connect_devices` (mac/wifiIndex/
        signal only — no ip, hostname, or traffic counters) when devicelist
        comes back empty — CONFIRMED LIVE against a unit running in AP/
        bridge mode (`xqnetwork/mode` == 2, `hostip` pointing at the
        upstream Sagemcom): an AP-mode node doesn't run its own DHCP or
        route traffic, so it genuinely has no IP/hostname/byte-counters to
        report for its WiFi clients — not a wrong assumption to fix, a real
        capability gap for that mode. Downstream code (_to_device_snapshot,
        get_traffic_samples) already defaults every field `field()` can't
        find, so no other change is needed to handle either shape.
        """
        resp = await self._client.get('misystem/devicelist')
        clients = [c for c in field(resp, 'list', []) if isinstance(c, dict)]
        if clients:
            return clients

        resp = await self._client.get('xqnetwork/wifi_connect_devices')
        return [c for c in field(resp, 'list', []) if isinstance(c, dict)]

    def _to_device_snapshot(self, client: dict) -> DeviceSnapshot:
        """Convert one raw MiWiFi devicelist entry to a canonical
        DeviceSnapshot. Signal strength/rate aren't populated from the rich
        `misystem/devicelist` shape's own signal-ish fields (unconfirmed
        scale — see the sparse-fallback note below); left at their 0
        defaults rather than guessed, same "don't fabricate a reading"
        posture as SagemcomXmoAdapter when a field genuinely isn't
        available.

        `online` defaults to 1 (present), not 0, when the key is entirely
        absent — CONFIRMED LIVE (2026-09-13) that the sparse
        `xqnetwork/wifi_connect_devices` fallback shape (see
        _get_device_list) carries no `online` key at all, and every entry
        in that list is by definition a *currently associated* client (that
        endpoint has no way to list a disconnected one) — field()'s default
        is only ever used when the key is missing, so a `misystem/
        devicelist` entry that explicitly says `online: 0` is unaffected.
        """
        mac = _norm_mac(field(client, 'mac'))
        ip_entries = field(client, 'ip', [])
        ip = str(field(ip_entries[0], 'ip', '')) if ip_entries else ''
        return DeviceSnapshot(
            mac_address=mac,
            ip_address=ip,
            hostname=str(field(client, 'oname', '')),
            interface_name='WiFi',  # stock MiWiFi's devicelist is WiFi-client-oriented;
                                     # wired LAN ports aren't distinguished by this API
            is_online=bool(_to_int(field(client, 'online', 1))),
            source_router=_SOURCE_ROUTER,
        )


def _norm_mac(mac: Any) -> str:
    return str(mac or '').lower().strip()


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
