import logging
import re
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.discovery import discover_gateway_ip
from sentinel.adapter.models import (
    DeviceSnapshot,
    PortStats,
    RouterInfo,
    TrafficGranularity,
    TrafficSample,
)

from .delta import TrafficDeltaCalculator
from .xmo_auth import XmoAuth
from .xmo_client import XmoClient

logger = logging.getLogger(__name__)

_PORT_ALIASES = ['PHY1', 'PHY2', 'PHY3', 'PHY4', 'PHY5']

# WiFi access point aliases (2.4GHz/5GHz main, 2.4GHz/5GHz guest, mesh backhaul)
# confirmed live via Device/WiFi/AccessPoints/AccessPoint[@uid=N]/Alias — this
# firmware has a fixed set of AP slots, not user-configurable in count.
_ACCESS_POINT_ALIASES = ['PRIV0', 'VID1', 'GUEST2G', 'GUEST5G', 'AP_BACKHAUL']

# Firewall chain used for MAC-based device blocking
_BLOCK_CHAIN = 'Device/Firewall/Chain[Name="LAN_IN"]/Rule'


class SagemcomXmoAdapter(RouterAdapter):
    """RouterAdapter implementation for the Sagemcom F@st 5670 via its XMO JSON API.

    This is the only module that may communicate with the router. All other
    sentinel modules interact only with the canonical models in adapter.models.
    """

    def __init__(
        self,
        router_ip: str,
        password: str,
        router_port: int = 80,
        poll_interval_s: int = 15,
        username: str = 'admin',
    ) -> None:
        base_url = f'http://{router_ip}:{router_port}'
        self._auth = XmoAuth(password, username=username)
        self._client = XmoClient(base_url, self._auth)
        self._device_delta = TrafficDeltaCalculator()
        # port alias -> (bytes_sent_total, bytes_recv_total)
        self._port_prev: dict[str, Tuple[int, int]] = {}
        self._poll_interval_s = poll_interval_s
        # mac -> firewall rule UID (populated by block_device, consumed by unblock_device)
        self._block_rule_uids: dict[str, str] = {}

    # ──────────────────────────────────────────────────────────────────────────
    # RouterAdapter interface
    # ──────────────────────────────────────────────────────────────────────────

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Return all currently connected LAN devices."""
        hosts = await self._get_hosts()
        associated = await self._get_associated_devices()
        return [self._to_device_snapshot(h, associated) for h in hosts if isinstance(h, dict)]

    async def get_traffic_samples(self) -> List[TrafficSample]:
        """Return per-device (WiFi) and per-port (wired) traffic deltas.

        WiFi samples have granularity=PER_DEVICE.
        Wired port samples have granularity=PER_PORT and mac_address=port_alias.
        A wired port with exactly one device on it (no switch/hub sharing
        that port) additionally gets a PER_DEVICE sample too, since the
        port's whole traffic total unambiguously belongs to that one device —
        see _single_occupant_port_samples.
        """
        samples: List[TrafficSample] = []

        # WiFi: per-device bytes from the WiFi AssociatedDevices stats, not the
        # Host table (Device/Hosts entries have no byte counters on this
        # firmware — see _get_hosts).
        hosts = await self._get_hosts()
        associated = await self._get_associated_devices()

        for h in hosts:
            if not isinstance(h, dict):
                continue
            if h.get('InterfaceType') != 'WiFi':
                continue
            mac = _norm_mac(h.get('PhysAddress', ''))
            if not mac:
                continue
            ap_stats = associated.get(mac, {}).get('Stats', {})
            # Confirmed empirically against live traffic: from the AP's own
            # perspective, "Sent" is AP-to-device (the device's download) and
            # "Received" is device-to-AP (the device's upload) — the reverse
            # of the WAN interface's Sent/Received convention. compute()'s
            # sent_now always maps to throughput_up, so the AP fields are
            # passed in swapped here.
            device_download = _int_field(ap_stats, 'BytesSent')
            device_upload = _int_field(ap_stats, 'BytesReceived')
            sample = self._device_delta.compute(
                mac, device_upload, device_download, TrafficGranularity.PER_DEVICE, self._poll_interval_s
            )
            samples.append(sample)

        # Wired: per-port aggregate (PHY1–PHY5)
        port_samples = await self._get_port_traffic_samples()
        samples.extend(port_samples)
        samples.extend(self._single_occupant_port_samples(hosts, port_samples))

        return samples

    def _single_occupant_port_samples(
        self, hosts: List[dict], port_samples: List[TrafficSample],
    ) -> List[TrafficSample]:
        """For any PHY port with exactly one *currently active* wired device
        attached, that port's traffic total unambiguously belongs to that
        device — copy it into a PER_DEVICE sample too. Ports shared by more
        than one device (a switch/hub downstream) can't be split apart; the
        router has no visibility past the switch — see docs/router/
        wired-monitoring-caveat.md. Only active hosts count towards occupancy
        — a stale/historical Host entry pointing at a port it's no longer
        actually plugged into shouldn't make a genuinely single-occupant port
        look shared.
        """
        macs_by_port: dict[str, List[str]] = {}
        for h in hosts:
            if not isinstance(h, dict) or h.get('InterfaceType') == 'WiFi' or not _is_active(h):
                continue
            alias = _parse_port_alias(h.get('Layer1Interface', ''))
            mac = _norm_mac(h.get('PhysAddress', ''))
            if alias and mac:
                macs_by_port.setdefault(alias, []).append(mac)

        port_samples_by_alias = {s.port_alias: s for s in port_samples}
        device_samples: List[TrafficSample] = []
        for alias, macs in macs_by_port.items():
            if len(macs) != 1:
                continue
            port_sample = port_samples_by_alias.get(alias)
            if port_sample is None:
                continue
            device_samples.append(TrafficSample(
                mac_address=macs[0],
                timestamp=port_sample.timestamp,
                bytes_sent_delta=port_sample.bytes_sent_delta,
                bytes_recv_delta=port_sample.bytes_recv_delta,
                throughput_up_kbps=port_sample.throughput_up_kbps,
                throughput_dn_kbps=port_sample.throughput_dn_kbps,
                granularity=TrafficGranularity.PER_DEVICE,
                poll_interval_s=self._poll_interval_s,
            ))
        return device_samples

    async def get_port_stats(self) -> List[PortStats]:
        """Return per-physical-port Ethernet stats (PHY1–PHY5)."""
        # Build one batched request: Stats + Status + CurrentBitRate + LastChange per port
        actions: list[dict] = []
        action_id = 0
        port_action_ids: dict[str, dict[str, int]] = {}

        for alias in _PORT_ALIASES:
            base = f'Device/Ethernet/Interfaces/Interface[Alias="{alias}"]'
            ids: dict[str, int] = {}
            for sub in ('Stats', 'Status', 'CurrentBitRate', 'LastChange'):
                actions.append({'id': action_id, 'method': 'getValue', 'xpath': f'{base}/{sub}'})
                ids[sub] = action_id
                action_id += 1
            port_action_ids[alias] = ids

        resp = await self._client.post(actions)
        now = datetime.now(timezone.utc)
        result: List[PortStats] = []

        for alias in _PORT_ALIASES:
            ids = port_action_ids[alias]
            stats = self._client._extract_result(resp, ids['Stats']) or {}
            if isinstance(stats, list) and stats:
                stats = stats[0]
            status_raw = self._client._extract_result(resp, ids['Status'])
            bitrate_raw = self._client._extract_result(resp, ids['CurrentBitRate'])
            lastchange_raw = self._client._extract_result(resp, ids['LastChange'])

            status = _scalar_str(status_raw, 'DOWN')
            bitrate = _scalar_int(bitrate_raw)
            lastchange = _scalar_int(lastchange_raw)

            sent_total = _int_field(stats, 'BytesSent')
            recv_total = _int_field(stats, 'BytesReceived')

            prev = self._port_prev.get(alias)
            sent_delta = recv_delta = 0
            if prev is not None:
                sent_delta = sent_total - prev[0] if sent_total >= prev[0] else sent_total
                recv_delta = recv_total - prev[1] if recv_total >= prev[1] else recv_total
            self._port_prev[alias] = (sent_total, recv_total)

            result.append(PortStats(
                port_alias=alias,
                timestamp=now,
                status=status,
                link_speed_mbps=bitrate,
                bytes_sent_total=sent_total,
                bytes_recv_total=recv_total,
                sent_delta=sent_delta,
                recv_delta=recv_delta,
                errors_sent=_int_field(stats, 'ErrorsSent'),
                errors_recv=_int_field(stats, 'ErrorsReceived'),
                discards_recv=_int_field(stats, 'DiscardPacketsReceived'),
                broadcast_recv=_int_field(stats, 'BroadcastPacketsReceived'),
                last_change_secs=lastchange,
            ))

        return result

    async def block_device(self, mac: str) -> bool:
        """Add a firewall DROP rule for the given MAC address."""
        mac = _norm_mac(mac)
        resp = await self._client.add_object(
            _BLOCK_CHAIN,
            {
                'SourceMACAddress': mac,
                'Target': 'DROP',
                'Enable': True,
                'Description': f'SENTINEL_BLOCK_{mac}',
            },
        )
        # Extract the UID of the newly created rule so we can delete it later
        uid = self._extract_added_uid(resp)
        if uid:
            self._block_rule_uids[mac] = uid
            logger.info('Blocked device %s (rule uid=%s)', mac, uid)
        else:
            logger.warning('block_device(%s): could not extract rule UID from response', mac)
        return True

    async def unblock_device(self, mac: str) -> bool:
        """Remove the firewall DROP rule for the given MAC address."""
        mac = _norm_mac(mac)
        uid = self._block_rule_uids.pop(mac, None)
        if uid is None:
            logger.warning('unblock_device(%s): no stored rule UID — was block_device called?', mac)
            return False
        await self._client.delete_object(
            f'Device/Firewall/Chain[Name="LAN_IN"]/Rule[@uid="{uid}"]'
        )
        logger.info('Unblocked device %s (removed rule uid=%s)', mac, uid)
        return True

    async def get_router_info(self) -> RouterInfo:
        """Return router metadata: model, firmware, uptime, WAN status.

        Several fields here were confirmed wrong against a live router and
        fixed: `Device/DeviceInfo` has no `WANMACAddress` field (that's just
        `MACAddress`); the WAN IP was never fetched at all (it lives at
        `Device/IP/Interfaces/Interface[Alias='IP_DATA']/IPv4Addresses[0]/
        IPAddress`, one level deeper than the `/Status` xpath previously
        fetched); SSIDs were never fetched at all; and `Device/Services/
        NetworkCfg/CurrentWanMode` doesn't exist on this firmware
        (XMO_UNKNOWN_PATH_ERR) — wan_mode is inferred instead from whether the
        WAN interface's LowerLayers reference a PPP interface, since no
        working direct xpath for it has been found yet (see docs/router/
        sagemcom-xmo-api.md "Remaining captures needed").
        """
        resp = await self._client.get_values([
            'Device/DeviceInfo',
            "Device/IP/Interfaces/Interface[Alias='IP_DATA']",
            'Device/WiFi/SSIDs',
        ])

        info = self._client._extract_result(resp, 0) or {}
        if isinstance(info, list) and info:
            info = info[0]

        wan_interface = self._client._extract_result(resp, 1) or {}
        if isinstance(wan_interface, list) and wan_interface:
            wan_interface = wan_interface[0]

        ssids_raw = self._client._extract_result(resp, 2) or []
        if isinstance(ssids_raw, dict):
            ssids_raw = [ssids_raw]

        wan_ipv4_addresses = wan_interface.get('IPv4Addresses') or []
        wan_ip = wan_ipv4_addresses[0].get('IPAddress', '') if wan_ipv4_addresses else ''
        wan_mode = 'PPPoE' if 'PPP' in (wan_interface.get('LowerLayers') or '') else ''

        return RouterInfo(
            model=_str_field(info, 'ModelName'),
            firmware=_str_field(info, 'SoftwareVersion'),
            serial=_str_field(info, 'SerialNumber'),
            wan_ip=wan_ip,
            wan_mac=_str_field(info, 'MACAddress'),
            wan_status=_scalar_str(wan_interface.get('Status'), 'UNKNOWN'),
            wan_mode=wan_mode,
            uptime_seconds=_int_field(info, 'UpTime'),
            # dict.fromkeys dedupes while preserving order — each SSID name is
            # typically broadcast as a separate XMO object per radio band
            # (2.4GHz/5GHz), so the same name appears more than once here.
            ssids=list(dict.fromkeys(s['SSID'] for s in ssids_raw if isinstance(s, dict) and s.get('SSID'))),
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _to_device_snapshot(self, host: dict, associated: Optional[dict] = None) -> DeviceSnapshot:
        """Convert a raw XMO Host dict to a canonical DeviceSnapshot.

        `associated` is the mac -> AssociatedDevices-entry map from
        _get_associated_devices() (optional so existing callers/tests that
        only have a Host dict still work). Host entries have no usable signal
        fields on this firmware (X_SAGEMCOM_SignalStrength/RxRate don't
        exist); AssociatedDevices carries real SignalStrength (dBm) and
        LastDataDownlinkRate (kbps) for WiFi clients instead.
        """
        iface_type = host.get('InterfaceType', '')
        interface_name = 'WiFi' if iface_type == 'WiFi' else 'Ethernet'
        is_active = _is_active(host)

        mac = _norm_mac(host.get('PhysAddress', ''))
        client = (associated or {}).get(mac, {})

        signal_strength_dbm = _int_field(client, 'SignalStrength') if client else _int_field(host, 'X_SAGEMCOM_SignalStrength')
        # LastDataDownlinkRate is in kbps (confirmed live: 72222 ~= MaxBitRate
        # 72200 for an 802.11n client) — divide down to the Mbps this field
        # has always reported.
        signal_rate_mbps = (
            _int_field(client, 'LastDataDownlinkRate') // 1000
            if client else _int_field(host, 'X_SAGEMCOM_RxRate')
        )

        return DeviceSnapshot(
            mac_address=mac,
            ip_address=host.get('IPAddress', ''),
            hostname=host.get('HostName', ''),
            interface_name=interface_name,
            signal_strength_dbm=signal_strength_dbm,
            signal_rate_mbps=signal_rate_mbps,
            is_online=bool(is_active),
            port_alias=_parse_port_alias(host.get('Layer1Interface', '')) if interface_name == 'Ethernet' else '',
        )

    async def _get_hosts(self) -> List[dict]:
        """Return the raw Host dicts from the router's Hosts table.

        `Device/Hosts/Host` (the xpath the XMO docs describe) does not exist
        on this firmware — XMO_UNKNOWN_PATH_ERR. The real xpath is
        `Device/Hosts`, which returns a container object with the host list
        nested one level deeper under its own `Hosts` key. Confirmed live:
        entries carry PhysAddress/IPAddress/HostName/InterfaceType/Active as
        expected, but no X_SAGEMCOM_SignalStrength/X_SAGEMCOM_RxRate and no
        BytesSent/BytesReceived — those always read as 0/empty here for WiFi
        clients on this firmware. See _get_associated_devices() for the real
        source of that data.
        """
        resp = await self._client.get_value('Device/Hosts')
        container = self._client._extract_result(resp, 0) or {}
        hosts = container.get('Hosts', []) if isinstance(container, dict) else []
        if isinstance(hosts, dict):
            hosts = [hosts]
        return hosts

    async def _get_associated_devices(self) -> dict[str, dict]:
        """Return per-client WiFi stats keyed by normalized MAC address,
        merged across every access point (2.4GHz/5GHz, main/guest/backhaul).

        This is the real source for WiFi signal/traffic data on this firmware
        — Device/Hosts entries have neither. The xpath is confirmed live:
        `Device/WiFi/AccessPoints/AccessPoint[Alias="..."]/AssociatedDevices`
        (plural — the singular `AssociatedDevice` the XMO docs and most
        Sagemcom API examples use is XMO_UNKNOWN_PATH_ERR on this firmware).
        Each entry carries SignalStrength (dBm), LastDataDownlinkRate/
        LastDataUplinkRate (kbps), and cumulative Stats.BytesSent/BytesReceived.
        """
        actions = [
            {
                'id': i,
                'method': 'getValue',
                'xpath': f'Device/WiFi/AccessPoints/AccessPoint[Alias="{alias}"]/AssociatedDevices',
            }
            for i, alias in enumerate(_ACCESS_POINT_ALIASES)
        ]
        resp = await self._client.post(actions)

        by_mac: dict[str, dict] = {}
        for i in range(len(_ACCESS_POINT_ALIASES)):
            clients = self._client._extract_result(resp, i) or []
            if isinstance(clients, dict):
                clients = [clients]
            for client in clients:
                if not isinstance(client, dict):
                    continue
                mac = _norm_mac(client.get('MACAddress', ''))
                if not mac:
                    continue
                # A device can have a stale entry on more than one AP object
                # (e.g. mid-roam between bands) — prefer whichever the router
                # currently reports as Active.
                if mac not in by_mac or client.get('Active'):
                    by_mac[mac] = client
        return by_mac

    async def _get_port_traffic_samples(self) -> List[TrafficSample]:
        """Return one PER_PORT TrafficSample per active port (based on Stats/BytesSent)."""
        actions = [
            {
                'id': i,
                'method': 'getValue',
                'xpath': f'Device/Ethernet/Interfaces/Interface[Alias="{alias}"]/Stats',
            }
            for i, alias in enumerate(_PORT_ALIASES)
        ]
        resp = await self._client.post(actions)
        samples: List[TrafficSample] = []

        for i, alias in enumerate(_PORT_ALIASES):
            stats = self._client._extract_result(resp, i) or {}
            if isinstance(stats, list) and stats:
                stats = stats[0]
            sent = _int_field(stats, 'BytesSent')
            recv = _int_field(stats, 'BytesReceived')
            sample = self._device_delta.compute(
                key=alias,
                sent_now=sent,
                recv_now=recv,
                granularity=TrafficGranularity.PER_PORT,
                poll_interval_s=self._poll_interval_s,
                port_alias=alias,
            )
            samples.append(sample)

        return samples

    def _extract_added_uid(self, resp: dict) -> Optional[str]:
        """Extract the UID of a newly created object from an addObject response."""
        actions = resp.get('reply', {}).get('actions', [])
        for action in actions:
            uid = action.get('uid')
            if uid is not None:
                return str(uid)
        return None

    async def aclose(self) -> None:
        """Release underlying HTTP connections."""
        await self._client.aclose()


# ──────────────────────────────────────────────────────────────────────────────
# Module-level helpers (pure functions — no adapter state)
# ──────────────────────────────────────────────────────────────────────────────

def _norm_mac(mac: str) -> str:
    """Normalise a MAC address to lowercase colon-separated format."""
    return mac.lower().strip()


def _is_active(host: dict) -> bool:
    """Parse a Host entry's Active field — a bool on this firmware, but
    defensively handles a string 'true'/'false' too."""
    is_active = host.get('Active', False)
    if isinstance(is_active, str):
        return is_active.lower() == 'true'
    return bool(is_active)


_LAYER1_INTERFACE_RE = re.compile(r'\[([^\]]+)\]')


def _parse_port_alias(layer1_interface: str) -> str:
    """Extract the PHY alias from a Host's Layer1Interface field.

    Confirmed live: wired hosts carry e.g.
    'Device/Ethernet/Interfaces/Interface[PHY5]' — only meaningful for
    Ethernet hosts; WiFi hosts have this blank.
    """
    if not layer1_interface:
        return ''
    match = _LAYER1_INTERFACE_RE.search(layer1_interface)
    alias = match.group(1) if match else ''
    return alias if alias in _PORT_ALIASES else ''


def _int_field(d: Any, key: str) -> int:
    """Safely extract an integer field from a dict."""
    if not isinstance(d, dict):
        return 0
    try:
        return int(d.get(key, 0) or 0)
    except (ValueError, TypeError):
        return 0


def _str_field(d: Any, key: str) -> str:
    """Safely extract a string field from a dict."""
    if not isinstance(d, dict):
        return ''
    return str(d.get(key, '') or '')


def _scalar_str(value: Any, default: str = '') -> str:
    """Extract a string from a raw XMO result which may be a scalar or a dict."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # e.g. {"Status": "UP"} — take the first value
        v = next(iter(value.values()), None)
        return str(v) if v is not None else default
    return str(value)


def _scalar_int(value: Any) -> int:
    """Extract an int from a raw XMO result which may be a scalar or a dict."""
    s = _scalar_str(value, '0')
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0
