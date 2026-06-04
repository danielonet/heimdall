import logging
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
    ) -> None:
        base_url = f'http://{router_ip}:{router_port}'
        self._auth = XmoAuth(password)
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
        resp = await self._client.get_value('Device/Hosts/Host')
        hosts = self._client._extract_result(resp, 0) or []
        if isinstance(hosts, dict):
            hosts = [hosts]
        return [self._to_device_snapshot(h) for h in hosts if isinstance(h, dict)]

    async def get_traffic_samples(self) -> List[TrafficSample]:
        """Return per-device (WiFi) and per-port (wired) traffic deltas.

        WiFi samples have granularity=PER_DEVICE.
        Wired port samples have granularity=PER_PORT and mac_address=port_alias.
        """
        samples: List[TrafficSample] = []

        # WiFi: per-device bytes from Host table
        resp = await self._client.get_value('Device/Hosts/Host')
        hosts = self._client._extract_result(resp, 0) or []
        if isinstance(hosts, dict):
            hosts = [hosts]

        for h in hosts:
            if not isinstance(h, dict):
                continue
            if h.get('InterfaceType') != 'WiFi':
                continue
            mac = _norm_mac(h.get('PhysAddress', ''))
            if not mac:
                continue
            sent = _int_field(h, 'BytesSent')
            recv = _int_field(h, 'BytesReceived')
            sample = self._device_delta.compute(
                mac, sent, recv, TrafficGranularity.PER_DEVICE, self._poll_interval_s
            )
            samples.append(sample)

        # Wired: per-port aggregate (PHY1–PHY5)
        port_samples = await self._get_port_traffic_samples()
        samples.extend(port_samples)

        return samples

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
        """Return router metadata: model, firmware, uptime, WAN status."""
        resp = await self._client.get_values([
            'Device/DeviceInfo',
            "Device/IP/Interfaces/Interface[Alias='IP_DATA']/Status",
            "Device/Services/NetworkCfg/CurrentWanMode",
        ])

        info = self._client._extract_result(resp, 0) or {}
        if isinstance(info, list) and info:
            info = info[0]
        wan_status_raw = self._client._extract_result(resp, 1)
        wan_mode_raw = self._client._extract_result(resp, 2)

        return RouterInfo(
            model=_str_field(info, 'ModelName'),
            firmware=_str_field(info, 'SoftwareVersion'),
            serial=_str_field(info, 'SerialNumber'),
            wan_mac=_str_field(info, 'WANMACAddress'),
            wan_status=_scalar_str(wan_status_raw, 'UNKNOWN'),
            wan_mode=_scalar_str(wan_mode_raw, ''),
            uptime_seconds=_int_field(info, 'UpTime'),
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _to_device_snapshot(self, host: dict) -> DeviceSnapshot:
        """Convert a raw XMO Host dict to a canonical DeviceSnapshot."""
        iface_type = host.get('InterfaceType', '')
        interface_name = 'WiFi' if iface_type == 'WiFi' else 'Ethernet'
        is_active = host.get('Active', False)
        if isinstance(is_active, str):
            is_active = is_active.lower() == 'true'

        return DeviceSnapshot(
            mac_address=_norm_mac(host.get('PhysAddress', '')),
            ip_address=host.get('IPAddress', ''),
            hostname=host.get('HostName', ''),
            interface_name=interface_name,
            signal_strength_dbm=_int_field(host, 'X_SAGEMCOM_SignalStrength'),
            signal_rate_mbps=_int_field(host, 'X_SAGEMCOM_RxRate'),
            is_online=bool(is_active),
        )

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
