import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.discovery import discover_gateway_ip
from sentinel.adapter.models import (
    DeviceSnapshot,
    DhcpLease,
    PortStats,
    RouterInfo,
    TrafficGranularity,
    TrafficSample,
    WanStats,
    WifiRadioInfo,
)

from .delta import TrafficDeltaCalculator
from .xmo_auth import XmoAuth
from .xmo_client import XmoClient

logger = logging.getLogger(__name__)

_PORT_ALIASES = ['PHY1', 'PHY2', 'PHY3', 'PHY4', 'PHY5']

# How long get_connected_devices() serves its cached result before hitting
# the router again — see that method's docstring. Requested explicitly:
# the connected-devices fetch (Device/Hosts + WiFi AssociatedDevices) was
# being repeated every single 15s poll cycle purely to feed things that
# don't actually change that fast (device directory, online/offline
# status), same complaint as the ARP/DHCP reconciliation cadence fix.
# invalidate_connected_devices_cache() lets a caller force a fresh fetch
# sooner — SentinelScheduler does this the moment ArpWatcher observes a
# MAC/IP pairing it's never seen before, so a genuinely new device still
# shows up within one ~15s poll cycle instead of waiting out the full
# window; there's no equivalent passive signal for a device *leaving*, so
# a disconnect is only ever noticed on the next natural cache refresh.
_CONNECTED_DEVICES_CACHE_TTL_S = 300

# WiFi access point aliases (2.4GHz/5GHz main, 2.4GHz/5GHz guest, mesh backhaul)
# confirmed live via Device/WiFi/AccessPoints/AccessPoint[@uid=N]/Alias — this
# firmware has a fixed set of AP slots, not user-configurable in count.
_ACCESS_POINT_ALIASES = ['PRIV0', 'VID1', 'GUEST2G', 'GUEST5G', 'AP_BACKHAUL']

# MAC-based device blocking: confirmed live (DevTools capture against the
# router's own Devices-page block action, 2026-07-19) to work by blacklisting
# a Device/Hosts/Hosts/Host entry 24/7 via its BlacklistedSchedule — every
# ManagementDay[1..7 = SUNDAY..SATURDAY]/HoursN (0-23) leaf set to true. Every
# Host entry defaults to BlacklistEnable=true and BlacklistedAccordingToSchedule
# =true, so this alone is sufficient; no separate enable step is needed. A
# firewall DROP rule (the previous implementation here) only cuts WAN/routed
# access — it has no effect on purely-local traffic like ARP spoofing, which
# is why that approach didn't actually remove an attacker from the LAN.
_MANAGEMENT_DAY_UIDS = list(range(1, 8))  # 1=SUNDAY .. 7=SATURDAY, confirmed live
_SCHEDULE_SETVALUE_BATCH_SIZE = 100  # the router's own UI batches ~90 setValue actions per request
_XMO_NO_ERR = 16777239

# Quarantine tier: unlike block_device, this deliberately DOES use the
# Firewall Custom chain — confirmed live (docs/router/sagemcom-xmo-api.md:206)
# that a Custom-chain rule only affects routed/WAN-bound traffic and has no
# effect on purely-local LAN traffic, which is exactly the "cut internet,
# keep LAN reachable" distinction a quarantine tier needs (the opposite of
# why that chain was rejected for block_device). The xpath and addChild
# method are confirmed live, and so is the Rule object's full field set —
# confirmed by reading the ~40 firmware-default rule-template entries that
# ship pre-populated in every chain (Custom included) as `addChild` targets
# for the router's own port-forwarding UI. That capture caught two real bugs
# in the field names this adapter had been sending, both fixed: the target
# field is `Target` (values `'ACCEPT'`/`'DROP'`), not `TargetAction` — the
# rule was being created with an unrecognized field and silently defaulting
# to `Target: 'ACCEPT'`, the worst possible failure mode for a block rule;
# and single-host scoping is `SourceMask` (a dotted-decimal netmask string,
# e.g. `'255.255.255.255'` — confirmed against this router's own
# IPv4Addresses[].SubnetMask format elsewhere in the data model), not a
# `SourcePrefixLength` integer, which isn't a field on this object at all.
_QUARANTINE_CHAIN_XPATH = 'Device/Firewall/Chains/Chain[Name="Custom"]/Rules'
_QUARANTINE_RULE_DESCRIPTION_PREFIX = 'heimdall-quarantine-'


class SagemcomXmoAdapter(RouterAdapter):
    """RouterAdapter implementation for the Sagemcom F@st 5670 via its XMO JSON API.

    This is the only module that may communicate with the router. All other
    sentinel modules interact only with the canonical models in adapter.models.
    """

    # Upper bound for _get_wifi_radios' by-uid enumeration — confirmed live
    # this router has exactly 2 (2.4GHz + 5GHz); a little headroom for a
    # tri-band unit without risking an unbounded request loop.
    _MAX_RADIO_UID = 4

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
        # Logged once, not every poll — see get_wan_stats().
        self._wan_stats_warned = False
        # time.monotonic(), not a device list — None means "no cache yet,
        # fetch for real". See get_connected_devices()/
        # invalidate_connected_devices_cache().
        self._connected_devices_cache: List[DeviceSnapshot] | None = None
        self._connected_devices_cached_at: float | None = None

    # ──────────────────────────────────────────────────────────────────────────
    # RouterAdapter interface
    # ──────────────────────────────────────────────────────────────────────────

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Return all currently connected LAN devices.

        Cached for _CONNECTED_DEVICES_CACHE_TTL_S (see that constant's
        comment) — callers wanting a guaranteed-fresh read (e.g. right
        after a manual block/unblock) should call
        invalidate_connected_devices_cache() first, not assume this always
        hits the router. get_traffic_samples() is unaffected — it reads
        Hosts/AssociatedDevices independently and isn't cached, since
        per-poll traffic freshness is still wanted every cycle.
        """
        now = time.monotonic()
        if (
            self._connected_devices_cache is not None
            and self._connected_devices_cached_at is not None
            and now - self._connected_devices_cached_at < _CONNECTED_DEVICES_CACHE_TTL_S
        ):
            return self._connected_devices_cache

        hosts = await self._get_hosts()
        associated = await self._get_associated_devices()
        devices = [self._to_device_snapshot(h, associated) for h in hosts if isinstance(h, dict)]
        self._connected_devices_cache = devices
        self._connected_devices_cached_at = now
        return devices

    def invalidate_connected_devices_cache(self) -> None:
        """Force the next get_connected_devices() call to hit the router
        again instead of serving the cache. Sync and cheap (clears one
        timestamp) — safe to call from anywhere, including ArpWatcher's own
        callback thread by way of the scheduler's existing thread-safe
        bridge (see SentinelScheduler._handle_arp_new_ip)."""
        self._connected_devices_cached_at = None

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

            # Same direction convention as the WiFi AssociatedDevices fix in
            # get_traffic_samples() (applied here on that precedent, not
            # independently re-verified against live wired traffic — see
            # docs/router/sagemcom-xmo-api.md's "Remaining captures needed"):
            # from the interface's own perspective, "Sent" is
            # interface-to-device (the device's download) and "Received" is
            # device-to-interface (the device's upload) — the opposite of
            # the WAN interface's convention. sent_total/sent_delta below
            # are what the frontend renders under a ↑ upload arrow
            # (PortCard.jsx), so the raw fields are swapped feeding them.
            port_download_total = _int_field(stats, 'BytesSent')
            port_upload_total = _int_field(stats, 'BytesReceived')
            sent_total = port_upload_total
            recv_total = port_download_total

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
        """Blacklist the device 24/7 via its Host entry's BlacklistedSchedule —
        see the module-level comment above _MANAGEMENT_DAY_UIDS. Returns False
        (not True) if the MAC has no matching Host entry, or if the router
        doesn't confirm every setValue — callers must not report a block as
        successful just because this coroutine didn't raise.
        """
        mac = _norm_mac(mac)
        host_uid = await self._find_host_uid(mac)
        if host_uid is None:
            logger.error('block_device(%s): no matching Device/Hosts/Hosts entry — cannot block', mac)
            return False
        return await self._set_blacklist_schedule(mac, host_uid, blacklisted=True)

    async def unblock_device(self, mac: str) -> bool:
        """Clear every BlacklistedSchedule hour for the device's Host entry —
        the reverse of block_device()."""
        mac = _norm_mac(mac)
        host_uid = await self._find_host_uid(mac)
        if host_uid is None:
            logger.warning('unblock_device(%s): no matching Device/Hosts/Hosts entry', mac)
            return False
        return await self._set_blacklist_schedule(mac, host_uid, blacklisted=False)

    async def quarantine_device(self, mac: str) -> bool:
        """Add a WAN-only DROP rule to the Firewall Custom chain, scoped to
        this device's current IP — see the module-level comment above
        _QUARANTINE_CHAIN_XPATH for why this chain (rejected for
        block_device) is the right mechanism here. Returns False if the MAC
        has no matching Host entry with a known IP, or if the router
        rejects the addChild call.
        """
        mac = _norm_mac(mac)
        host = await self._find_host(mac)
        ip = host.get('IPAddress') if host else ''
        if not ip:
            logger.error('quarantine_device(%s): no matching Host entry with an IP — cannot quarantine', mac)
            return False

        resp = await self._client.add_child(_QUARANTINE_CHAIN_XPATH, {
            'Rule': {
                'Enable': True,
                'Description': f'{_QUARANTINE_RULE_DESCRIPTION_PREFIX}{mac}',
                'SourceIP': ip,
                'SourceMask': '255.255.255.255',
                'Target': 'DROP',
            },
        })
        action = (resp.get('reply', {}).get('actions') or [{}])[0]
        if action.get('error', {}).get('code') != _XMO_NO_ERR:
            logger.error('quarantine_device(%s): addChild failed: %s', mac, resp)
            return False

        await self._warn_if_custom_chain_inactive(mac)
        logger.info('Quarantined device %s (ip=%s) via Firewall Custom chain', mac, ip)
        return True

    async def unquarantine_device(self, mac: str) -> bool:
        """Remove the Firewall Custom-chain rule created by quarantine_device.

        The rule's own uid isn't persisted anywhere outside the router
        (Device.is_quarantined is just a boolean), so it's resolved the same
        way block_device resolves a host uid: looked up fresh by matching
        the Description this adapter stamped on it at creation time.
        """
        mac = _norm_mac(mac)
        resp = await self._client.get_value(_QUARANTINE_CHAIN_XPATH)
        rules = self._client._extract_result(resp, 0) or []
        if isinstance(rules, dict):
            rules = [rules]

        target_uid = next(
            (
                r.get('uid') for r in rules
                if isinstance(r, dict) and r.get('Description') == f'{_QUARANTINE_RULE_DESCRIPTION_PREFIX}{mac}'
            ),
            None,
        )
        if target_uid is None:
            logger.warning('unquarantine_device(%s): no matching Custom-chain rule found', mac)
            return False

        resp = await self._client.delete_object(f'{_QUARANTINE_CHAIN_XPATH}/Rule[@uid="{target_uid}"]')
        action = (resp.get('reply', {}).get('actions') or [{}])[0]
        if action.get('error', {}).get('code') != _XMO_NO_ERR:
            logger.error('unquarantine_device(%s): deleteObject failed: %s', mac, resp)
            return False

        logger.info('Unquarantined device %s', mac)
        return True

    async def _warn_if_custom_chain_inactive(self, mac: str) -> None:
        """Read-only check: a Custom-chain rule only actually enforces while
        the chain that contains it is itself enabled — which only happens
        while the router's active firewall Security Level is set to
        "Custom" in its own admin UI (confirmed live: every chain, Custom
        included, carries its own top-level Enable flag; exactly one is
        true at a time, matching whichever Level is currently selected).

        This used to instead read Device/Firewall/Levels/Level[Name=
        "Custom"]/DefaultPolicy and compare it to 'Custom' — confirmed live
        that field is a static property of the Custom level itself (its own
        default action, always 'DROP' on this unit) and was never going to
        equal 'Custom', so that check warned unconditionally regardless of
        which level was actually active. Fixed to read the chain's own
        Enable flag directly instead, which is a genuine live indicator —
        confirmed false on this unit (Custom is not the active level here),
        i.e. quarantine_device() currently creates a rule that does not yet
        enforce anything until that's changed by hand in the router's UI.

        This never writes to the chain or flips the router's Security
        Level — switching the whole active firewall posture is out of scope
        for a per-device action — it only reads it, to warn the admin that
        the rule that was just created may not actually enforce yet.
        """
        resp = await self._client.get_value(f'{_QUARANTINE_CHAIN_XPATH.removesuffix("/Rules")}/Enable')
        enabled = self._client._extract_result(resp, 0)
        if not enabled:
            logger.warning(
                'quarantine_device(%s): Custom-chain rule created, but the Custom chain itself is '
                'not active (Enable=%r) — the rule will not enforce until the router\'s own Security '
                'Level setting is changed to "Custom" manually in its admin UI',
                mac, enabled,
            )

    async def _find_host(self, mac: str) -> Optional[dict]:
        """Resolve a MAC to its full Device/Hosts/Hosts/Host[@uid=...] entry."""
        hosts = await self._get_hosts()
        for h in hosts:
            if isinstance(h, dict) and _norm_mac(h.get('PhysAddress', '')) == mac:
                return h
        return None

    async def _find_host_uid(self, mac: str) -> Optional[int]:
        """Resolve a MAC to its Device/Hosts/Hosts/Host[@uid=...] uid."""
        host = await self._find_host(mac)
        return host.get('uid') if host else None

    async def _set_blacklist_schedule(self, mac: str, host_uid: int, *, blacklisted: bool) -> bool:
        """setValue every BlacklistedSchedule/ManagementDay/HoursN leaf (7
        days x 24 hours = 168 actions) to `blacklisted`, batched the same way
        the router's own UI does it — sending all 168 in a single request
        isn't confirmed to work, so this chunks conservatively.
        """
        actions = [
            {
                'id': i,
                'method': 'setValue',
                'xpath': (
                    f'Device/Hosts/Hosts/Host[@uid="{host_uid}"]/BlacklistedSchedule'
                    f'/ManagementDay[@uid="{day_uid}"]/Hours{hour}'
                ),
                'parameters': {'value': blacklisted},
            }
            for i, (day_uid, hour) in enumerate(
                (day_uid, hour) for day_uid in _MANAGEMENT_DAY_UIDS for hour in range(24)
            )
        ]

        verb = 'block_device' if blacklisted else 'unblock_device'
        for start in range(0, len(actions), _SCHEDULE_SETVALUE_BATCH_SIZE):
            batch = actions[start:start + _SCHEDULE_SETVALUE_BATCH_SIZE]
            resp = await self._client.post(batch)
            reply_actions = resp.get('reply', {}).get('actions', [])
            if len(reply_actions) != len(batch) or any(
                a.get('error', {}).get('code') != _XMO_NO_ERR for a in reply_actions
            ):
                logger.error(
                    '%s(%s): setValue batch failed (actions %d-%d): %s',
                    verb, mac, batch[0]['id'], batch[-1]['id'], resp,
                )
                return False

        logger.info('%s device %s (host uid=%s)', 'Blocked' if blacklisted else 'Unblocked', mac, host_uid)
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

        Radios are fetched separately, one `Radio[@uid='N']` request per
        radio (see _get_wifi_radios) — also confirmed live and fixed: the
        bare, unfiltered `Device/WiFi/Radios/Radio` path used here
        previously only ever returned the single first-numbered radio
        (uid=1, this router's 2.4GHz radio), silently dropping every other
        one (uid=2, 5GHz) with no error of any kind — unlike
        `Device/WiFi/SSIDs`, which genuinely does return every SSID from
        one unfiltered call, so this wasn't the pattern used everywhere
        else in this file failing the same way.
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

        radios_raw = await self._get_wifi_radios()

        wan_ipv4_addresses = wan_interface.get('IPv4Addresses') or []
        wan_ip = wan_ipv4_addresses[0].get('IPAddress', '') if wan_ipv4_addresses else ''
        wan_mode = 'PPPoE' if 'PPP' in (wan_interface.get('LowerLayers') or '') else ''

        radios = [self._to_wifi_radio_info(r) for r in radios_raw if isinstance(r, dict)]

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
            radios=radios,
        )

    async def _get_wifi_radios(self) -> list[dict]:
        """Every WiFi radio object, fetched by explicit uid (1, 2, 3, ...)
        since the bare `Device/WiFi/Radios/Radio` path only ever returns
        the first one — see get_router_info's docstring. Stops at the
        first uid that doesn't resolve (XMO_UNKNOWN_PATH_ERR ->
        _extract_result returns None, confirmed live, no exception raised)
        rather than assuming a fixed radio count, so this still works on a
        single-radio or triple-radio (tri-band) unit. _MAX_RADIO_UID caps
        the search so a persistently-misbehaving router can't turn this
        into an unbounded loop of requests.
        """
        radios: list[dict] = []
        for uid in range(1, self._MAX_RADIO_UID + 1):
            resp = await self._client.get_value(f"Device/WiFi/Radios/Radio[@uid='{uid}']")
            radio = self._client._extract_result(resp, 0)
            if isinstance(radio, list) and radio:
                radio = radio[0]
            if not isinstance(radio, dict):
                break
            radios.append(radio)
        return radios

    async def get_wan_stats(self) -> Optional[WanStats]:
        """Household-total WAN traffic delta since the last call.

        Reads `Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats` — this
        xpath is confirmed correct against a live router (cross-checked the
        `wan_stats` DB table's real throughput history — see
        docs/router/sagemcom-xmo-api.md's WAN Layer section). Still degrades
        gracefully rather than assuming that holds on every firmware: if the
        response doesn't have BytesSent/BytesReceived, logs a warning once
        (not every poll — this runs on the main 15s cycle) and returns None;
        poll_cycle just skips persisting a row that cycle rather than
        raising.
        """
        resp = await self._client.get_value("Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats")
        stats = self._client._extract_result(resp, 0) or {}
        if isinstance(stats, list) and stats:
            stats = stats[0]

        if not isinstance(stats, dict) or 'BytesSent' not in stats or 'BytesReceived' not in stats:
            if not self._wan_stats_warned:
                logger.warning(
                    "WAN stats xpath (Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats) "
                    'did not resolve as expected — household bandwidth tracking is disabled'
                )
                self._wan_stats_warned = True
            return None

        sent_total = _int_field(stats, 'BytesSent')
        recv_total = _int_field(stats, 'BytesReceived')
        # Reuse TrafficDeltaCalculator purely as a delta/throughput
        # calculator (same counter-reset guard as every other traffic
        # source) rather than duplicating that math a third time — the
        # resulting TrafficSample's key/granularity/port_alias fields are
        # discarded, only the computed deltas/throughput are kept. A
        # household total has no device/port key of its own, so it's never
        # persisted as a TrafficSample (see WanStats' docstring).
        sample = self._device_delta.compute(
            key='__WAN__', sent_now=sent_total, recv_now=recv_total,
            granularity=TrafficGranularity.PER_DEVICE, poll_interval_s=self._poll_interval_s,
        )
        return WanStats(
            timestamp=sample.timestamp,
            bytes_sent_delta=sample.bytes_sent_delta,
            bytes_recv_delta=sample.bytes_recv_delta,
            throughput_up_kbps=sample.throughput_up_kbps,
            throughput_dn_kbps=sample.throughput_dn_kbps,
        )

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        """Every currently-active DHCP lease, straight from the router's own
        DHCP server — the authoritative MAC<->IP source (see DhcpLease's
        docstring for why this exists).

        Confirmed live: `Device/DHCPv4/Server/Pools` (**not**
        `.../Pool/Client` as an earlier pass at this doc guessed and marked
        ✅ off — that xpath is XMO_UNKNOWN_PATH_ERR on this firmware,
        confirmed live 2026-08-28) returns a bare list of pool objects, each
        with a nested `Clients` list. A client that's exhausted its lease
        keeps its Clients entry (Active=false, IPv4Addresses[0].IPAddress
        empty) rather than disappearing — filtered out here, along with any
        entry missing a MAC. Iterates every pool (this router has exactly
        one, DEFAULT_POOL, but nothing stops a future firmware/config from
        having more, e.g. a separate guest pool) and merges by MAC.
        """
        resp = await self._client.get_value('Device/DHCPv4/Server/Pools')
        pools = self._client._extract_result(resp, 0) or []
        if isinstance(pools, dict):
            pools = [pools]

        leases: List[DhcpLease] = []
        for pool in pools:
            if not isinstance(pool, dict):
                continue
            for client in pool.get('Clients', []) or []:
                if not isinstance(client, dict) or not _is_active(client):
                    continue
                mac = _norm_mac(client.get('Chaddr', ''))
                addrs = client.get('IPv4Addresses') or []
                ip = _str_field(addrs[0], 'IPAddress') if addrs else ''
                if not mac or not ip:
                    continue
                leases.append(DhcpLease(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=_decode_dhcp_option12_hostname(client.get('Options')),
                    lease_expires_at=_parse_lease_time_remaining(
                        _str_field(addrs[0], 'LeaseTimeRemaining') if addrs else ''
                    ),
                ))
        return leases

    def _to_wifi_radio_info(self, radio: dict) -> WifiRadioInfo:
        """Field names confirmed live against a real Sagemcom F@st 5670
        (Channel/TransmitPower/OperatingStandards all present as named).
        TransmitPower is a percentage of TransmitPowerMax, not dBm — see
        WifiRadioInfo's docstring — and its -1 sentinel (automatic power
        control) is mapped to None rather than passed through as -1%.
        Band is inferred from the radio's own Alias (wl0=5GHz, wl1=2.4GHz,
        confirmed via the sibling Stats rows) since OperatingFrequencyBand
        isn't confirmed either.
        """
        alias = _str_field(radio, 'Alias')
        if alias == 'wl0':
            band = '5GHz'
        elif alias == 'wl1':
            band = '2.4GHz'
        else:
            # Neither wl0 nor wl1 — confirmed on a real F@st 5670, whose
            # Alias is 'RADIO2G4'/'RADIO5G' instead. OperatingFrequencyBand
            # ('2_4GHZ'/'5GHZ') is confirmed present and reliable there;
            # normalized to the same 'X.XGHz' shape the wl0/wl1 branch and
            # the mock adapter both already use.
            raw_band = _str_field(radio, 'OperatingFrequencyBand')
            band = {'2_4GHZ': '2.4GHz', '5GHZ': '5GHz', '6GHZ': '6GHz'}.get(raw_band, raw_band)
        tx_power = _int_field(radio, 'TransmitPower')
        return WifiRadioInfo(
            band=band,
            channel=_int_field(radio, 'Channel'),
            tx_power_percent=None if tx_power == -1 else tx_power,
            standard=_str_field(radio, 'OperatingStandards'),
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
        mac = _norm_mac(host.get('PhysAddress', ''))
        client = (associated or {}).get(mac, {})

        # Layer1Interface is the authoritative wired signal: confirmed live
        # to carry a real PHY interface path (e.g.
        # 'Device/Ethernet/Interfaces/Interface[PHY5]') only for genuinely
        # wired hosts, and to be blank for every WiFi host (see
        # _parse_port_alias's docstring). Computed once here and reused
        # below instead of re-parsed for port_alias.
        #
        # This must be the *positive* signal 'Ethernet' is decided from —
        # not a fallback for "didn't prove WiFi". The previous logic
        # (`'WiFi' if iface_type == 'WiFi' or client else 'Ethernet'`)
        # defaulted anything ambiguous to Ethernet: Device/Hosts'
        # InterfaceType is unreliable on this firmware (several of its
        # other fields are known-stale/blank for WiFi clients too — see
        # _get_hosts()'s docstring), and a WiFi phone briefly missing from
        # this poll's AssociatedDevices response (a roam, a per-AP-entry
        # lag — see _get_associated_devices' own "prefer whichever the
        # router reports Active" comment) would silently flip a real WiFi
        # device to Ethernet — confirmed in production: several WiFi-only
        # phones showing an ETH badge with no physical cable involved.
        port_alias = _parse_port_alias(host.get('Layer1Interface', ''))
        interface_name = 'Ethernet' if port_alias else 'WiFi'
        # Same reasoning as interface_name above, applied to liveness: Hosts'
        # own Active field appears to lag well behind the device actually
        # going away (confirmed in production — a powered-off device stayed
        # "online" on the dashboard for a long time). AssociatedDevices'
        # Active field is the router's live 802.11 association state — the
        # xpath docs (docs/router/sagemcom-xmo-api.md) confirm it can be
        # false on a stale per-AP entry, so it's a real, faster-updating
        # signal, not just presence/absence. Only WiFi clients ever appear
        # in AssociatedDevices at all, so wired devices keep relying on
        # Hosts' Active exactly as before.
        is_active = _is_active(client) if client else _is_active(host)

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
            port_alias=port_alias,
            # The router's own DHCP-fingerprint classification (matched against
            # Device/DeviceDiscovery/DeviceIdentification/DHCPFingerprintDatabase)
            # — confirmed live values include 'Smartphone', 'Multimedia device';
            # blank when the router couldn't classify it. UserDeviceType (the
            # router UI's manually-editable category) is deliberately not used
            # here — it defaults to 'MISCELLANEOUS' for nearly every host and
            # carries no real signal unless an admin hand-edited it in the
            # router's own UI.
            device_type=host.get('DetectedDeviceType', ''),
            # Which AP this client is on (private vs. guest) — stamped onto
            # the client dict by _get_associated_devices(); blank for wired
            # devices, which have no AssociatedDevices entry at all.
            ap_alias=client.get('_ap_alias', '') if client else '',
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
        for i, alias in enumerate(_ACCESS_POINT_ALIASES):
            clients = self._client._extract_result(resp, i) or []
            if isinstance(clients, dict):
                clients = [clients]
            for client in clients:
                if not isinstance(client, dict):
                    continue
                mac = _norm_mac(client.get('MACAddress', ''))
                if not mac:
                    continue
                # Stamp which AP this entry came from — the loop variable
                # is otherwise discarded at merge time, which used to mean
                # DeviceSnapshot had no way to say which network (private
                # vs. guest) a device is actually on. See ap_alias.
                client['_ap_alias'] = alias
                # A device can have a stale entry on more than one AP object
                # (e.g. mid-roam between bands) — prefer whichever the router
                # currently reports as Active.
                if mac not in by_mac or client.get('Active'):
                    by_mac[mac] = client
        return by_mac

    async def _get_port_traffic_samples(self) -> List[TrafficSample]:
        """Return one PER_PORT TrafficSample per active port (based on Stats/BytesSent).

        Same Sent/Received swap as get_port_stats() — see that method's
        comment for the reasoning (mirrors the confirmed WiFi
        AssociatedDevices direction fix, not independently re-verified
        against live wired traffic).
        """
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
            port_download = _int_field(stats, 'BytesSent')
            port_upload = _int_field(stats, 'BytesReceived')
            sample = self._device_delta.compute(
                key=alias,
                sent_now=port_upload,
                recv_now=port_download,
                granularity=TrafficGranularity.PER_PORT,
                poll_interval_s=self._poll_interval_s,
                port_alias=alias,
            )
            samples.append(sample)

        return samples

    async def aclose(self) -> None:
        """Release underlying HTTP connections."""
        await self._client.aclose()


# ──────────────────────────────────────────────────────────────────────────────
# Module-level helpers (pure functions — no adapter state)
# ──────────────────────────────────────────────────────────────────────────────

def _norm_mac(mac: str) -> str:
    """Normalise a MAC address to lowercase colon-separated format."""
    return mac.lower().strip()


def _decode_dhcp_option12_hostname(options: Any) -> str:
    """DHCP option 12 (Host Name) as the client itself sent it — this
    firmware's Pools[].Clients[].Options entries carry it hex-encoded, e.g.
    'MIBOX4' as Value='4d49424f5834'. Confirmed live 2026-08-28 against
    Device/DHCPv4/Server/Pools. Not every client sends one; '' if absent or
    undecodable rather than raising — this is cosmetic, never worth failing
    the whole leases call over one malformed option."""
    if not isinstance(options, list):
        return ''
    for opt in options:
        if isinstance(opt, dict) and opt.get('Tag') == 12:
            try:
                return bytes.fromhex(str(opt.get('Value', ''))).decode('ascii', errors='replace')
            except ValueError:
                return ''
    return ''


def _parse_lease_time_remaining(raw: str) -> Optional[datetime]:
    """Best-effort parse of Clients[].IPv4Addresses[].LeaseTimeRemaining.

    NOT fully reverse-engineered — flagged here rather than asserted with
    false confidence. Confirmed live values look like a *duration*
    (e.g. a lease from an 86400s/24h pool reading '1-01-02T02:00:49Z')
    mis-serialized as an absolute dateTime measured from a 0001-01-01
    epoch, a known TR-181 firmware quirk — but the parsed duration for a
    freshly-renewed lease came out to ~26h against a 24h pool LeaseTime,
    which doesn't cleanly fit "seconds remaining" either. Parsed
    defensively and returned as an approximate expiry (now + duration)
    for informational display only — nothing here depends on it being
    exact to the second. Returns None on any parse failure or an empty
    string (e.g. the inactive-client sentinel '1-01-01T02:00:00Z' some
    entries carry, or a genuinely absent value).
    """
    if not raw:
        return None
    # strptime's %Y wants 4 digits and this firmware's "year" is 1 — split
    # by hand instead of fighting the format string over it.
    match = re.match(r'^(\d+)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)Z$', raw)
    if not match:
        return None
    try:
        year, month, day, hour, minute, second = (int(g) for g in match.groups())
        duration = datetime(year, month, day, hour, minute, second) - datetime(1, 1, 1)
        if duration.total_seconds() <= 0:
            return None
        return datetime.now(timezone.utc) + duration
    except (ValueError, OverflowError):
        return None


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
