"""PassiveAdapter tests: canned `ip neigh` / `nmap -oX` output through a fake
command runner and a controllable clock, so no network, nmap or root needed."""
import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.adapter import factory
from sentinel.adapter.passive.passive_adapter import (
    PassiveAdapter, parse_ip_neigh, parse_lan_networks, parse_nmap_ping_sweep,
)

NEIGH = """\
192.168.1.1 dev eth0 lladdr c4:eb:42:00:00:01 router REACHABLE
192.168.1.20 dev eth0 lladdr AA:BB:CC:00:00:20 STALE
192.168.1.21 dev eth0 FAILED
192.168.1.22 dev eth0  INCOMPLETE
172.17.0.2 dev docker0 lladdr 02:42:ac:11:00:02 REACHABLE
10.9.9.9 dev eth0 lladdr aa:bb:cc:00:00:99 REACHABLE
not a neighbour row
"""

NMAP = """\
<nmaprun>
<host><status state="up"/><address addr="192.168.1.30" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:00:30" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="printer.lan" type="PTR"/></hostnames></host>
<host><status state="down"/><address addr="192.168.1.31" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.1.2" addrtype="ipv4"/></host>
</nmaprun>
"""

ADDR = '2: eth0    inet 192.168.1.2/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever'


class FakeHost:
    """Fake command runner + clock."""

    def __init__(self, neigh=NEIGH, nmap=NMAP, addr=ADDR):
        self.outputs = {'neigh': neigh, 'nmap': nmap, 'addr': addr, 'route': 'default via 192.168.1.1 dev eth0'}
        self.calls: list[list[str]] = []
        self.now = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)

    async def run(self, cmd, timeout_s):
        self.calls.append(cmd)
        if cmd[0] == 'nmap':
            return self.outputs['nmap']
        if cmd[:3] == ['ip', '-4', 'neigh']:
            return self.outputs['neigh']
        if 'route' in cmd:
            return self.outputs['route']
        return self.outputs['addr']

    def clock(self):
        return self.now

    def adapter(self, **kwargs):
        kwargs.setdefault('iface', 'eth0')
        return PassiveAdapter(runner=self.run, clock=self.clock, **kwargs)


async def settle(adapter):
    if adapter._sweep_task is not None:
        await adapter._sweep_task


class TestParsers:
    def test_neighbour_rows_without_a_mac_or_with_failed_state_are_dropped(self):
        macs = {e.mac for e in parse_ip_neigh(NEIGH)}
        assert 'aa:bb:cc:00:00:20' in macs
        assert not any(e.ip in ('192.168.1.21', '192.168.1.22') for e in parse_ip_neigh(NEIGH))

    def test_nmap_sweep_keeps_only_up_hosts_with_a_mac(self):
        hosts = parse_nmap_ping_sweep(NMAP)
        assert [(h.ip, h.mac, h.hostname, h.vendor) for h in hosts] == [
            ('192.168.1.30', 'aa:bb:cc:00:00:30', 'printer.lan', 'Acme')]

    def test_garbage_xml_is_an_empty_sweep(self):
        assert parse_nmap_ping_sweep('<<<') == []

    def test_lan_networks(self):
        assert [str(n) for n in parse_lan_networks(ADDR)] == ['192.168.1.0/24']


class TestInventory:
    @pytest.mark.asyncio
    async def test_only_this_interface_and_subnet_are_inventoried(self):
        adapter = FakeHost().adapter()
        macs = {d.mac_address for d in await adapter.get_connected_devices()}
        assert macs == {'c4:eb:42:00:00:01', 'aa:bb:cc:00:00:20'}  # not docker0, not 10.9.9.9
        await settle(adapter)

    @pytest.mark.asyncio
    async def test_devices_are_stamped_passive_and_carry_no_wifi_or_port_data(self):
        adapter = FakeHost().adapter()
        device = next(d for d in await adapter.get_connected_devices() if d.ip_address == '192.168.1.1')
        assert device.source_router == 'passive'
        assert device.interface_name == '' and device.signal_strength_dbm == 0 and device.port_alias == ''
        await settle(adapter)

    @pytest.mark.asyncio
    async def test_sweep_adds_devices_with_hostname_and_vendor(self):
        adapter = FakeHost().adapter()
        await adapter.get_connected_devices()
        await settle(adapter)
        printer = next(d for d in await adapter.get_connected_devices() if d.mac_address == 'aa:bb:cc:00:00:30')
        assert (printer.hostname, printer.vendor_name, printer.is_online) == ('printer.lan', 'Acme', True)

    @pytest.mark.asyncio
    async def test_stale_entry_is_known_but_not_proof_of_presence_while_sweeping(self):
        host = FakeHost(nmap='<nmaprun/>')
        adapter = host.adapter(sweep_interval_s=300)
        await adapter.get_connected_devices()
        await settle(adapter)
        host.now += timedelta(minutes=16)  # past 3 sweeps
        devices = {d.mac_address: d for d in await adapter.get_connected_devices()}
        assert devices['aa:bb:cc:00:00:20'].is_online is False  # STALE only
        assert devices['c4:eb:42:00:00:01'].is_online is True   # kernel still says REACHABLE
        await settle(adapter)

    @pytest.mark.asyncio
    async def test_device_that_stops_answering_goes_offline_and_returns(self):
        host = FakeHost(neigh='')
        adapter = host.adapter(sweep_interval_s=300)
        await adapter.get_connected_devices()
        await settle(adapter)
        host.outputs['nmap'] = '<nmaprun/>'
        host.now += timedelta(minutes=20)
        await adapter.get_connected_devices()
        await settle(adapter)
        gone = next(d for d in await adapter.get_connected_devices() if d.mac_address == 'aa:bb:cc:00:00:30')
        assert gone.is_online is False
        host.outputs['nmap'] = NMAP
        host.now += timedelta(minutes=6)
        await adapter.get_connected_devices()
        await settle(adapter)
        back = next(d for d in await adapter.get_connected_devices() if d.mac_address == 'aa:bb:cc:00:00:30')
        assert back.is_online is True and back.first_seen < back.last_seen

    @pytest.mark.asyncio
    async def test_without_sweeps_the_arp_table_alone_confirms_presence_and_nmap_never_runs(self):
        host = FakeHost()
        adapter = host.adapter(sweep_interval_s=0)
        devices = {d.mac_address: d for d in await adapter.get_connected_devices()}
        assert devices['aa:bb:cc:00:00:20'].is_online is True
        assert not any(c[0] == 'nmap' for c in host.calls)

    @pytest.mark.asyncio
    async def test_sweep_is_rate_limited(self):
        host = FakeHost()
        adapter = host.adapter(sweep_interval_s=300)
        for _ in range(3):
            await adapter.get_connected_devices()
            await settle(adapter)
        assert sum(c[0] == 'nmap' for c in host.calls) == 1
        host.now += timedelta(seconds=301)
        await adapter.get_connected_devices()
        await settle(adapter)
        assert sum(c[0] == 'nmap' for c in host.calls) == 2

    @pytest.mark.asyncio
    async def test_a_huge_subnet_is_never_swept(self):
        host = FakeHost(addr='2: eth0    inet 10.0.0.2/8 scope global eth0')
        adapter = host.adapter()
        await adapter.get_connected_devices()
        await settle(adapter)
        assert not any(c[0] == 'nmap' for c in host.calls)

    @pytest.mark.asyncio
    async def test_failing_commands_never_raise(self):
        async def boom(cmd, timeout_s):
            raise RuntimeError('no such binary')
        adapter = PassiveAdapter('eth0', runner=boom)
        assert await adapter.get_connected_devices() == []

    @pytest.mark.asyncio
    async def test_interface_defaults_to_the_default_route(self):
        host = FakeHost()
        adapter = host.adapter(iface='')
        await adapter.get_connected_devices()
        await settle(adapter)
        assert adapter._iface == 'eth0'

    @pytest.mark.asyncio
    async def test_invalidate_cache_triggers_a_fresh_sweep(self):
        host = FakeHost()
        adapter = host.adapter()
        await adapter.get_connected_devices()
        await settle(adapter)
        adapter.invalidate_connected_devices_cache()
        await adapter.get_connected_devices()
        await settle(adapter)
        assert sum(c[0] == 'nmap' for c in host.calls) == 2


class TestWhatItCannotDo:
    @pytest.mark.asyncio
    async def test_nothing_is_faked(self):
        adapter = FakeHost().adapter()
        assert await adapter.get_traffic_samples() == []
        assert await adapter.get_port_stats() == []
        assert await adapter.get_wan_stats() is None
        assert await adapter.get_dhcp_leases() == []
        assert adapter.HAS_DHCP_LEASES is False

    @pytest.mark.asyncio
    async def test_block_and_quarantine_report_failure(self):
        adapter = FakeHost().adapter()
        assert await adapter.block_device('aa:bb:cc:00:00:20') is False
        assert await adapter.quarantine_device('aa:bb:cc:00:00:20') is False
        assert await adapter.unblock_device('aa:bb:cc:00:00:20') is False
        assert await adapter.unquarantine_device('aa:bb:cc:00:00:20') is False

    @pytest.mark.asyncio
    async def test_router_info_says_passive_and_unknown_wan(self):
        info = await FakeHost().adapter().get_router_info()
        assert info.source_router == 'passive' and info.wan_status == 'UNKNOWN' and 'passive' in info.model

    @pytest.mark.asyncio
    async def test_aclose_cancels_an_in_flight_sweep(self):
        gate = asyncio.Event()

        async def slow(cmd, timeout_s):
            if cmd[0] == 'nmap':
                await gate.wait()
            return ''
        adapter = PassiveAdapter('eth0', runner=slow, clock=FakeHost().clock)
        adapter._networks = parse_lan_networks(ADDR)
        adapter._networks_at = FakeHost().now
        await adapter.get_connected_devices()
        task = adapter._sweep_task
        await asyncio.sleep(0)
        await adapter.aclose()
        with pytest.raises(asyncio.CancelledError):
            await task


class TestFactory:
    @pytest.mark.asyncio
    async def test_builds_a_passive_adapter_without_any_secret(self, monkeypatch):
        class Settings:
            async def get_sniff_iface(self):
                return 'enp3s0'
        monkeypatch.setattr('sentinel.db.repositories.SettingsRepository', Settings)
        adapter = await factory.create_router_adapter('passive')
        assert isinstance(adapter, PassiveAdapter) and adapter._iface == 'enp3s0'

    @pytest.mark.asyncio
    @pytest.mark.parametrize('picked,expected', [(False, ['sagemcom']), (True, ['sagemcom', 'passive'])])
    async def test_passive_is_a_primary_choice_once_picked(self, picked, expected, monkeypatch):
        class Profiles:
            async def get(self, router_id):
                return SimpleNamespace(host='') if picked and router_id == 'passive' else None
        monkeypatch.setattr('sentinel.db.repositories.RouterProfileRepository', Profiles)

        async def no_miwifi():
            return False
        monkeypatch.setattr(factory, 'miwifi_configured', no_miwifi)
        assert await factory.available_routers() == expected
