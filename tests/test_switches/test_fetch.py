import pytest

from sentinel.switches.web.fetch import HostNotAllowed, ensure_lan_host, host_part

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize('host', ['192.168.1.5', '10.0.0.2', '172.16.4.4', '169.254.1.1', '192.168.1.5:8080', 'http://10.1.1.1/', '[fd00::1]:80'])
async def test_private_and_link_local_addresses_are_allowed(host):
    await ensure_lan_host(host)


@pytest.mark.parametrize('host', ['8.8.8.8', '1.1.1.1:80', '127.0.0.1', '0.0.0.0', '224.0.0.1', '203.0.113.9', '198.18.0.5', '100.64.0.1', '240.0.0.1', 'http://93.184.216.34/', '[::1]'])
async def test_public_loopback_and_multicast_addresses_are_refused(host):
    # 203.0.113.0/24 is a documentation range: Python calls it "private", a home network never is.
    with pytest.raises(HostNotAllowed):
        await ensure_lan_host(host)


async def test_a_name_that_resolves_to_a_public_address_is_refused(monkeypatch):
    async def fake(name):
        return ['93.184.216.34']
    monkeypatch.setattr('sentinel.switches.web.fetch._resolve', fake)
    with pytest.raises(HostNotAllowed):
        await ensure_lan_host('switch.example.com')


async def test_a_name_must_resolve_only_to_lan_addresses(monkeypatch):
    async def mixed(name):
        return ['192.168.1.5', '93.184.216.34']
    monkeypatch.setattr('sentinel.switches.web.fetch._resolve', mixed)
    with pytest.raises(HostNotAllowed):
        await ensure_lan_host('switch.lan')


async def test_a_lan_name_is_allowed(monkeypatch):
    async def lan(name):
        return ['192.168.1.5']
    monkeypatch.setattr('sentinel.switches.web.fetch._resolve', lan)
    await ensure_lan_host('switch.lan')


async def test_host_part():
    assert host_part('192.168.1.5:8080') == '192.168.1.5'
    assert host_part('http://sw.lan/x') == 'sw.lan'
    with pytest.raises(HostNotAllowed):
        host_part('')
