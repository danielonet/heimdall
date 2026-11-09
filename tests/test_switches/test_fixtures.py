"""One generic suite, run against every folder in tests/fixtures/switches/.

Adding a switch means adding a folder there (pages, fixture.json, expected.json) and a catalog entry: these tests
pick it up with no new test code. See docs/router-and-switch-expansion-plan.md, section 2.5.
"""
from __future__ import annotations

import hashlib

import httpx
import pytest

from sentinel.switches.catalog import get_spec
from sentinel.switches.core.attribution import attribute
from sentinel.switches.core.counters import CounterTracker
from sentinel.switches.registry import build_source
from sentinel.switches.source import SwitchAuthError, SwitchParseError, SwitchUnreachable
from tests.test_switches.simulator import SwitchSimulator, fixture_dirs

pytestmark = pytest.mark.asyncio


@pytest.fixture(params=fixture_dirs(), ids=lambda p: p.name)
def sim(request) -> SwitchSimulator:
    return SwitchSimulator(request.param)


def make_source(sim: SwitchSimulator, password: str | None = None):
    spec = get_spec(sim.fixture['spec_id'])
    assert spec is not None, f"catalog has no entry {sim.fixture['spec_id']!r}"
    return build_source(spec, sim.host, sim.username, sim.password if password is None else password,
                        transport=sim.transport())


def snapshot_dict(snapshot) -> dict:
    return {
        'identity': {'model': snapshot.identity.model, 'firmware': snapshot.identity.firmware, 'mac': snapshot.identity.mac},
        'ports': [dict(port=p.port, rx_bytes=p.rx_bytes, tx_bytes=p.tx_bytes, rx_packets=p.rx_packets,
                       tx_packets=p.tx_packets, link_up=p.link_up, speed_mbps=p.speed_mbps,
                       counter_bits=p.counter_bits) for p in snapshot.ports],
        'macs': [dict(mac=m.mac, port=m.port, vlan=m.vlan, dynamic=m.dynamic) for m in snapshot.macs],
    }


async def test_first_poll_matches_expected_snapshot(sim):
    source = make_source(sim)
    try:
        snapshot = await source.poll()
    finally:
        await source.aclose()
    assert snapshot_dict(snapshot) == sim.expected['snapshot']
    assert snapshot.warnings == []


async def test_second_poll_gives_expected_deltas_and_attribution(sim):
    source = make_source(sim)
    tracker = CounterTracker()
    try:
        first = attribute(await source.poll(), tracker, 0.0, 'sw')
        assert first.samples == []          # the first reading only sets the baseline
        second = attribute(await source.poll(), tracker, float(sim.expected['poll2']['elapsed_s']), 'sw')
    finally:
        await source.aclose()
    expected = sim.expected['poll2']
    got_ports = {p.port: {'in': p.bytes_in_delta, 'out': p.bytes_out_delta, 'macs': len(p.macs), 'attributed': p.attributed_mac}
                 for p in second.ports}
    assert got_ports == expected['ports']
    got_samples = [{'mac': s.mac_address, 'sent': s.bytes_sent_delta, 'recv': s.bytes_recv_delta} for s in second.samples]
    assert got_samples == expected['samples']
    assert all(s.granularity.value == 'per_device' for s in second.samples)


async def test_login_cookie_is_the_md5_of_user_and_password(sim):
    """Independent of the template evaluator: the driver must send md5(user + password) where the fixture says so."""
    source = make_source(sim)
    try:
        await source.poll()
    finally:
        await source.aclose()
    expected = hashlib.md5((sim.username + sim.password).encode()).hexdigest()
    cookies = [r.headers.get('cookie', '') for r in sim.requests]
    assert any(f'={expected}' in c for c in cookies)


async def test_ended_session_logs_in_once_more_and_carries_on(sim):
    source = make_source(sim)
    try:
        await source.poll()
        assert sim.login_count() == 1
        sim.expire_session()
        snapshot = await source.poll()
    finally:
        await source.aclose()
    assert sim.login_count() == 2
    assert snapshot.ports


async def test_rejected_login_raises_and_is_not_retried_in_a_loop(sim):
    sim.reject_login = True
    source = make_source(sim)
    try:
        with pytest.raises(SwitchAuthError):
            await source.poll()
        assert sim.login_count() == 1
        with pytest.raises(SwitchAuthError, match='suppressed'):
            await source.poll()
        assert sim.login_count() == 1       # cool-down: the wrong password is not sent again
    finally:
        await source.aclose()


async def test_error_messages_never_contain_the_password(sim):
    sim.reject_login = True
    source = make_source(sim)
    try:
        with pytest.raises(SwitchAuthError) as raised:
            await source.poll()
    finally:
        await source.aclose()
    assert sim.password not in str(raised.value)


async def test_a_changed_page_raises_parse_error_instead_of_returning_zeros(sim):
    ports_route = next(r for r in sim.fixture['routes'] if r['method'] == 'GET' and 'stat' in r['path'])
    body = (sim.folder / ports_route['bodies'][0]).read_text()
    first_header = sim.expected['snapshot']['ports'][0]
    assert first_header
    sim.overrides[(ports_route['method'], ports_route['path'])] = body.replace('TxGoodBytes', 'Transmitted')
    source = make_source(sim)
    try:
        with pytest.raises(SwitchParseError, match='layout may have changed'):
            await source.poll()
    finally:
        await source.aclose()


async def test_a_counter_that_is_not_a_number_is_an_error_not_zero(sim):
    ports_route = next(r for r in sim.fixture['routes'] if r['method'] == 'GET' and 'stat' in r['path'])
    body = (sim.folder / ports_route['bodies'][0]).read_text()
    sim.overrides[(ports_route['method'], ports_route['path'])] = body.replace('id=port0-txgoodByte>0-', 'id=port0-txgoodByte>n/a-', 1)
    source = make_source(sim)
    try:
        with pytest.raises(SwitchParseError):
            await source.poll()
    finally:
        await source.aclose()


async def test_an_oversized_page_is_refused(sim):
    route = sim.fixture['routes'][0]
    sim.overrides[(route['method'], route['path'])] = 'x' * (2 * 1024 * 1024 + 1)
    source = make_source(sim)
    try:
        with pytest.raises(SwitchParseError, match='larger than'):
            await source.poll()
    finally:
        await source.aclose()


async def test_a_redirect_is_not_followed(sim):
    route = sim.fixture['routes'][0]
    sim.overrides[(route['method'], route['path'])] = httpx.Response(302, headers={'Location': 'http://203.0.113.9/steal'})
    source = make_source(sim)
    try:
        with pytest.raises(SwitchParseError, match='redirect'):
            await source.poll()
    finally:
        await source.aclose()
    assert not any(r.url.host == '203.0.113.9' for r in sim.requests)


async def test_a_switch_that_does_not_answer_is_unreachable_not_a_parse_error(sim):
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError('refused', request=request)

    spec = get_spec(sim.fixture['spec_id'])
    source = build_source(spec, sim.host, sim.username, sim.password, transport=httpx.MockTransport(refuse))
    try:
        with pytest.raises(SwitchUnreachable):
            await source.poll()
    finally:
        await source.aclose()


async def test_a_public_address_is_refused(sim):
    from sentinel.switches.web.fetch import HostNotAllowed
    spec = get_spec(sim.fixture['spec_id'])
    source = build_source(spec, '8.8.8.8', sim.username, sim.password, transport=sim.transport())
    try:
        with pytest.raises(HostNotAllowed):
            await source.poll()
    finally:
        await source.aclose()
    assert sim.requests == []              # nothing was sent
