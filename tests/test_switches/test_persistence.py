"""Switch polls written to a real Postgres, and how they interact with the router poll's own writes.

These need a database migrated to head (including a8d3f1c7e925, the switch tables). They skip when the switch
tables are missing. They only create and delete rows whose MAC starts with the synthetic prefix 02:00:00:00:00:.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select, text

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity
from sentinel.adapter.models import TrafficSample as TrafficSampleSnapshot
from sentinel.db.models import Device, SwitchPortStat, TrafficSample
from sentinel.db.repositories import SwitchPortRepository, SwitchTargetRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.jobs import _insert_traffic_samples, _upsert_devices
from sentinel.switches.core.attribution import attribute
from sentinel.switches.core.counters import CounterTracker
from sentinel.switches.store import persist_poll, switch_owned_macs
from tests.test_switches.helpers import snap

pytestmark = pytest.mark.asyncio

A, B, C = '02:00:00:00:00:0a', '02:00:00:00:00:0b', '02:00:00:00:00:0c'
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture(autouse=True)
async def _db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel')
    init_db(app)
    try:
        async with get_session() as session:
            present = (await session.execute(text(
                "select count(*) from information_schema.tables where table_name = 'switch_targets'"))).scalar()
    except Exception as exc:
        await get_engine().dispose()
        pytest.skip(f'database unavailable: {exc}')
    if not present:
        await get_engine().dispose()
        pytest.skip('the switch tables are missing: run the migrations (alembic upgrade head) on this database')
    await _clean()
    yield
    await _clean()
    await get_engine().dispose()


async def _clean() -> None:
    async with get_session() as session:
        await session.execute(text('TRUNCATE switch_targets, switch_port_stats RESTART IDENTITY'))
        await session.execute(delete(TrafficSample).where(TrafficSample.mac_address.like('02:00:00:00:00:%')))
        await session.execute(delete(Device).where(Device.mac_address.like('02:00:00:00:00:%')))


async def add_device(mac: str, **fields) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=mac, ip_address='192.168.0.50', hostname='dev', interface_name='Ethernet', **fields))


async def get_device(mac: str) -> Device:
    async with get_session() as session:
        return await session.get(Device, mac)


def two_poll_attribution(macs_by_port, second=None):
    """Attribution of a second poll: A uploaded 50 and downloaded 4000 on port 1."""
    tracker = CounterTracker()
    attribute(snap({'1': (0, 0), '8': (0, 0)}, macs_by_port), tracker, 0.0, 'sw')
    return attribute(second or snap({'1': (50, 4000), '8': (9000, 90)}, macs_by_port), tracker, 10.0, 'sw')


async def test_a_poll_stores_port_rows_a_device_sample_and_the_device_columns():
    await add_device(A, traffic_granularity='per_port')
    attribution = two_poll_attribution([(A, '1'), (B, '8'), (C, '8')])
    unknown = await persist_poll(1, 'Garage', attribution, NOW)
    assert unknown == []

    async with get_session() as session:
        ports = {r.port: r for r in await session.scalars(select(SwitchPortStat).where(SwitchPortStat.switch_id == 1))}
        samples = list(await session.scalars(select(TrafficSample).where(TrafficSample.mac_address == A)))
    assert set(ports) == {'1', '8'}
    assert (ports['1'].bytes_in_delta, ports['1'].bytes_out_delta, ports['1'].macs, ports['1'].attributed_mac) == (50, 4000, 1, A)
    assert (ports['8'].bytes_in_delta, ports['8'].macs, ports['8'].attributed_mac) == (9000, 2, None)
    [sample] = samples
    assert (sample.bytes_sent_delta, sample.bytes_recv_delta, sample.granularity) == (50, 4000, 'per_device')
    device = await get_device(A)
    assert (device.switch_name, device.switch_port, device.switch_target_id) == ('Garage', '1', 1)
    assert device.traffic_granularity == 'per_device' and device.switch_seen_at == NOW


async def test_the_baseline_poll_stores_nothing():
    await add_device(A)
    first = attribute(snap({'1': (0, 0)}, [(A, '1')]), CounterTracker(), 0.0, 'sw')
    await persist_poll(1, 'Garage', first, NOW)
    async with get_session() as session:
        assert list(await session.scalars(select(SwitchPortStat))) == []
        assert list(await session.scalars(select(TrafficSample).where(TrafficSample.mac_address == A))) == []


async def test_a_mac_heimdall_has_no_row_for_is_reported_and_not_created():
    attribution = two_poll_attribution([(A, '1')])
    assert await persist_poll(1, 'Garage', attribution, NOW) == [A]
    async with get_session() as session:
        assert await session.get(Device, A) is None
        assert list(await session.scalars(select(TrafficSample).where(TrafficSample.mac_address == A))) == []


async def test_a_device_that_moves_to_a_shared_port_is_released():
    await add_device(A)
    await persist_poll(1, 'Garage', two_poll_attribution([(A, '1')]), NOW)
    assert (await get_device(A)).switch_port == '1'
    shared = two_poll_attribution([(A, '1'), (B, '1')])
    await persist_poll(1, 'Garage', shared, NOW + timedelta(seconds=15))
    device = await get_device(A)
    assert device.switch_port is None and device.switch_target_id is None


async def test_switch_owned_macs_only_lists_recently_confirmed_devices():
    await add_device(A, switch_seen_at=datetime.now(timezone.utc) - timedelta(seconds=30))
    await add_device(B, switch_seen_at=datetime.now(timezone.utc) - timedelta(hours=2))
    await add_device(C)
    async with get_session() as session:
        assert await switch_owned_macs(session) == {A}


def wired(mac: str, port: str) -> DeviceSnapshot:
    return DeviceSnapshot(mac_address=mac, ip_address='192.168.0.50', hostname='dev', interface_name='Ethernet',
                          port_alias=port, is_online=True)


async def test_the_router_poll_does_not_flip_a_switch_owned_device_back_to_per_port():
    """Regression: two devices share router port PHY5, so the router says per_port every cycle. While a switch
    confirmed A recently, A stays per_device; once the confirmation is stale the router's view applies again."""
    await add_device(A, traffic_granularity='per_device', switch_seen_at=datetime.now(timezone.utc) - timedelta(seconds=20))
    await add_device(B, traffic_granularity='per_device')
    async with get_session() as session:
        await _upsert_devices(session, [wired(A, 'PHY5'), wired(B, 'PHY5')])
    assert (await get_device(A)).traffic_granularity == 'per_device'     # a switch owns it
    assert (await get_device(B)).traffic_granularity == 'per_port'       # nobody does: the router's view

    async with get_session() as session:
        (await session.get(Device, A)).switch_seen_at = datetime.now(timezone.utc) - timedelta(hours=1)
    async with get_session() as session:
        await _upsert_devices(session, [wired(A, 'PHY5'), wired(B, 'PHY5')])
    assert (await get_device(A)).traffic_granularity == 'per_port'


def router_sample(mac: str, granularity=TrafficGranularity.PER_DEVICE) -> TrafficSampleSnapshot:
    return TrafficSampleSnapshot(mac_address=mac, timestamp=NOW, bytes_sent_delta=1, bytes_recv_delta=2, granularity=granularity)


async def test_the_router_poll_skips_its_own_per_device_row_for_a_switch_owned_mac():
    """One stream of bytes must not be counted twice: the switch's row is stored, the router's is skipped."""
    async with get_session() as session:
        await _insert_traffic_samples(
            session, [router_sample(A), router_sample(B), router_sample('PHY5', TrafficGranularity.PER_PORT)],
            {}, skip_macs={A, 'PHY5'},
        )
    async with get_session() as session:
        stored = {r.mac_address for r in await session.scalars(
            select(TrafficSample).where(TrafficSample.mac_address.in_([A, B])))}
    assert stored == {B}        # A skipped (owned); B stored
    async with get_session() as session:
        await session.execute(delete(TrafficSample).where(TrafficSample.mac_address == 'PHY5'))


async def test_per_port_rows_are_never_skipped():
    async with get_session() as session:
        await _insert_traffic_samples(session, [router_sample('PHY5', TrafficGranularity.PER_PORT)], {}, skip_macs={'PHY5'})
    async with get_session() as session:
        rows = list(await session.scalars(select(TrafficSample).where(TrafficSample.mac_address == 'PHY5')))
        await session.execute(delete(TrafficSample).where(TrafficSample.mac_address == 'PHY5'))
    assert len(rows) == 1


async def test_repository_create_update_status_and_delete():
    repo = SwitchTargetRepository()
    row = await repo.create(spec_id='hc-swtgw218as', name='Garage', host='192.168.0.2', username='admin', poll_interval_s=15)
    assert row.id == 1 and (await repo.count()) == 1
    assert await repo.update(row.id, name='Rack', enabled=False) and not await repo.update(999, name='x')
    with pytest.raises(ValueError):
        await repo.update(row.id, consecutive_failures=5)
    assert [t.name for t in await repo.list_all()] == ['Rack'] and await repo.list_enabled() == []

    assert await repo.record_failure(row.id, 'no answer') == 1
    assert await repo.record_failure(row.id, 'no answer') == 2
    await repo.record_ok(row.id, model='M1', firmware='v9', now=NOW)
    fresh = await repo.get(row.id)
    assert (fresh.consecutive_failures, fresh.last_error, fresh.model, fresh.last_ok_at) == (0, None, 'M1', NOW)


async def test_deleting_a_switch_removes_its_history_and_releases_its_devices():
    repo = SwitchTargetRepository()
    row = await repo.create(spec_id='hc-swtgw218as', name='Garage', host='192.168.0.2', username='admin', poll_interval_s=15)
    await add_device(A)
    await persist_poll(row.id, 'Garage', two_poll_attribution([(A, '1')]), NOW)
    await repo.delete(row.id)
    assert await repo.get(row.id) is None
    device = await get_device(A)
    assert (device.switch_target_id, device.switch_port, device.switch_seen_at) == (None, None, None)
    async with get_session() as session:
        assert list(await session.scalars(select(SwitchPortStat))) == []


async def test_latest_ports_returns_one_row_per_port_with_the_device_name():
    repo = SwitchTargetRepository()
    row = await repo.create(spec_id='hc-swtgw218as', name='Garage', host='192.168.0.2', username='admin', poll_interval_s=15)
    await add_device(A, nickname='Office PC')
    now = datetime.now(timezone.utc)
    await persist_poll(row.id, 'Garage', two_poll_attribution([(A, '1'), (B, '8'), (C, '8')]), now - timedelta(seconds=30))
    await persist_poll(row.id, 'Garage', two_poll_attribution([(A, '1'), (B, '8'), (C, '8')]), now)
    ports = await SwitchPortRepository().latest_ports(row.id)
    assert [p['port'] for p in ports] == ['1', '8']
    assert ports[0]['device_name'] == 'Office PC' and ports[1]['device_name'] == '' and ports[1]['attributed_mac'] is None
