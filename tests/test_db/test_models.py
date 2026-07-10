"""Round-trip tests for the SQLAlchemy models against the migrated schema.

Each test flushes (not commits) within a transaction that the db_session
fixture rolls back afterward, so nothing persists in the real database.
"""
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from sentinel.db.models import (
    Alert,
    Device,
    DnsQuery,
    PortStats,
    Rule,
    ThreatIntelCache,
    TrafficSample,
    WanStatusHistory,
)

pytestmark = pytest.mark.asyncio


class TestDevice:
    async def test_insert_and_fetch_by_mac_address(self, db_session):
        device = Device(
            mac_address='aa:bb:cc:dd:ee:ff',
            ip_address='10.100.102.50',
            hostname='test-device',
            vendor_name='Acme Corp',
            interface_name='WiFi',
        )
        db_session.add(device)
        await db_session.flush()

        fetched = await db_session.get(Device, 'aa:bb:cc:dd:ee:ff')
        assert fetched is not None
        assert fetched.hostname == 'test-device'
        assert fetched.traffic_granularity == 'per_device'  # server default
        assert fetched.is_blocked is False

    async def test_tags_array_round_trips(self, db_session):
        device = Device(mac_address='11:22:33:44:55:66', tags=['trusted', 'iot'])
        db_session.add(device)
        await db_session.flush()

        fetched = await db_session.get(Device, '11:22:33:44:55:66')
        assert set(fetched.tags) == {'trusted', 'iot'}


class TestTrafficSample:
    async def test_insert_and_query_by_mac_address(self, db_session):
        sample = TrafficSample(
            time=datetime.now(timezone.utc),
            mac_address='aa:bb:cc:dd:ee:ff',
            bytes_sent_delta=100,
            bytes_recv_delta=200,
            throughput_up_kbps=8,
            throughput_dn_kbps=16,
            granularity='per_device',
            poll_interval_s=15,
        )
        db_session.add(sample)
        await db_session.flush()

        result = await db_session.execute(
            select(TrafficSample).where(TrafficSample.mac_address == 'aa:bb:cc:dd:ee:ff')
        )
        fetched = result.scalar_one()
        assert fetched.bytes_sent_delta == 100
        assert fetched.anomaly_score is None  # NULL during bootstrap


class TestPortStats:
    async def test_insert_and_query_by_port_alias(self, db_session):
        stats = PortStats(
            time=datetime.now(timezone.utc),
            port_alias='PHY5',
            status='UP',
            link_speed_mbps=1000,
            bytes_sent_delta=1_000,
            bytes_recv_delta=2_000,
        )
        db_session.add(stats)
        await db_session.flush()

        result = await db_session.execute(select(PortStats).where(PortStats.port_alias == 'PHY5'))
        fetched = result.scalar_one()
        assert fetched.status == 'UP'
        assert fetched.link_speed_mbps == 1000


class TestDnsQuery:
    async def test_insert_and_query_by_device_mac(self, db_session):
        query = DnsQuery(
            time=datetime.now(timezone.utc),
            device_mac='aa:bb:cc:dd:ee:ff',
            query='malicious.example.com',
            blocked=True,
            list_name='Phishing Army',
        )
        db_session.add(query)
        await db_session.flush()

        result = await db_session.execute(
            select(DnsQuery).where(DnsQuery.device_mac == 'aa:bb:cc:dd:ee:ff')
        )
        fetched = result.scalar_one()
        assert fetched.blocked is True
        assert fetched.list_name == 'Phishing Army'


class TestAlert:
    async def test_insert_generates_id_and_defaults(self, db_session):
        alert = Alert(
            device_mac='aa:bb:cc:dd:ee:ff',
            alert_type='port_scan',
            severity='WARNING',
            description='Port scan detected',
            raw_data={'ports': [22, 80, 443]},
        )
        db_session.add(alert)
        await db_session.flush()

        assert alert.id is not None
        assert alert.acknowledged is False
        assert alert.resolved is False
        assert alert.raw_data == {'ports': [22, 80, 443]}


class TestRule:
    async def test_insert_and_fetch(self, db_session):
        rule = Rule(
            name='Block known C2 IPs',
            condition_json={'field': 'dest_ip', 'op': 'in_feed', 'feed': 'feodo'},
            action_json={'type': 'block'},
        )
        db_session.add(rule)
        await db_session.flush()

        fetched = await db_session.get(Rule, rule.id)
        assert fetched.enabled is True
        assert fetched.name == 'Block known C2 IPs'


class TestThreatIntelCache:
    async def test_insert_and_fetch_by_ip_or_domain(self, db_session):
        cache_entry = ThreatIntelCache(
            ip_or_domain='198.51.100.23',
            is_malicious=True,
            threat_type='botnet_c2',
            source_feed='feodo',
            score=90,
        )
        db_session.add(cache_entry)
        await db_session.flush()

        fetched = await db_session.get(ThreatIntelCache, '198.51.100.23')
        assert fetched.is_malicious is True
        assert fetched.source_feed == 'feodo'


class TestWanStatusHistory:
    async def test_insert_and_fetch(self, db_session):
        entry = WanStatusHistory(status='DOWN', wan_mode='PPPoE', duration_s=120)
        db_session.add(entry)
        await db_session.flush()

        fetched = await db_session.get(WanStatusHistory, entry.id)
        assert fetched.status == 'DOWN'
        assert fetched.changed_at is not None  # server default
