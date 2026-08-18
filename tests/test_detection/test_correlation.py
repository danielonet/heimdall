"""Integration tests for CrossAlertCorrelator against the real migrated
schema — Alert.device_mac has no FK, so these seed Alert rows directly
without needing a Device row (mirrors test_rules_engine.py's real-DB style).
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.db.models import Alert
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.correlation import CrossAlertCorrelator

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:f1'
_MAC2 = 'aa:bb:cc:dd:ee:f2'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac.in_([_MAC, _MAC2])))
    await get_engine().dispose()


async def _add_alert(mac: str, alert_type: str, created_at: datetime, **kwargs) -> int:
    async with get_session() as session:
        alert = Alert(device_mac=mac, alert_type=alert_type, severity='WARNING', created_at=created_at, **kwargs)
        session.add(alert)
        await session.flush()
        alert_id = alert.id
    return alert_id


@pytest.fixture
def correlator() -> CrossAlertCorrelator:
    return CrossAlertCorrelator()


class TestFindNewIncidents:
    async def test_matching_pair_within_window_produces_one_incident(self, correlator):
        now = datetime.now(timezone.utc)
        trigger_id = await _add_alert(_MAC, 'NEW_DEVICE', now - timedelta(minutes=30))
        follow_id = await _add_alert(_MAC, 'ARP_SPOOF', now - timedelta(minutes=20))

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        matches = [i for i in incidents if i['mac'] == _MAC]
        assert len(matches) == 1
        assert matches[0]['pattern_name'] == 'NEW_DEVICE_THEN_SPOOFING'
        assert matches[0]['trigger_alert_id'] == trigger_id
        assert matches[0]['follow_alert_id'] == follow_id

    async def test_pair_outside_the_window_produces_no_incident(self, correlator):
        now = datetime.now(timezone.utc)
        await _add_alert(_MAC, 'NEW_DEVICE', now - timedelta(minutes=120))
        await _add_alert(_MAC, 'ARP_SPOOF', now - timedelta(minutes=10))  # 110min gap > 60min window

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        assert not any(i['mac'] == _MAC for i in incidents)

    async def test_follow_before_trigger_is_not_matched(self, correlator):
        now = datetime.now(timezone.utc)
        await _add_alert(_MAC, 'NEW_DEVICE', now - timedelta(minutes=10))
        await _add_alert(_MAC, 'ARP_SPOOF', now - timedelta(minutes=20))  # earlier than the trigger

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        assert not any(i['mac'] == _MAC for i in incidents)

    async def test_different_devices_do_not_cross_contaminate(self, correlator):
        now = datetime.now(timezone.utc)
        await _add_alert(_MAC, 'NEW_DEVICE', now - timedelta(minutes=30))
        await _add_alert(_MAC2, 'ARP_SPOOF', now - timedelta(minutes=20))  # different MAC

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        assert not any(i['mac'] == _MAC for i in incidents)
        assert not any(i['mac'] == _MAC2 for i in incidents)

    async def test_a_previously_correlated_pair_does_not_re_fire(self, correlator):
        now = datetime.now(timezone.utc)
        trigger_id = await _add_alert(_MAC, 'NEW_DEVICE', now - timedelta(minutes=30))
        follow_id = await _add_alert(_MAC, 'ARP_SPOOF', now - timedelta(minutes=20))
        # Simulate the scheduler's _correlation_job having already escalated this pair.
        await _add_alert(
            _MAC, 'COMPROMISE_CHAIN_DETECTED', now,
            raw_data={'trigger_alert_id': trigger_id, 'follow_alert_id': follow_id},
        )

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        assert not any(i['mac'] == _MAC for i in incidents)

    async def test_a_later_different_follow_alert_still_produces_a_fresh_incident(self, correlator):
        """Dedup is keyed on the specific follow-alert id, not the device —
        a second, later follow-alert of the same device must still fire."""
        now = datetime.now(timezone.utc)
        trigger_id = await _add_alert(_MAC, 'NEW_DEVICE', now - timedelta(minutes=50))
        old_follow_id = await _add_alert(_MAC, 'ARP_SPOOF', now - timedelta(minutes=40))
        await _add_alert(
            _MAC, 'COMPROMISE_CHAIN_DETECTED', now - timedelta(minutes=39),
            raw_data={'trigger_alert_id': trigger_id, 'follow_alert_id': old_follow_id},
        )
        new_follow_id = await _add_alert(_MAC, 'FINGERPRINT_MISMATCH', now - timedelta(minutes=10))

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        matches = [i for i in incidents if i['mac'] == _MAC]
        assert len(matches) == 1
        assert matches[0]['follow_alert_id'] == new_follow_id

    async def test_exposure_then_compromise_pattern_within_24h(self, correlator):
        now = datetime.now(timezone.utc)
        trigger_id = await _add_alert(_MAC, 'CREDENTIAL_EXPOSURE_DETECTED', now - timedelta(hours=20))
        follow_id = await _add_alert(_MAC, 'C2_BEACONING', now - timedelta(hours=1))

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        matches = [i for i in incidents if i['mac'] == _MAC]
        assert len(matches) == 1
        assert matches[0]['pattern_name'] == 'EXPOSURE_THEN_COMPROMISE'
        assert matches[0]['trigger_alert_id'] == trigger_id
        assert matches[0]['follow_alert_id'] == follow_id

    async def test_exposure_then_malicious_traffic_destination(self, correlator):
        """MALICIOUS_TRAFFIC_DESTINATION (SentinelScheduler._spike_ip_enrichment_job's
        escalation) is a follow_type on EXPOSURE_THEN_COMPROMISE too — a
        device with a known prior weakness now confirmed talking to a
        malicious IP is a stronger compromise signal."""
        now = datetime.now(timezone.utc)
        trigger_id = await _add_alert(_MAC, 'HIGH_RISK_PORT_OPENED', now - timedelta(hours=20))
        follow_id = await _add_alert(_MAC, 'MALICIOUS_TRAFFIC_DESTINATION', now - timedelta(hours=1))

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        matches = [i for i in incidents if i['mac'] == _MAC]
        assert len(matches) == 1
        assert matches[0]['pattern_name'] == 'EXPOSURE_THEN_COMPROMISE'
        assert matches[0]['trigger_alert_id'] == trigger_id
        assert matches[0]['follow_alert_id'] == follow_id

    async def test_a_recurring_trigger_is_found_via_last_seen_not_created_at(self, correlator):
        """AlertRepository.upsert() touches (rather than re-inserts) a
        still-recurring trigger alert, so created_at is set once at first
        occurrence and never advances. A trigger first created outside
        _LOOKBACK_HOURS (48h) but still actively recurring (last_seen
        recent) must still be found — filtering on created_at here would
        silently drop it from the correlator's lookback window."""
        now = datetime.now(timezone.utc)
        trigger_id = await _add_alert(
            _MAC, 'CREDENTIAL_EXPOSURE_DETECTED', now - timedelta(hours=50),
            last_seen=now - timedelta(minutes=10),
        )
        follow_id = await _add_alert(_MAC, 'C2_BEACONING', now - timedelta(hours=30))

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        matches = [i for i in incidents if i['mac'] == _MAC]
        assert len(matches) == 1
        assert matches[0]['trigger_alert_id'] == trigger_id
        assert matches[0]['follow_alert_id'] == follow_id

    async def test_unrelated_alert_types_produce_nothing(self, correlator):
        now = datetime.now(timezone.utc)
        await _add_alert(_MAC, 'HIGH_UPLOAD', now - timedelta(minutes=30))
        await _add_alert(_MAC, 'SIGNAL_ANOMALY', now - timedelta(minutes=20))

        async with get_session() as session:
            incidents = await correlator.find_new_incidents(session)

        assert not any(i['mac'] == _MAC for i in incidents)
