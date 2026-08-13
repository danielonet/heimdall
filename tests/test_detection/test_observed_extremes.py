"""Integration tests for sentinel/detection/observed_extremes.py against the
real migrated schema — same per-test engine create/dispose pattern as
tests/test_ml/test_trainer.py (these queries go through the module-level
get_session() singleton).

Each query is grouped PER device_type (see the module docstring), but within
one type it's still a global max across every device of that type — against
a long-running shared dev database that already has real traffic history for
some types, there's no way to assert "no data for this type" or "exactly our
seeded value wins." Instead, each test either uses a dedicated, never-seen
device_type string (so there's guaranteed no ambient data to compete with)
or seeds a value extreme enough to dominate regardless (a ratio no real
traffic could produce, a streak far longer than realistic mock traffic would
generate, or the mathematical maximum of 1.0 for a fraction).
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import TrafficGranularity
from sentinel.db.models import Device, TrafficSample
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.observed_extremes import (
    compute_observed_extremes, get_highest_anomalous_fraction_by_type, get_highest_ratio_by_type,
    get_longest_anomalous_streak_by_type,
)

pytestmark = pytest.mark.asyncio

_MAC_A = 'aa:bb:cc:dd:ee:f1'
_MAC_B = 'aa:bb:cc:dd:ee:f2'
_TYPE_A = '__test_type_a__'
_TYPE_B = '__test_type_b__'
_BASE_TIME = datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)

_DOMINANT_STREAK_LEN = 5000


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(TrafficSample).where(TrafficSample.mac_address.in_([_MAC_A, _MAC_B])))
        await session.execute(delete(Device).where(Device.mac_address.in_([_MAC_A, _MAC_B])))
    await get_engine().dispose()


def _sample(mac, offset_s, *, sent=1000, recv=1000, anomaly_score=None) -> TrafficSample:
    return TrafficSample(
        time=_BASE_TIME + timedelta(seconds=offset_s),
        mac_address=mac,
        bytes_sent_delta=sent,
        bytes_recv_delta=recv,
        throughput_up_kbps=sent,
        throughput_dn_kbps=recv,
        anomaly_score=anomaly_score,
        granularity=TrafficGranularity.PER_DEVICE.value,
        poll_interval_s=15,
    )


async def _add_sample(mac, offset_s, *, sent=1000, recv=1000, anomaly_score=None):
    async with get_session() as session:
        session.add(_sample(mac, offset_s, sent=sent, recv=recv, anomaly_score=anomaly_score))


async def _add_samples(samples: list[TrafficSample]) -> None:
    async with get_session() as session:
        session.add_all(samples)


async def _add_device(mac: str, device_type: str, hostname: str = '') -> None:
    async with get_session() as session:
        session.add(Device(mac_address=mac, hostname=hostname, device_type=device_type))


class TestGetHighestRatioByType:
    async def test_grouped_by_device_type_not_globally(self):
        """Two distinct, never-seeded device types, each with its own
        distinct max ratio — both must show up as separate entries, proving
        this is a per-type breakdown and not one global winner."""
        await _add_device(_MAC_A, _TYPE_A)
        await _add_device(_MAC_B, _TYPE_B)
        await _add_sample(_MAC_A, 0, sent=500, recv=100)   # ratio 5.0
        await _add_sample(_MAC_B, 0, sent=900, recv=100)   # ratio 9.0

        result = await get_highest_ratio_by_type()

        assert result[_TYPE_A].value == pytest.approx(5.0)
        assert result[_TYPE_A].device_mac == _MAC_A
        assert result[_TYPE_B].value == pytest.approx(9.0)
        assert result[_TYPE_B].device_mac == _MAC_B

    async def test_picks_the_highest_among_multiple_devices_of_the_same_type(self):
        await _add_device(_MAC_A, _TYPE_A, hostname='phone-1')
        await _add_device(_MAC_B, _TYPE_A, hostname='phone-2')
        await _add_sample(_MAC_A, 0, sent=200, recv=100)   # ratio 2.0
        await _add_sample(_MAC_B, 0, sent=800, recv=100)   # ratio 8.0

        result = await get_highest_ratio_by_type()

        assert result[_TYPE_A].value == pytest.approx(8.0)
        assert result[_TYPE_A].hostname == 'phone-2'

    async def test_zero_recv_does_not_divide_by_zero(self):
        await _add_device(_MAC_A, _TYPE_A)
        await _add_sample(_MAC_A, 0, sent=500, recv=0)
        result = await get_highest_ratio_by_type()
        assert result[_TYPE_A].value == pytest.approx(500.0)  # GREATEST(recv, 1)

    async def test_devices_with_no_device_type_are_excluded(self):
        await _add_sample(_MAC_A, 0, sent=99999, recv=1)  # no Device row at all
        result = await get_highest_ratio_by_type()
        assert _MAC_A not in {e.device_mac for e in result.values()}

    async def test_per_port_samples_are_excluded(self):
        await _add_device(_MAC_A, _TYPE_A)
        async with get_session() as session:
            session.add(TrafficSample(
                time=_BASE_TIME, mac_address=_MAC_A, bytes_sent_delta=99999, bytes_recv_delta=1,
                granularity=TrafficGranularity.PER_PORT.value, poll_interval_s=15,
            ))
        result = await get_highest_ratio_by_type()
        assert _TYPE_A not in result


class TestGetLongestAnomalousStreakByType:
    async def test_finds_a_streak_longer_than_any_break_in_between(self):
        await _add_device(_MAC_A, _TYPE_A)
        samples = [_sample(_MAC_A, i * 15, anomaly_score=-0.1) for i in range(_DOMINANT_STREAK_LEN)]
        samples.append(_sample(_MAC_A, _DOMINANT_STREAK_LEN * 15, anomaly_score=0.5))  # breaks the streak
        samples.append(_sample(_MAC_A, (_DOMINANT_STREAK_LEN + 1) * 15, anomaly_score=-0.1))
        await _add_samples(samples)

        result = await get_longest_anomalous_streak_by_type()

        assert result[_TYPE_A].value == _DOMINANT_STREAK_LEN
        assert result[_TYPE_A].device_mac == _MAC_A

    async def test_null_anomaly_score_does_not_bridge_two_runs(self):
        await _add_device(_MAC_A, _TYPE_A)
        samples = [_sample(_MAC_A, i * 15, anomaly_score=-0.1) for i in range(_DOMINANT_STREAK_LEN)]
        samples.append(_sample(_MAC_A, _DOMINANT_STREAK_LEN * 15, anomaly_score=None))
        samples.append(_sample(_MAC_A, (_DOMINANT_STREAK_LEN + 1) * 15, anomaly_score=-0.1))
        await _add_samples(samples)

        result = await get_longest_anomalous_streak_by_type()

        assert result[_TYPE_A].value == _DOMINANT_STREAK_LEN  # not + 1

    async def test_positive_score_is_not_anomalous(self):
        await _add_device(_MAC_A, _TYPE_A)
        for i in range(10):
            await _add_sample(_MAC_A, i * 15, anomaly_score=0.5)
        result = await get_longest_anomalous_streak_by_type()
        assert _TYPE_A not in result

    async def test_grouped_by_device_type_not_globally(self):
        await _add_device(_MAC_A, _TYPE_A)
        await _add_device(_MAC_B, _TYPE_B)
        for i in range(3):
            await _add_sample(_MAC_A, i * 15, anomaly_score=-0.1)
        for i in range(7):
            await _add_sample(_MAC_B, i * 15, anomaly_score=-0.1)

        result = await get_longest_anomalous_streak_by_type()

        assert result[_TYPE_A].value == 3
        assert result[_TYPE_B].value == 7


class TestGetHighestAnomalousFractionByType:
    async def test_the_mathematical_maximum_of_one_beats_any_ambient_data(self):
        await _add_device(_MAC_A, _TYPE_A)
        for i in range(5):
            await _add_sample(_MAC_A, i * 15, anomaly_score=-0.1)  # 5 of 5 anomalous = 1.0

        result = await get_highest_anomalous_fraction_by_type()

        assert result[_TYPE_A].value == pytest.approx(1.0)
        assert result[_TYPE_A].device_mac == _MAC_A

    async def test_grouped_by_device_type_not_globally(self):
        await _add_device(_MAC_A, _TYPE_A)
        await _add_device(_MAC_B, _TYPE_B)
        for i, score in enumerate([-0.1, 0.5, 0.5, 0.5]):  # 1 of 4 = 0.25
            await _add_sample(_MAC_A, i * 15, anomaly_score=score)
        for i, score in enumerate([-0.1, -0.2, -0.3, 0.5]):  # 3 of 4 = 0.75
            await _add_sample(_MAC_B, i * 15, anomaly_score=score)

        result = await get_highest_anomalous_fraction_by_type()

        assert result[_TYPE_A].value == pytest.approx(0.25)
        assert result[_TYPE_B].value == pytest.approx(0.75)


class TestComputeObservedExtremes:
    async def test_merges_all_three_metrics_under_one_device_type_key(self):
        await _add_device(_MAC_A, _TYPE_A, hostname='my-phone')
        await _add_sample(_MAC_A, 0, sent=500, recv=100, anomaly_score=-0.1)

        result = await compute_observed_extremes()

        assert _TYPE_A in result
        entry = result[_TYPE_A]
        assert set(entry.keys()) == {'high_upload_ratio_threshold', 'volume_sustained_polls', 'contamination'}
        assert entry['high_upload_ratio_threshold']['hostname'] == 'my-phone'
        assert entry['high_upload_ratio_threshold']['device_mac'] == _MAC_A

    async def test_a_metric_with_no_scored_data_is_none_not_missing(self):
        """This type has ratio data but no anomaly_score at all — POLLS and
        CONTAM. must be explicitly None, not simply absent from the dict."""
        await _add_device(_MAC_A, _TYPE_A)
        await _add_sample(_MAC_A, 0, sent=500, recv=100, anomaly_score=None)

        result = await compute_observed_extremes()

        assert result[_TYPE_A]['high_upload_ratio_threshold'] is not None
        assert result[_TYPE_A]['volume_sustained_polls'] is None
        assert result[_TYPE_A]['contamination'] is None
