import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import DeviceSnapshot
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.detectors.vendor_mismatch import VendorMismatchDetector

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    """Only TestResolveOnConditionChange below needs the DB (a state
    transition on the same detector instance triggers a real
    AlertRepository().resolve() call) — harmless overhead for the
    single-call tests above, which never reach that branch."""
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac == _MAC))
    await get_engine().dispose()


def _device(hostname: str, vendor_name: str) -> DeviceSnapshot:
    return DeviceSnapshot(
        mac_address='aa:bb:cc:dd:ee:ff',
        ip_address='10.100.102.10',
        hostname=hostname,
        vendor_name=vendor_name,
        interface_name='WiFi',
    )


class TestInspectDevice:
    async def test_mismatched_hostname_and_vendor_alerts(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('daniels-iphone', 'Samsung Electronics'))
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'VENDOR_MISMATCH'

    async def test_matching_hostname_and_vendor_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('daniels-iphone', 'Apple, Inc.'))
        assert alert is None

    async def test_hostname_with_no_known_keyword_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('kitchen-speaker', 'Amazon Technologies'))
        assert alert is None

    async def test_case_insensitive_matching(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('DANIELS-IPHONE', 'samsung electronics'))
        assert alert is not None

    async def test_missing_hostname_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('', 'Samsung Electronics'))
        assert alert is None

    async def test_missing_vendor_with_hostname_hint_raises_unverified_info_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('daniels-iphone', ''))
        assert alert is not None
        assert alert.severity == 'INFO'
        assert alert.alert_type == 'VENDOR_UNVERIFIED'

    async def test_missing_vendor_with_no_hostname_hint_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('kitchen-speaker', ''))
        assert alert is None


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_traffic(sample=None, snapshot=_device('x', 'y'))
        assert alert is None


class TestResolveOnConditionChange:
    """Confirmed to have zero gating of its own before this redesign — a
    static mismatch used to re-fire a brand-new alert every single poll.
    Coalescing repeats is now AlertRepository.upsert()'s job (at the
    poll_cycle level); this detector's own job is only to resolve() the
    open alert the moment the condition stops being true or switches type."""

    async def test_condition_clearing_resolves_the_open_alert_row(self):
        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type='VENDOR_MISMATCH', severity='WARNING', description='seed',
        )
        detector = VendorMismatchDetector()
        await detector.inspect_device(_device('daniels-iphone', 'Samsung Electronics'))
        assert detector._open_alert_type[_MAC] == 'VENDOR_MISMATCH'

        await detector.inspect_device(_device('daniels-iphone', 'Apple, Inc.'))  # now matches

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
            assert refreshed.resolved is True
        assert _MAC not in detector._open_alert_type

    async def test_switching_alert_type_resolves_the_previous_one(self):
        """A device whose OUI resolution goes from blank to a known,
        conflicting vendor flips VENDOR_UNVERIFIED -> VENDOR_MISMATCH — the
        old type's row must close, not just get orphaned open forever."""
        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type='VENDOR_UNVERIFIED', severity='INFO', description='seed',
        )
        detector = VendorMismatchDetector()
        await detector.inspect_device(_device('daniels-iphone', ''))
        assert detector._open_alert_type[_MAC] == 'VENDOR_UNVERIFIED'

        result = await detector.inspect_device(_device('daniels-iphone', 'Samsung Electronics'))
        assert result.alert_type == 'VENDOR_MISMATCH'

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
            assert refreshed.resolved is True
        assert detector._open_alert_type[_MAC] == 'VENDOR_MISMATCH'

    async def test_resolve_is_not_called_when_nothing_was_ever_open(self, monkeypatch):
        called = False

        async def _boom(*args, **kwargs):
            nonlocal called
            called = True
            return True

        monkeypatch.setattr(AlertRepository, 'resolve', _boom)
        detector = VendorMismatchDetector()
        await detector.inspect_device(_device('daniels-iphone', 'Apple, Inc.'))  # matches, never mismatched
        assert called is False
