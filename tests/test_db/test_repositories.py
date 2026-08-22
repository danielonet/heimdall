"""Integration tests for DeviceRepository/TrustedMacRepository against the
real migrated schema.

Uses the same per-test engine create/dispose pattern as tests/test_scheduler
(these repositories go through the module-level get_session() singleton,
whose connection pool must be created on the same event loop pytest-asyncio
gives this test).
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.config import settings
from sentinel.db.models import AppSettings, Device, DeviceTypeProfile, TrustedMac
from sentinel.db.repositories import (
    DeviceRepository, DeviceTypeProfileRepository, SettingsRepository, TrustedMacRepository,
)
from sentinel.db.session import get_engine, get_session, init_db

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_MAC_2 = '11:22:33:44:55:66'
_MAC_3 = '77:88:99:aa:bb:cc'
_TEST_DEVICE_TYPE = '__test_device_type__'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Device).where(Device.mac_address.in_([_MAC, _MAC_2, _MAC_3])))
        await session.execute(delete(TrustedMac).where(TrustedMac.mac_address.in_([_MAC, _MAC_2, _MAC_3])))
        await session.execute(delete(AppSettings))
        await session.execute(delete(DeviceTypeProfile).where(DeviceTypeProfile.device_type == _TEST_DEVICE_TYPE))
    await get_engine().dispose()


class TestExists:
    async def test_unknown_mac_returns_false(self):
        repo = DeviceRepository()
        assert await repo.exists(_MAC) is False

    async def test_known_mac_returns_true(self):
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device'))

        repo = DeviceRepository()
        assert await repo.exists(_MAC) is True


class TestHasConnectedBefore:
    async def test_no_row_returns_false(self):
        repo = DeviceRepository()
        assert await repo.has_connected_before(_MAC) is False

    async def test_row_exists_but_never_connected_returns_false(self):
        """The core regression: a devices row alone (e.g. a stale DHCP
        reservation the router mentions but that never actually connected)
        must not count as 'has connected before' — see NewDeviceDetector."""
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', ever_connected=False))

        repo = DeviceRepository()
        assert await repo.exists(_MAC) is True
        assert await repo.has_connected_before(_MAC) is False

    async def test_ever_connected_true_returns_true(self):
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', ever_connected=True))

        repo = DeviceRepository()
        assert await repo.has_connected_before(_MAC) is True


class TestTrustedMacRepository:
    async def test_unknown_mac_is_not_trusted(self):
        repo = TrustedMacRepository()
        assert await repo.is_trusted(_MAC) is False

    async def test_trust_makes_it_trusted(self):
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        assert await repo.is_trusted(_MAC) is True

    async def test_trust_is_idempotent(self):
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        await repo.trust(_MAC)  # must not raise (duplicate PK)
        assert await repo.is_trusted(_MAC) is True

    async def test_untrust_removes_it(self):
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        await repo.untrust(_MAC)
        assert await repo.is_trusted(_MAC) is False

    async def test_untrust_unknown_mac_is_a_no_op(self):
        repo = TrustedMacRepository()
        await repo.untrust(_MAC)  # must not raise
        assert await repo.is_trusted(_MAC) is False

    async def test_survives_devices_row_being_absent(self):
        """The whole point of this table: trust persists even with no devices row."""
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        assert await DeviceRepository().exists(_MAC) is False
        assert await repo.is_trusted(_MAC) is True


class TestTrustMany:
    async def test_trusts_every_mac(self):
        await TrustedMacRepository().trust_many([_MAC, _MAC_2])
        assert await TrustedMacRepository().is_trusted(_MAC) is True
        assert await TrustedMacRepository().is_trusted(_MAC_2) is True

    async def test_empty_list_is_a_no_op(self):
        await TrustedMacRepository().trust_many([])  # must not raise

    async def test_idempotent_with_an_already_trusted_mac(self):
        """trust_many must not choke on a conflict for a MAC that's already
        trusted (e.g. the same device trusted again on a later poll while
        still LEARNING) — see _auto_trust_new_connections_during_learning
        in sentinel/scheduler/jobs.py."""
        await TrustedMacRepository().trust(_MAC)
        await TrustedMacRepository().trust_many([_MAC, _MAC_2])
        assert await TrustedMacRepository().is_trusted(_MAC_2) is True


class TestGetFirstSeen:
    async def test_no_row_returns_none(self):
        assert await DeviceRepository().get_first_seen(_MAC) is None

    async def test_returns_the_devices_row_first_seen(self):
        from datetime import datetime, timezone
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', first_seen=ts))
        assert await DeviceRepository().get_first_seen(_MAC) == ts


class TestIsEmpty:
    """Requires a genuinely empty database to be meaningful — run against an
    isolated test database (e.g. sentinel_test), never a live/shared one,
    since these assert on *global* table emptiness, not a specific MAC."""

    async def test_device_repository_true_with_no_rows(self):
        assert await DeviceRepository().is_empty() is True

    async def test_device_repository_false_once_any_row_exists(self):
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device'))
        assert await DeviceRepository().is_empty() is False

    async def test_trusted_mac_repository_true_with_no_rows(self):
        assert await TrustedMacRepository().is_empty() is True

    async def test_trusted_mac_repository_false_once_any_mac_is_trusted(self):
        await TrustedMacRepository().trust(_MAC)
        assert await TrustedMacRepository().is_empty() is False


async def _seed_device(mac: str, **overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=mac, hostname=f'device-{mac}', **overrides))


class TestListOnline:
    async def test_returns_online_devices_with_a_known_ip(self):
        await _seed_device(_MAC, is_online=True, ip_address='10.100.102.50')

        result = await DeviceRepository().list_online()

        assert result == [(_MAC, '10.100.102.50')]

    async def test_excludes_offline_devices(self):
        await _seed_device(_MAC, is_online=False, ip_address='10.100.102.50')

        assert await DeviceRepository().list_online() == []

    async def test_excludes_online_devices_with_no_ip(self):
        await _seed_device(_MAC, is_online=True, ip_address=None)

        assert await DeviceRepository().list_online() == []

    async def test_multiple_online_devices(self):
        await _seed_device(_MAC, is_online=True, ip_address='10.100.102.50')
        await _seed_device(_MAC_2, is_online=True, ip_address='10.100.102.51')
        await _seed_device(_MAC_3, is_online=False, ip_address='10.100.102.52')

        result = await DeviceRepository().list_online()

        assert set(result) == {(_MAC, '10.100.102.50'), (_MAC_2, '10.100.102.51')}


class TestLink:
    async def test_sets_all_three_columns(self):
        await _seed_device(_MAC)
        await _seed_device(_MAC_2)

        linked = await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_2, reason='test reason')

        assert linked.linked_to_mac == _MAC_2
        assert linked.linked_at is not None
        assert linked.link_reason == 'test reason'

    async def test_unknown_old_mac_returns_none(self):
        await _seed_device(_MAC_2)
        assert await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_2, reason='x') is None

    async def test_idempotent_on_repeat_confirmation(self):
        await _seed_device(_MAC)
        await _seed_device(_MAC_2)

        first = await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_2, reason='first')
        second = await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_2, reason='second')

        assert first.linked_to_mac == second.linked_to_mac == _MAC_2

    async def test_repoints_when_new_mac_is_itself_already_linked(self):
        """A -> B already exists; linking C -> B must resolve onto B's own
        target, not create a dangling C -> B -> (something) chain."""
        await _seed_device(_MAC)      # A
        await _seed_device(_MAC_2)    # B
        await _seed_device(_MAC_3)    # C
        await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_2, reason='A->B')

        linked = await DeviceRepository().link(old_mac=_MAC_3, new_mac=_MAC, reason='C->A, but A is linked to B')

        assert linked.linked_to_mac == _MAC_2

    async def test_repoints_existing_chain_on_supersession(self):
        """A already links to B; B itself gets superseded by C — A must be
        repointed onto C too, so linked_to_mac never requires a multi-hop
        walk for any reader."""
        await _seed_device(_MAC)      # A
        await _seed_device(_MAC_2)    # B
        await _seed_device(_MAC_3)    # C
        await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_2, reason='A->B')

        await DeviceRepository().link(old_mac=_MAC_2, new_mac=_MAC_3, reason='B->C')

        async with get_session() as session:
            a = await session.get(Device, _MAC)
        assert a.linked_to_mac == _MAC_3


class TestUnlink:
    async def test_clears_all_three_columns(self):
        await _seed_device(_MAC)
        await _seed_device(_MAC_2)
        await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_2, reason='x')

        assert await DeviceRepository().unlink(_MAC) is True

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.linked_to_mac is None
        assert device.linked_at is None
        assert device.link_reason is None

    async def test_unknown_mac_returns_false(self):
        assert await DeviceRepository().unlink(_MAC) is False

    async def test_not_currently_linked_returns_false(self):
        await _seed_device(_MAC)
        assert await DeviceRepository().unlink(_MAC) is False


class TestGetLinkedInto:
    async def test_returns_rows_linked_to_this_mac(self):
        await _seed_device(_MAC)
        await _seed_device(_MAC_2)
        await _seed_device(_MAC_3)
        await DeviceRepository().link(old_mac=_MAC, new_mac=_MAC_3, reason='x')
        await DeviceRepository().link(old_mac=_MAC_2, new_mac=_MAC_3, reason='y')

        linked_into = await DeviceRepository().get_linked_into(_MAC_3)

        assert {d.mac_address for d in linked_into} == {_MAC, _MAC_2}

    async def test_empty_when_nothing_is_linked(self):
        await _seed_device(_MAC)
        assert await DeviceRepository().get_linked_into(_MAC) == []


class TestArchiveStale:
    async def test_archives_a_device_past_the_cutoff(self):
        old = datetime.now(timezone.utc) - timedelta(days=100)
        await _seed_device(_MAC, last_seen=old)

        archived_count = await DeviceRepository().archive_stale(timedelta(days=90))

        assert archived_count == 1
        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_archived is True
        assert device.archived_at is not None
        assert '90' in device.archive_reason

    async def test_leaves_a_recently_seen_device_alone(self):
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        await _seed_device(_MAC, last_seen=recent)

        archived_count = await DeviceRepository().archive_stale(timedelta(days=90))

        assert archived_count == 0
        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_archived is False

    async def test_exempts_a_trusted_device(self):
        old = datetime.now(timezone.utc) - timedelta(days=100)
        await _seed_device(_MAC, last_seen=old, is_trusted=True)

        archived_count = await DeviceRepository().archive_stale(timedelta(days=90))

        assert archived_count == 0

    async def test_exempts_a_blocked_device(self):
        old = datetime.now(timezone.utc) - timedelta(days=100)
        await _seed_device(_MAC, last_seen=old, is_blocked=True)

        archived_count = await DeviceRepository().archive_stale(timedelta(days=90))

        assert archived_count == 0

    async def test_exempts_a_quarantined_device(self):
        old = datetime.now(timezone.utc) - timedelta(days=100)
        await _seed_device(_MAC, last_seen=old, is_quarantined=True)

        archived_count = await DeviceRepository().archive_stale(timedelta(days=90))

        assert archived_count == 0

    async def test_exempts_an_already_linked_away_device(self):
        old = datetime.now(timezone.utc) - timedelta(days=100)
        await _seed_device(_MAC_2, last_seen=old)
        await _seed_device(_MAC, last_seen=old, linked_to_mac=_MAC_2, linked_at=old, link_reason='x')

        archived_count = await DeviceRepository().archive_stale(timedelta(days=90))

        # _MAC_2 (the survivor) is a genuine stale candidate and gets archived;
        # _MAC (already linked away) must not be double-counted/touched again.
        assert archived_count == 1
        async with get_session() as session:
            linked_away = await session.get(Device, _MAC)
        assert linked_away.archived_at is None

    async def test_idempotent_on_repeat_sweep(self):
        old = datetime.now(timezone.utc) - timedelta(days=100)
        await _seed_device(_MAC, last_seen=old)

        first = await DeviceRepository().archive_stale(timedelta(days=90))
        second = await DeviceRepository().archive_stale(timedelta(days=90))

        assert first == 1
        assert second == 0


class TestUnarchive:
    async def test_clears_all_three_columns(self):
        old = datetime.now(timezone.utc) - timedelta(days=100)
        await _seed_device(_MAC, last_seen=old)
        await DeviceRepository().archive_stale(timedelta(days=90))

        assert await DeviceRepository().unarchive(_MAC) is True

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_archived is False
        assert device.archived_at is None
        assert device.archive_reason is None

    async def test_unknown_mac_returns_false(self):
        assert await DeviceRepository().unarchive(_MAC) is False

    async def test_not_currently_archived_returns_false(self):
        await _seed_device(_MAC)
        assert await DeviceRepository().unarchive(_MAC) is False


class TestSettingsRepository:
    async def test_falls_back_to_the_env_default_with_no_row(self):
        assert await SettingsRepository().get_ml_learning_period_hours() == settings.ML_LEARNING_PERIOD_HOURS

    async def test_set_then_get_round_trips(self):
        await SettingsRepository().set_ml_learning_period_hours(24)
        assert await SettingsRepository().get_ml_learning_period_hours() == 24

    async def test_set_overwrites_an_existing_row_rather_than_erroring(self):
        repo = SettingsRepository()
        await repo.set_ml_learning_period_hours(24)
        await repo.set_ml_learning_period_hours(48)
        assert await repo.get_ml_learning_period_hours() == 48

    async def test_data_retention_days_falls_back_to_the_env_default(self):
        assert await SettingsRepository().get_data_retention_days() == settings.DATA_RETENTION_DAYS

    async def test_data_retention_days_set_then_get_round_trips(self):
        await SettingsRepository().set_data_retention_days(30)
        assert await SettingsRepository().get_data_retention_days() == 30

    async def test_setting_one_field_does_not_clobber_the_other(self):
        """Both fields live on the same singleton row — a setter for one must
        not reset the other back to its column default."""
        repo = SettingsRepository()
        await repo.set_ml_learning_period_hours(24)
        await repo.set_data_retention_days(30)
        assert await repo.get_ml_learning_period_hours() == 24
        assert await repo.get_data_retention_days() == 30

    async def test_baseline_established_at_defaults_to_none(self):
        assert (await SettingsRepository().get_all())['baseline_established_at'] is None

    async def test_baseline_established_at_set_then_get_round_trips(self):
        from datetime import datetime, timezone
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        repo = SettingsRepository()
        await repo.set_baseline_established_at(ts)
        assert (await repo.get_all())['baseline_established_at'] == ts

    async def test_baseline_established_at_can_be_cleared_back_to_none(self):
        from datetime import datetime, timezone
        repo = SettingsRepository()
        await repo.set_baseline_established_at(datetime(2026, 1, 1, tzinfo=timezone.utc))
        await repo.set_baseline_established_at(None)
        assert (await repo.get_all())['baseline_established_at'] is None

    async def test_get_all_returns_every_field_together(self):
        data = await SettingsRepository().get_all()
        assert set(data.keys()) == {
            'ml_learning_period_hours', 'data_retention_days', 'baseline_established_at',
            'armed_retrain_done', 'sniff_iface', 'router_username', 'ntfy_url', 'smtp_host',
            'smtp_port', 'smtp_from', 'smtp_to', 'smtp_username', 'smtp_use_tls',
            'auto_block_on_threat', 'auto_block_expiry_hours', 'last_digest_sent_at',
            'alert_stale_hours', 'alert_auto_resolve_hours', 'device_archive_after_days',
        }

    async def test_router_username_falls_back_to_the_env_default(self):
        assert await SettingsRepository().get_router_username() == settings.ROUTER_USERNAME

    async def test_router_username_set_then_get_round_trips(self):
        await SettingsRepository().set_router_username('newadmin')
        assert await SettingsRepository().get_router_username() == 'newadmin'

    async def test_smtp_settings_fall_back_to_env_defaults_with_no_row(self):
        smtp = await SettingsRepository().get_smtp_settings()
        assert smtp == {
            'smtp_host': settings.SMTP_HOST,
            'smtp_port': settings.SMTP_PORT,
            'smtp_from': settings.SMTP_FROM,
            'smtp_to': settings.SMTP_TO,
            'smtp_username': settings.SMTP_USERNAME,
            'smtp_use_tls': settings.SMTP_USE_TLS,
        }

    async def test_smtp_settings_set_then_get_round_trips(self):
        repo = SettingsRepository()
        await repo.set_smtp_settings(
            smtp_host='smtp.example.com', smtp_port=465, smtp_from='a@b.com',
            smtp_to='c@d.com', smtp_username='a@b.com', smtp_use_tls=False,
        )
        smtp = await repo.get_smtp_settings()
        assert smtp == {
            'smtp_host': 'smtp.example.com', 'smtp_port': 465, 'smtp_from': 'a@b.com',
            'smtp_to': 'c@d.com', 'smtp_username': 'a@b.com', 'smtp_use_tls': False,
        }

    async def test_smtp_settings_does_not_include_a_password_field(self):
        """smtp_password is deliberately never stored in this table — see
        Settings.SMTP_PASSWORD_FILE."""
        assert 'smtp_password' not in await SettingsRepository().get_smtp_settings()


class TestDeviceTypeProfileRepository:
    """CRUD coverage for the admin-editable device_type_profiles table —
    see tests/test_detection/test_device_profiles.py for the seeded rows
    (Smartphone/NAS/IP Camera/Printer) this migration ships with."""

    async def test_get_profile_for_unknown_type_returns_default_without_a_db_row(self):
        from sentinel.detection.device_profiles import DEFAULT_PROFILE
        assert await DeviceTypeProfileRepository().get_profile(_TEST_DEVICE_TYPE) == DEFAULT_PROFILE

    async def test_upsert_then_get_profile_round_trips(self):
        repo = DeviceTypeProfileRepository()
        await repo.upsert_profile(
            _TEST_DEVICE_TYPE, high_upload_ratio_threshold=4.5, volume_sustained_polls=7, contamination=0.12,
        )
        profile = await repo.get_profile(_TEST_DEVICE_TYPE)
        assert profile == {
            'high_upload_ratio_threshold': 4.5, 'volume_sustained_polls': 7, 'contamination': 0.12,
        }

    async def test_upsert_twice_updates_the_same_row_not_a_duplicate(self):
        repo = DeviceTypeProfileRepository()
        await repo.upsert_profile(
            _TEST_DEVICE_TYPE, high_upload_ratio_threshold=1.0, volume_sustained_polls=1, contamination=0.01,
        )
        await repo.upsert_profile(
            _TEST_DEVICE_TYPE, high_upload_ratio_threshold=2.0, volume_sustained_polls=2, contamination=0.02,
        )
        profile = await repo.get_profile(_TEST_DEVICE_TYPE)
        assert profile['high_upload_ratio_threshold'] == 2.0

        all_profiles = await repo.get_all_profiles()
        matching = [p for p in all_profiles if p.device_type == _TEST_DEVICE_TYPE]
        assert len(matching) == 1

    async def test_delete_profile_reverts_to_default(self):
        from sentinel.detection.device_profiles import DEFAULT_PROFILE
        repo = DeviceTypeProfileRepository()
        await repo.upsert_profile(
            _TEST_DEVICE_TYPE, high_upload_ratio_threshold=9.0, volume_sustained_polls=9, contamination=0.09,
        )
        assert await repo.delete_profile(_TEST_DEVICE_TYPE) is True
        assert await repo.get_profile(_TEST_DEVICE_TYPE) == DEFAULT_PROFILE

    async def test_delete_nonexistent_profile_returns_false(self):
        assert await DeviceTypeProfileRepository().delete_profile(_TEST_DEVICE_TYPE) is False

    async def test_unmatched_type_logs_a_warning_once_not_every_call(self, caplog):
        """Regression: a device_type with no matching profile row silently
        fell back to DEFAULT_PROFILE with zero visibility anywhere —
        confirmed in production, a live device classified 'NAS' missed a
        seeded 'Network Attached Storage' row (exact-string PK lookup, no
        aliasing) and got the generic default instead, invisibly. Logs
        once per distinct type per process, not on every poll."""
        import logging
        unmatched_type = '__unmatched_for_warning_test__'
        with caplog.at_level(logging.WARNING, logger='sentinel.db.repositories'):
            await DeviceTypeProfileRepository().get_profile(unmatched_type)
            await DeviceTypeProfileRepository().get_profile(unmatched_type)
        matching_records = [r for r in caplog.records if unmatched_type in r.getMessage()]
        assert len(matching_records) == 1

    async def test_get_all_profiles_includes_seeded_smartphone_row(self):
        all_profiles = await DeviceTypeProfileRepository().get_all_profiles()
        smartphone = next((p for p in all_profiles if p.device_type == 'Smartphone'), None)
        assert smartphone is not None
        assert smartphone.volume_sustained_polls > 3  # the direct fix — see the migration's docstring
