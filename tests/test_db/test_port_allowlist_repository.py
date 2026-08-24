"""Integration tests for PortAllowlistRepository against the real migrated
schema — same per-test engine create/dispose pattern as
tests/test_db/test_alert_repository.py.
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import PortAllowlistEntry
from sentinel.db.repositories import PortAllowlistRepository
from sentinel.db.session import get_engine, get_session, init_db

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_MAC_2 = '11:22:33:44:55:66'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(PortAllowlistEntry).where(PortAllowlistEntry.device_mac.in_([_MAC, _MAC_2])))
    await get_engine().dispose()


class TestAllow:
    async def test_creates_an_entry(self):
        entry = await PortAllowlistRepository().allow(_MAC, 445, 'SMB', note='print server')
        assert entry.device_mac == _MAC
        assert entry.port == 445
        assert entry.service == 'SMB'
        assert entry.note == 'print server'

    async def test_re_allowing_replaces_service_and_note_not_a_duplicate_row(self):
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB', note='first')
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB', note='second')

        entries = await PortAllowlistRepository().list_all()
        matching = [e for e in entries if e.device_mac == _MAC and e.port == 445]
        assert len(matching) == 1
        assert matching[0].note == 'second'

    async def test_same_port_on_different_devices_are_independent_entries(self):
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB')
        await PortAllowlistRepository().allow(_MAC_2, 445, 'SMB')

        assert await PortAllowlistRepository().allowed_ports_for(_MAC) == {445}
        assert await PortAllowlistRepository().allowed_ports_for(_MAC_2) == {445}


class TestDisallow:
    async def test_removes_an_entry(self):
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB')
        removed = await PortAllowlistRepository().disallow(_MAC, 445)
        assert removed is True
        assert await PortAllowlistRepository().allowed_ports_for(_MAC) == set()

    async def test_returns_false_when_nothing_to_remove(self):
        removed = await PortAllowlistRepository().disallow(_MAC, 445)
        assert removed is False

    async def test_removing_one_port_does_not_affect_another(self):
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB')
        await PortAllowlistRepository().allow(_MAC, 23, 'Telnet')
        await PortAllowlistRepository().disallow(_MAC, 445)
        assert await PortAllowlistRepository().allowed_ports_for(_MAC) == {23}


class TestAllowedPortsFor:
    async def test_empty_when_nothing_allowlisted(self):
        assert await PortAllowlistRepository().allowed_ports_for(_MAC) == set()

    async def test_batches_multiple_ports_for_one_device(self):
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB')
        await PortAllowlistRepository().allow(_MAC, 3389, 'RDP')
        assert await PortAllowlistRepository().allowed_ports_for(_MAC) == {445, 3389}


class TestListAll:
    async def test_lists_entries_across_devices(self):
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB')
        await PortAllowlistRepository().allow(_MAC_2, 3389, 'RDP')

        entries = await PortAllowlistRepository().list_all()
        macs = {e.device_mac for e in entries}
        assert _MAC in macs
        assert _MAC_2 in macs
