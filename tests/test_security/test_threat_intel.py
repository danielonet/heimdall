import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import ThreatIntelCache
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.security.threat_intel import ThreatIntelService

_FEODO_SAMPLE = (
    '# Firstseen,DstIP,DstPort,c2_status,last_online,malware\n'
    '"2026-01-01 00:00:00","198.51.100.10",443,"online","2026-01-05","Dridex"\n'
    '"2026-01-02 00:00:00","198.51.100.11",8080,"offline","2026-01-03","TrickBot"\n'
)

_TOR_EXIT_SAMPLE = '# tor exit list\n203.0.113.1\n203.0.113.2\n'

_SPAMHAUS_SAMPLE = (
    '; Spamhaus DROP list\n'
    '192.0.2.0/24 ; SBL12345\n'
    '198.51.100.0/24 ; SBL67890\n'
)

_URLHAUS_SAMPLE = (
    '# id,dateadded,url,url_status,...\n'
    '"1","2026-01-01","http://evil.example.com/payload.exe","online"\n'
    '"2","2026-01-02","https://bad.example.net:8080/drop","online"\n'
)


class TestParseFeeds:
    def test_parse_feodo_extracts_ips(self):
        service = ThreatIntelService()
        count = service._parse_feed('feodo', _FEODO_SAMPLE)
        assert count == 2
        assert service._ip_in_blocklist('198.51.100.10') is True
        assert service._ip_in_blocklist('198.51.100.11') is True
        assert service._ip_in_blocklist('10.0.0.1') is False

    def test_parse_tor_exits(self):
        service = ThreatIntelService()
        count = service._parse_feed('tor_exits', _TOR_EXIT_SAMPLE)
        assert count == 2
        assert service._ip_in_blocklist('203.0.113.1') is True

    def test_parse_spamhaus_cidr_membership(self):
        service = ThreatIntelService()
        count = service._parse_feed('spamhaus', _SPAMHAUS_SAMPLE)
        assert count == 2
        assert service._ip_in_blocklist('192.0.2.55') is True   # inside 192.0.2.0/24
        assert service._ip_in_blocklist('192.0.3.1') is False   # outside the block

    def test_parse_urlhaus_extracts_domains(self):
        service = ThreatIntelService()
        count = service._parse_feed('urlhaus', _URLHAUS_SAMPLE)
        assert count == 2
        assert service.is_domain_malicious('evil.example.com') is True
        assert service.is_domain_malicious('bad.example.net') is True
        assert service.is_domain_malicious('safe.example.org') is False

    def test_malformed_lines_are_skipped_not_fatal(self):
        service = ThreatIntelService()
        count = service._parse_feed('spamhaus', 'not a cidr at all\n; comment\n192.0.2.0/24 ; ok\n')
        assert count == 1

    def test_unknown_feed_name_returns_zero(self):
        service = ThreatIntelService()
        assert service._parse_feed('made_up_feed', 'whatever') == 0


class TestIsDomainMalicious:
    def test_case_insensitive(self):
        service = ThreatIntelService()
        service._parse_feed('urlhaus', _URLHAUS_SAMPLE)
        assert service.is_domain_malicious('EVIL.EXAMPLE.COM') is True


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(
            delete(ThreatIntelCache).where(ThreatIntelCache.ip_or_domain == '198.51.100.10')
        )
    await get_engine().dispose()


class TestLookupIpCaching:
    pytestmark = pytest.mark.asyncio

    async def test_lookup_with_no_otx_key_reports_blocklist_only(self):
        service = ThreatIntelService(otx_api_key='')
        service._parse_feed('feodo', _FEODO_SAMPLE)

        result = await service.lookup_ip('198.51.100.10')
        assert result['in_blocklist'] is True
        assert result['otx_pulses'] == 0
        assert result['is_malicious'] is True

    async def test_clean_ip_reports_not_malicious(self):
        service = ThreatIntelService(otx_api_key='')
        result = await service.lookup_ip('198.51.100.10')  # no feeds parsed this time
        assert result['in_blocklist'] is False
        assert result['is_malicious'] is False

    async def test_second_lookup_uses_cache(self):
        service = ThreatIntelService(otx_api_key='')
        service._parse_feed('feodo', _FEODO_SAMPLE)

        first = await service.lookup_ip('198.51.100.10')
        # Wipe the in-memory blocklist — a cache hit shouldn't need it again.
        service._ip_block.clear()
        second = await service.lookup_ip('198.51.100.10')
        assert second == first
