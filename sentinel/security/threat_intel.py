"""Threat intelligence: downloads/caches open-source feeds, queries OTX, and
persists verdicts to threat_intel_cache so repeated lookups don't refetch.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from OTXv2 import OTXv2

from sentinel.db.models import ThreatIntelCache
from sentinel.db.session import get_session

logger = logging.getLogger(__name__)

FEED_URLS = {
    'feodo':     'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
    'tor_exits': 'https://check.torproject.org/torbulkexitlist',
    'spamhaus':  'https://www.spamhaus.org/drop/drop.txt',
    # /downloads/csv/ (the full dump) is a zip file; csv_recent is plain text.
    'urlhaus':   'https://urlhaus.abuse.ch/downloads/csv_recent/',
}

CACHE_TTL = timedelta(hours=24)


class ThreatIntelService:
    """Downloads/caches open-source threat feeds and queries AlienVault OTX."""

    def __init__(self, otx_api_key: str = '') -> None:
        self._otx = OTXv2(otx_api_key) if otx_api_key else None
        self._ip_block: set[str] = set()
        self._ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domains: set[str] = set()
        self._feed_status: dict[str, dict] = {
            name: {'refreshed_at': None, 'entry_count': 0, 'error': None} for name in FEED_URLS
        }

    async def refresh_feeds(self) -> None:
        """Download and re-parse every feed. A feed that fails to fetch is skipped, not fatal."""
        async with httpx.AsyncClient(timeout=30) as client:
            for name, url in FEED_URLS.items():
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    count = self._parse_feed(name, resp.text)
                    self._feed_status[name] = {
                        'refreshed_at': datetime.now(timezone.utc).isoformat(),
                        'entry_count': count,
                        'error': None,
                    }
                except Exception as exc:
                    logger.warning('Failed to refresh threat feed %s: %s', name, exc)
                    self._feed_status[name]['error'] = str(exc)

    def feed_status(self) -> dict[str, dict]:
        """Status + last-refresh timestamp of every feed — for GET /api/threats/feeds."""
        return dict(self._feed_status)

    async def lookup_ip(self, ip: str) -> dict:
        """On-demand IP reputation check against cached feeds + OTX, with DB caching."""
        cached = await self._get_cached(ip)
        if cached is not None:
            return cached

        in_feed = self._ip_in_blocklist(ip)
        otx_pulses = await self._otx_pulse_count(ip)
        is_malicious = in_feed or otx_pulses > 0

        await self._cache_result(
            ip,
            is_malicious=is_malicious,
            threat_type='blocklist' if in_feed else ('otx_pulse' if otx_pulses else None),
            source_feed='blocklist' if in_feed else 'otx',
            score=otx_pulses,
        )
        return {'ip': ip, 'in_blocklist': in_feed, 'otx_pulses': otx_pulses, 'is_malicious': is_malicious}

    def is_domain_malicious(self, domain: str) -> bool:
        return domain.lower() in self._domains

    def _ip_in_blocklist(self, ip: str) -> bool:
        if ip in self._ip_block:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(ip_obj in net for net in self._ip_networks)

    async def _otx_pulse_count(self, ip: str) -> int:
        if self._otx is None:
            return 0
        try:
            result = await asyncio.to_thread(self._otx.get_indicator_details_full, 'IPv4', ip)
            return len(result.get('general', {}).get('pulse_info', {}).get('pulses', []))
        except Exception as exc:
            logger.debug('OTX lookup failed for %s: %s', ip, exc)
            return 0

    async def _get_cached(self, key: str) -> Optional[dict]:
        async with get_session() as session:
            entry = await session.get(ThreatIntelCache, key)
        if entry is None:
            return None
        if entry.expires_at and entry.expires_at < datetime.now(timezone.utc):
            return None
        return {
            'ip': key,
            'in_blocklist': entry.threat_type == 'blocklist',
            'otx_pulses': entry.score or 0,
            'is_malicious': bool(entry.is_malicious),
        }

    async def _cache_result(
        self, key: str, *, is_malicious: bool, threat_type: Optional[str], source_feed: str, score: int
    ) -> None:
        now = datetime.now(timezone.utc)
        async with get_session() as session:
            entry = await session.get(ThreatIntelCache, key)
            if entry is None:
                entry = ThreatIntelCache(ip_or_domain=key)
                session.add(entry)
            entry.is_malicious = is_malicious
            entry.threat_type = threat_type
            entry.source_feed = source_feed
            entry.score = score
            entry.cached_at = now
            entry.expires_at = now + CACHE_TTL

    def _parse_feed(self, name: str, text: str) -> int:
        parser = {
            'feodo': self._parse_feodo,
            'tor_exits': self._parse_plain_ip_list,
            'spamhaus': self._parse_spamhaus,
            'urlhaus': self._parse_urlhaus,
        }.get(name)
        return parser(text) if parser else 0

    def _parse_feodo(self, text: str) -> int:
        """CSV: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware — comments
        start with #, and every field is quoted (e.g. "198.51.100.10")."""
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = [f.strip().strip('"') for f in line.split(',')]
            if len(fields) >= 2:
                self._ip_block.add(fields[1])
                count += 1
        return count

    def _parse_plain_ip_list(self, text: str) -> int:
        """One IP per line (Tor bulk exit list) — comments start with #."""
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            self._ip_block.add(line)
            count += 1
        return count

    def _parse_spamhaus(self, text: str) -> int:
        """DROP list: '<CIDR> ; <SBL ref>' per line — comments start with ;."""
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            cidr = line.split(';')[0].strip()
            try:
                self._ip_networks.append(ipaddress.ip_network(cidr, strict=False))
                count += 1
            except ValueError:
                continue
        return count

    def _parse_urlhaus(self, text: str) -> int:
        """CSV: id,dateadded,url,url_status,... — comments start with #. Extracts the hostname."""
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = [f.strip('"') for f in line.split(',')]
            if len(fields) < 3:
                continue
            domain = urlparse(fields[2]).hostname
            if domain:
                self._domains.add(domain.lower())
                count += 1
        return count
