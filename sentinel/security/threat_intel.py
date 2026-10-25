"""Threat intelligence: downloads/caches open-source feeds, queries OTX, and
persists verdicts to threat_intel_cache so repeated lookups don't refetch.
"""
from __future__ import annotations

import asyncio
import csv
import ipaddress
import logging
import os
import re
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
    # URLhaus is deliberately absent here — see URLHAUS_EXPORT_URL below.
}

# abuse.ch retired anonymous downloads: the old keyless
# https://urlhaus.abuse.ch/downloads/csv_recent/ now answers 410 Gone. The
# replacement is an export with a (free) Auth-Key in the URL path, so the URL
# is built at runtime and must never be logged or shown unredacted — see
# ThreatIntelService._redact. Obtain a key at https://auth.abuse.ch/.
URLHAUS_EXPORT_URL = 'https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv'
# The key is spliced into a URL path, so only accept characters that cannot
# alter the path (no '/', '?', '#', whitespace, ...).
AUTH_KEY_PATTERN = re.compile(r'^[A-Za-z0-9._~-]{8,128}$')
URLHAUS_CACHE_FILE = 'urlhaus.csv'
MAX_IMPORT_BYTES = 25 * 1024 * 1024

CACHE_TTL = timedelta(hours=24)


class ThreatIntelService:
    """Downloads/caches open-source threat feeds and queries AlienVault OTX."""

    def __init__(
        self, otx_api_key: str = '', abusech_auth_key: str = '', cache_dir: str = ''
    ) -> None:
        self._otx = OTXv2(otx_api_key) if otx_api_key else None
        self._abusech_auth_key = abusech_auth_key.strip()
        # Directory (a persisted volume in Docker) holding the last good copy
        # of the URLhaus export. It is a cache, not a substitute for the live
        # feed: a successful refresh always replaces it, and a failed one
        # leaves it serving.
        self._cache_dir = cache_dir
        self._ip_block: set[str] = set()
        self._ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domains: set[str] = set()
        self._feed_status: dict[str, dict] = {
            name: {'refreshed_at': None, 'entry_count': 0, 'error': None, 'source': None}
            for name in self._feed_urls()
        }
        self._load_urlhaus_cache()

    def _feed_urls(self) -> dict[str, str]:
        """Every feed to fetch. URLhaus is included only when an Auth-Key is
        configured; otherwise it is reported (not fetched) in refresh_feeds."""
        urls = dict(FEED_URLS)
        urls['urlhaus'] = (
            URLHAUS_EXPORT_URL.format(key=self._abusech_auth_key) if self._abusech_auth_key else ''
        )
        return urls

    # ── URLhaus: Auth-Key, on-disk cache, manual import ──────────────────────

    def set_abusech_auth_key(self, key: str) -> None:
        """Apply (or clear, with '') the abuse.ch Auth-Key live. The caller has
        already validated it against AUTH_KEY_PATTERN and persisted it."""
        self._abusech_auth_key = key.strip()

    @property
    def has_abusech_auth_key(self) -> bool:
        return bool(self._abusech_auth_key)

    def _cache_path(self) -> str:
        return os.path.join(self._cache_dir, URLHAUS_CACHE_FILE) if self._cache_dir else ''

    def _load_urlhaus_cache(self) -> None:
        """Serve the last saved URLhaus export immediately at startup — and
        keep serving it if the live feed later fails — instead of starting empty."""
        path = self._cache_path()
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                count = self._parse_urlhaus(f.read())
            saved_at = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat()
        except OSError as exc:
            logger.warning('Could not read URLhaus cache %s: %s', path, exc)
            return
        self._feed_status['urlhaus'] = {
            'refreshed_at': saved_at, 'entry_count': count, 'error': None, 'source': 'cache',
        }
        logger.info('Loaded %d URLhaus entries from cache (%s)', count, path)

    def _save_urlhaus_cache(self, text: str) -> None:
        path = self._cache_path()
        if not path:
            return
        try:
            os.makedirs(self._cache_dir, exist_ok=True)
            tmp = f'{path}.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(text)
            os.replace(tmp, path)  # atomic — a crash never leaves a half-written cache
        except OSError as exc:
            logger.warning('Could not write URLhaus cache %s: %s', path, exc)

    def import_urlhaus_csv(self, text: str) -> int:
        """Load a URLhaus CSV the user obtained themselves (the "set up the
        key later" path). Returns the number of entries; raises ValueError if
        the text contains none, so a wrong file never replaces a good cache.
        A later successful live refresh replaces it."""
        probe = ThreatIntelService()
        count = probe._parse_urlhaus(text)
        if count == 0:
            raise ValueError('No URLhaus entries found — expected the CSV export (id,dateadded,url,...)')
        self._parse_urlhaus(text)
        self._save_urlhaus_cache(text)
        self._feed_status['urlhaus'] = {
            'refreshed_at': datetime.now(timezone.utc).isoformat(),
            'entry_count': count, 'error': None, 'source': 'import',
        }
        return count

    def _describe_error(self, name: str, exc: Exception) -> str:
        """Human-readable refresh failure, with the Auth-Key redacted."""
        if name == 'urlhaus' and isinstance(exc, httpx.HTTPStatusError):
            code = exc.response.status_code
            if code in (401, 403):
                return f'abuse.ch rejected the Auth-Key (HTTP {code}) — check it was copied in full, or create a new one.'
            if code == 410:
                return 'abuse.ch answered 410 Gone — the export URL has changed again; please report this.'
        return self._redact(str(exc))

    def _redact(self, message: str) -> str:
        """Strip the Auth-Key (which sits in the URL path) from error text —
        httpx puts the full URL in its exception messages."""
        if self._abusech_auth_key:
            message = message.replace(self._abusech_auth_key, '***')
        return message

    async def refresh_feeds(self) -> None:
        """Download and re-parse every feed. A feed that fails to fetch is skipped, not fatal."""
        async with httpx.AsyncClient(timeout=30) as client:
            for name, url in self._feed_urls().items():
                if not url:
                    continue  # URLhaus without a key: not an error — see feed_status()
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    count = self._parse_feed(name, resp.text)
                    if name == 'urlhaus':
                        self._save_urlhaus_cache(resp.text)
                    self._feed_status[name] = {
                        'refreshed_at': datetime.now(timezone.utc).isoformat(),
                        'entry_count': count,
                        'error': None,
                        'source': 'live',
                    }
                except Exception as exc:
                    message = self._describe_error(name, exc)
                    logger.warning('Failed to refresh threat feed %s: %s', name, message)
                    # Keep whatever this feed already serves (e.g. the cache).
                    self._feed_status[name]['error'] = message

    def feed_status(self) -> dict[str, dict]:
        """Status + last-refresh timestamp of every feed — for GET /api/threats/feeds."""
        status = {name: dict(info) for name, info in self._feed_status.items()}
        if 'urlhaus' in status:
            # Never the key itself — only whether one is set, so the UI can
            # show the "create a key" setup instead of an error.
            status['urlhaus']['key_configured'] = self.has_abusech_auth_key
            status['urlhaus']['needs_key'] = not self.has_abusech_auth_key
        return status

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
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith('#')]
        for fields in csv.reader(lines, skipinitialspace=True):
            if len(fields) < 3:
                continue
            domain = urlparse(fields[2]).hostname
            if domain:
                self._domains.add(domain.lower())
                count += 1
        return count
