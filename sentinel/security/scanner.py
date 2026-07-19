"""Network scanner — wraps python-nmap for OS fingerprinting, service
detection, and NSE vulnerability scripts. Runs on a nightly APScheduler job
and on-demand from the device detail API endpoint.

python-nmap is a synchronous, blocking library; every call is bridged through
asyncio.to_thread. OS detection (-O) requires root/CAP_NET_RAW — when that's
not available (e.g. this dev environment), scan_device() falls back to a
service-only scan rather than failing outright.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import nmap

logger = logging.getLogger(__name__)

# Ports that have no business being open on an ordinary LAN client — remote
# admin/file-sharing protocols and a couple of well-known backdoor/C2 default
# ports. A device that didn't expose one of these on its last scan and does
# now is treated as a compromise signal by the nightly nmap job, not just a
# routine profile update. Not exhaustive — a curated "clearly wrong on a
# home LAN" list, not a general port-risk taxonomy.
HIGH_RISK_PORTS = {
    21: 'FTP',
    23: 'Telnet',
    135: 'MSRPC',
    139: 'NetBIOS',
    445: 'SMB',
    512: 'rexec',
    513: 'rlogin',
    514: 'rsh',
    1433: 'MSSQL',
    3389: 'RDP',
    5900: 'VNC',
    4444: 'Metasploit default handler',
    31337: 'Back Orifice / "elite" backdoor',
}


@dataclass
class OpenPort:
    port: int
    protocol: str
    service: str
    version: str
    state: str


@dataclass
class ScanResult:
    ip: str
    os: str
    ports: list[OpenPort] = field(default_factory=list)


class NetworkScanner:
    """OS/service detection and vulnerability scanning for a single device."""

    def __init__(self) -> None:
        self._nm = nmap.PortScanner()

    async def scan_device(self, ip: str) -> ScanResult:
        """OS detection + service version scan. Degrades to service-only if
        OS detection isn't permitted (needs root/CAP_NET_RAW)."""
        try:
            return await asyncio.to_thread(self._scan_sync, ip, '-O -sV --version-intensity 5')
        except nmap.PortScannerError as exc:
            if 'requires root privileges' not in str(exc):
                raise
            logger.warning('nmap OS detection needs root — falling back to service-only scan for %s', ip)
            return await asyncio.to_thread(self._scan_sync, ip, '-sV --version-intensity 5')

    def _scan_sync(self, ip: str, arguments: str) -> ScanResult:
        self._nm.scan(ip, arguments=arguments)
        if ip not in self._nm.all_hosts():
            return ScanResult(ip=ip, os='Unknown', ports=[])

        host = self._nm[ip]
        ports = [
            OpenPort(
                port=port,
                protocol=proto,
                service=host[proto][port].get('name', ''),
                version=host[proto][port].get('version', ''),
                state=host[proto][port].get('state', ''),
            )
            for proto in host.all_protocols()
            for port in host[proto]
        ]
        os_match = host.get('osmatch', [{}])
        os_name = os_match[0].get('name', 'Unknown') if os_match else 'Unknown'
        return ScanResult(ip=ip, os=os_name, ports=ports)

    async def vuln_scan(self, ip: str) -> dict:
        """NSE vulnerability scripts. Returns an empty dict on failure rather than raising —
        this runs unattended on a nightly schedule and one bad host shouldn't stop the rest."""
        try:
            return await asyncio.to_thread(self._vuln_scan_sync, ip)
        except Exception as exc:
            logger.warning('nmap vuln scan failed for %s: %s', ip, exc)
            return {}

    def _vuln_scan_sync(self, ip: str) -> dict:
        self._nm.scan(ip, arguments='--script vuln')
        if ip not in self._nm.all_hosts():
            return {}
        return self._nm[ip].get('script', {})
