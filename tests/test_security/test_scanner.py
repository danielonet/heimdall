import os

import nmap
import pytest

from sentinel.security.scanner import NetworkScanner, OpenPort, ScanResult


class _FakeHost(dict):
    """Mimics nmap.PortScanner()[ip]'s dict-plus-methods interface."""

    def __init__(self, protocols: dict, osmatch: list):
        super().__init__(protocols)
        self._osmatch = osmatch

    def all_protocols(self):
        return list(self.keys())

    def get(self, key, default=None):
        if key == 'osmatch':
            return self._osmatch
        return super().get(key, default)


class _FakePortScanner:
    """Stand-in for nmap.PortScanner, used to test _scan_sync's parsing
    without depending on nmap actually being installed/root privileges."""

    def __init__(self, host_data: dict | None = None) -> None:
        self._host_data = host_data or {}
        self.scanned_ip = None
        self.scanned_arguments = None

    def scan(self, ip, arguments):
        self.scanned_ip = ip
        self.scanned_arguments = arguments

    def all_hosts(self):
        return list(self._host_data.keys())

    def __getitem__(self, ip):
        return self._host_data[ip]


class TestScanSyncParsing:
    def test_parses_ports_and_os(self):
        scanner = NetworkScanner()
        scanner._nm = _FakePortScanner({
            '10.0.0.5': _FakeHost(
                protocols={'tcp': {80: {'name': 'http', 'version': '1.0', 'state': 'open'}}},
                osmatch=[{'name': 'Linux 5.x'}],
            )
        })

        result = scanner._scan_sync('10.0.0.5', '-O -sV')
        assert result.os == 'Linux 5.x'
        assert result.ports == [OpenPort(port=80, protocol='tcp', service='http', version='1.0', state='open')]

    def test_host_not_found_returns_unknown(self):
        scanner = NetworkScanner()
        scanner._nm = _FakePortScanner({})
        result = scanner._scan_sync('10.0.0.9', '-sV')
        assert result == ScanResult(ip='10.0.0.9', os='Unknown', ports=[])

    def test_no_osmatch_returns_unknown(self):
        scanner = NetworkScanner()
        scanner._nm = _FakePortScanner({'10.0.0.5': _FakeHost(protocols={}, osmatch=[])})
        result = scanner._scan_sync('10.0.0.5', '-sV')
        assert result.os == 'Unknown'


class TestScanDeviceFallback:
    pytestmark = pytest.mark.asyncio

    async def test_falls_back_when_os_detection_needs_root(self, monkeypatch):
        scanner = NetworkScanner()
        calls = []

        def fake_scan_sync(ip, arguments):
            calls.append(arguments)
            if '-O' in arguments:
                raise nmap.PortScannerError('TCP/IP fingerprinting (for OS scan) requires root privileges.')
            return ScanResult(ip=ip, os='Unknown', ports=[])

        monkeypatch.setattr(scanner, '_scan_sync', fake_scan_sync)

        result = await scanner.scan_device('10.0.0.5')
        assert len(calls) == 2
        assert '-O' in calls[0]
        assert '-O' not in calls[1]
        assert result.os == 'Unknown'

    async def test_reraises_unrelated_scanner_errors(self, monkeypatch):
        scanner = NetworkScanner()

        def fake_scan_sync(ip, arguments):
            raise nmap.PortScannerError('some other nmap failure')

        monkeypatch.setattr(scanner, '_scan_sync', fake_scan_sync)

        with pytest.raises(nmap.PortScannerError):
            await scanner.scan_device('10.0.0.5')


class TestVulnScan:
    pytestmark = pytest.mark.asyncio

    async def test_returns_empty_dict_on_failure(self, monkeypatch):
        scanner = NetworkScanner()

        def fake_vuln_scan_sync(ip):
            raise RuntimeError('boom')

        monkeypatch.setattr(scanner, '_vuln_scan_sync', fake_vuln_scan_sync)
        assert await scanner.vuln_scan('10.0.0.5') == {}


@pytest.mark.skipif(os.geteuid() == 0, reason='fallback behaviour only observable when not root')
class TestRealScanAgainstLocalhost:
    pytestmark = pytest.mark.asyncio

    async def test_scan_device_against_localhost_does_not_raise(self):
        scanner = NetworkScanner()
        result = await scanner.scan_device('127.0.0.1')
        assert isinstance(result, ScanResult)
        assert result.ip == '127.0.0.1'
