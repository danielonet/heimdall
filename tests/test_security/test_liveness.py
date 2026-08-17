"""Unit tests for ArpLivenessProbe — mocks scapy's srp() so these run
without a real network/CAP_NET_RAW, same reasoning as test_scanner.py
stubbing out nmap.PortScanner.
"""
import pytest

from sentinel.security.liveness import ArpLivenessProbe, LivenessProbeError

pytestmark = pytest.mark.asyncio


class TestIsReachable:
    async def test_answered_packet_returns_true(self, monkeypatch):
        monkeypatch.setattr('sentinel.security.liveness.srp', lambda *a, **k: (['some-reply'], []))
        probe = ArpLivenessProbe(iface='eth0')

        assert await probe.is_reachable('10.0.0.5') is True

    async def test_no_reply_after_retries_returns_false(self, monkeypatch):
        monkeypatch.setattr('sentinel.security.liveness.srp', lambda *a, **k: ([], ['unanswered']))
        probe = ArpLivenessProbe(iface='eth0', retries=2)

        assert await probe.is_reachable('10.0.0.5') is False

    async def test_stops_probing_after_the_first_reply(self, monkeypatch):
        calls = []

        def _fake_srp(*args, **kwargs):
            calls.append(1)
            return (['reply'], [])

        monkeypatch.setattr('sentinel.security.liveness.srp', _fake_srp)
        probe = ArpLivenessProbe(iface='eth0', retries=5)

        await probe.is_reachable('10.0.0.5')

        assert len(calls) == 1

    async def test_retries_up_to_the_configured_count_when_never_answered(self, monkeypatch):
        calls = []

        def _fake_srp(*args, **kwargs):
            calls.append(1)
            return ([], ['unanswered'])

        monkeypatch.setattr('sentinel.security.liveness.srp', _fake_srp)
        probe = ArpLivenessProbe(iface='eth0', retries=3)

        await probe.is_reachable('10.0.0.5')

        assert len(calls) == 3

    async def test_permission_error_raises_liveness_probe_error_not_false(self, monkeypatch):
        def _raise(*args, **kwargs):
            raise PermissionError('Operation not permitted')

        monkeypatch.setattr('sentinel.security.liveness.srp', _raise)
        probe = ArpLivenessProbe(iface='eth0')

        with pytest.raises(LivenessProbeError):
            await probe.is_reachable('10.0.0.5')

    async def test_os_error_raises_liveness_probe_error_not_false(self, monkeypatch):
        def _raise(*args, **kwargs):
            raise OSError('No such device')

        monkeypatch.setattr('sentinel.security.liveness.srp', _raise)
        probe = ArpLivenessProbe(iface='does-not-exist')

        with pytest.raises(LivenessProbeError):
            await probe.is_reachable('10.0.0.5')

    async def test_blank_ip_raises_liveness_probe_error(self):
        probe = ArpLivenessProbe(iface='eth0')

        with pytest.raises(LivenessProbeError):
            await probe.is_reachable('')

    async def test_iface_and_timeout_are_passed_through_to_srp(self, monkeypatch):
        captured = {}

        def _fake_srp(*args, **kwargs):
            captured.update(kwargs)
            return (['reply'], [])

        monkeypatch.setattr('sentinel.security.liveness.srp', _fake_srp)
        probe = ArpLivenessProbe(iface='wlan0', timeout_s=0.5)

        await probe.is_reachable('10.0.0.5')

        assert captured['iface'] == 'wlan0'
        assert captured['timeout'] == 0.5
