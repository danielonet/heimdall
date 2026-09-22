from types import SimpleNamespace

from sentinel.security import wifi_iface

_IW_DEV_OUTPUT = """\
phy#1
\tInterface wlx90de8047f3c5
\t\tifindex 7
\t\ttype managed
phy#0
\tInterface wlp2s0
\t\tifindex 3
\t\ttype managed
"""

_IW_PHY_MONITOR_CAPABLE = """\
Wiphy phy1
\tSupported interface modes:
\t\t * managed
\t\t * AP
\t\t * monitor
\t\t * P2P-client
\tBand 1:
"""

_IW_PHY_NOT_MONITOR_CAPABLE = """\
Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * AP
\tBand 1:
"""


def _run(returncode=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestListMonitorCapableInterfaces:
    def test_only_lists_interfaces_whose_phy_supports_monitor(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            if cmd[:2] == ['iw', 'dev']:
                return _run(stdout=_IW_DEV_OUTPUT)
            if cmd[:3] == ['iw', 'phy', 'phy1']:
                return _run(stdout=_IW_PHY_MONITOR_CAPABLE)
            if cmd[:3] == ['iw', 'phy', 'phy0']:
                return _run(stdout=_IW_PHY_NOT_MONITOR_CAPABLE)
            raise AssertionError(f'unexpected command {cmd}')

        monkeypatch.setattr(wifi_iface.subprocess, 'run', fake_run)

        assert wifi_iface.list_monitor_capable_interfaces() == ['wlx90de8047f3c5']

    def test_empty_when_iw_dev_fails(self, monkeypatch):
        monkeypatch.setattr(wifi_iface.subprocess, 'run', lambda cmd, **kwargs: _run(returncode=1))
        assert wifi_iface.list_monitor_capable_interfaces() == []

    def test_empty_when_iw_is_not_installed(self, monkeypatch):
        def raise_missing(cmd, **kwargs):
            raise FileNotFoundError('iw not found')

        monkeypatch.setattr(wifi_iface.subprocess, 'run', raise_missing)
        assert wifi_iface.list_monitor_capable_interfaces() == []


class TestEnterExitMonitorMode:
    def test_enter_runs_the_three_commands_in_order(self, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return _run(returncode=0)

        monkeypatch.setattr(wifi_iface.subprocess, 'run', fake_run)

        assert wifi_iface.enter_monitor_mode('wlx90de8047f3c5') is True
        assert calls == [
            ['ip', 'link', 'set', 'wlx90de8047f3c5', 'down'],
            ['iw', 'dev', 'wlx90de8047f3c5', 'set', 'type', 'monitor'],
            ['ip', 'link', 'set', 'wlx90de8047f3c5', 'up'],
        ]

    def test_enter_stops_at_the_first_failure(self, monkeypatch):
        """Confirmed live 2026-09-18: exactly this failure mode (down
        succeeding, monitor-mode switch denied for lack of NET_ADMIN) — the
        remaining commands must never run once one step fails."""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return _run(returncode=0 if cmd[-1] == 'down' else 1, stderr='Operation not permitted')

        monkeypatch.setattr(wifi_iface.subprocess, 'run', fake_run)

        assert wifi_iface.enter_monitor_mode('wlx90de8047f3c5') is False
        assert calls == [
            ['ip', 'link', 'set', 'wlx90de8047f3c5', 'down'],
            ['iw', 'dev', 'wlx90de8047f3c5', 'set', 'type', 'monitor'],
        ]

    def test_exit_switches_back_to_managed(self, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return _run(returncode=0)

        monkeypatch.setattr(wifi_iface.subprocess, 'run', fake_run)

        assert wifi_iface.exit_monitor_mode('wlx90de8047f3c5') is True
        assert calls[1] == ['iw', 'dev', 'wlx90de8047f3c5', 'set', 'type', 'managed']

    def test_never_raises_on_subprocess_error(self, monkeypatch):
        def raise_error(cmd, **kwargs):
            raise OSError('no permission')

        monkeypatch.setattr(wifi_iface.subprocess, 'run', raise_error)

        assert wifi_iface.enter_monitor_mode('wlx90de8047f3c5') is False
        assert wifi_iface.exit_monitor_mode('wlx90de8047f3c5') is False


class TestSetChannel:
    def test_runs_the_expected_command(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            wifi_iface.subprocess, 'run', lambda cmd, **kwargs: calls.append(cmd) or _run(returncode=0)
        )

        assert wifi_iface.set_channel('wlx90de8047f3c5', 6) is True
        assert calls == [['iw', 'dev', 'wlx90de8047f3c5', 'set', 'channel', '6']]
