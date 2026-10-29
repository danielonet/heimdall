"""build_suggestions: the router's SSIDs plus the heard access points, ready to review."""
from types import SimpleNamespace

from sentinel.api.routes.wifi import build_suggestions


def _net(bssid: str, ssid: str, signal: int | None = -50, channel: int = 6):
    return SimpleNamespace(bssid=bssid, ssid=ssid, strongest_signal_dbm=signal, channel=channel, vendor_name='')


ROUTER_MAC = 'AA:BB:CC:00:00:01'


def test_only_networks_with_the_routers_ssids_are_candidates() -> None:
    out = build_suggestions(['Home'], ROUTER_MAC, [_net('aa:bb:cc:00:00:02', 'Home'), _net('11:22:33:44:55:66', 'Neighbour')])
    assert [c['bssid'] for c in out['candidates']] == ['aa:bb:cc:00:00:02']
    assert out['protected_ssids'] == ['Home']


def test_a_matching_manufacturer_prefix_is_flagged_and_sorted_first() -> None:
    out = build_suggestions(['Home'], ROUTER_MAC, [
        _net('de:ad:be:ef:00:01', 'Home', signal=-30),
        _net('aa:bb:cc:00:00:02', 'Home', signal=-60),
    ])
    assert [(c['bssid'], c['matches_router']) for c in out['candidates']] == [
        ('aa:bb:cc:00:00:02', True), ('de:ad:be:ef:00:01', False),
    ]


def test_strongest_signal_first_within_a_group_and_missing_signal_last() -> None:
    out = build_suggestions(['Home'], ROUTER_MAC, [
        _net('aa:bb:cc:00:00:03', 'Home', signal=None),
        _net('aa:bb:cc:00:00:04', 'Home', signal=-70),
        _net('aa:bb:cc:00:00:02', 'Home', signal=-40),
    ])
    assert [c['bssid'] for c in out['candidates']] == ['aa:bb:cc:00:00:02', 'aa:bb:cc:00:00:04', 'aa:bb:cc:00:00:03']


def test_ssids_not_heard_are_reported_and_an_unknown_router_mac_matches_nothing() -> None:
    out = build_suggestions(['Home', 'Home-5G'], '', [_net('aa:bb:cc:00:00:02', 'Home')])
    assert out['not_heard'] == ['Home-5G']
    assert out['candidates'][0]['matches_router'] is False
