"""Builders shared by the switch tests."""
from __future__ import annotations

from datetime import datetime, timezone

from sentinel.switches.models import MacEntry, PortCounters, SwitchIdentity, SwitchSnapshot

SELF_MAC = '02:00:00:00:00:01'
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def snap(ports: dict[str, tuple[int, int]], macs: list, *, model: str = 'TEST-1', speed: int = 1000) -> SwitchSnapshot:
    """ports: {'1': (rx_bytes, tx_bytes)}; macs: [(mac, port)] or MacEntry."""
    counters = [PortCounters(port=p, rx_bytes=rx, tx_bytes=tx, link_up=True, speed_mbps=speed) for p, (rx, tx) in ports.items()]
    entries = [m if isinstance(m, MacEntry) else MacEntry(mac=m[0], port=m[1], vlan=1) for m in macs]
    return SwitchSnapshot(
        identity=SwitchIdentity(model=model, firmware='v1', mac=SELF_MAC), ports=counters, macs=entries, taken_at=T0,
    )
