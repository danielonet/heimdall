"""Catalog of switch models Heimdall can (or will) read.

Mirrors sentinel/adapter/catalog.py: it drives the Equipment tab's switch dropdown and form, so the frontend needs no
per-switch code. An entry being listed does not mean it works: `implemented` is true only once the switch's fixture
suite passes, and `tested` only after a run on real hardware (CLAUDE.md: never describe a planned feature as shipped).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from sentinel.adapter.catalog import SimulatorKind


@dataclass(frozen=True)
class SwitchSpec:
    """One selectable switch model."""

    id: str
    label: str
    family: str
    protocol: str
    driver: str                      # key in registry.DRIVERS
    definition: str = ''             # the definitions/<id>.json a web driver uses
    simulator: SimulatorKind = SimulatorKind.FIXTURES
    implemented: bool = False
    tested: bool = False             # True only after a run on real hardware
    fields: tuple[str, ...] = ('host', 'username', 'password')
    default_username: str = ''
    default_port: int | None = 80
    field_labels: dict[str, str] = field(default_factory=dict)
    notes: str = ''

    def to_dict(self) -> dict:
        """JSON form for GET /api/switches/catalog."""
        data = asdict(self)
        data['simulator'] = self.simulator.value
        data['fields'] = list(self.fields)
        data['field_labels'] = dict(self.field_labels)
        return data


CATALOG: tuple[SwitchSpec, ...] = (
    SwitchSpec(
        id='hc-swtgw218as', label='HC SW-TGW218AS (web UI)', family='HC web-managed',
        protocol='HTTP form login (MD5 cookie), HTML pages', driver='web-definition', definition='hc-swtgw218as',
        implemented=True, tested=True, default_username='admin',
        notes='9 ports. Reads the port statistics and MAC address table pages. The login cookie is a plain MD5 of '
              'the user name and password sent over HTTP, so anyone on the LAN who sees one request can reuse it.',
    ),
)

_BY_ID: dict[str, SwitchSpec] = {spec.id: spec for spec in CATALOG}


def get_spec(spec_id: str) -> SwitchSpec | None:
    """Return the catalog entry for `spec_id`, or None if unknown."""
    return _BY_ID.get(spec_id)
