"""Catalog of router families Heimdall can (or will) talk to.

Drives the Equipment tab's router dropdown and credential popup, so the
frontend needs no per-router code: each entry says which login fields it
needs and where its tests run. See docs/router-and-switch-expansion-plan.md
(Part 1) for the protocol research behind each row.

An entry being listed does NOT mean an adapter exists — `implemented` says
whether `sentinel/adapter/factory.py` can actually build one. Credentials for
unimplemented routers can still be saved now so the adapter lands onto a
ready foundation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class SimulatorKind(str, Enum):
    """How an adapter is exercised without the physical router."""

    WIREMOCK = 'wiremock'   # HTTP stubs under wiremock/<id>/
    DOCKER = 'docker'       # the real router OS in a container, tests/simulators/<id>/
    NONE = 'none'


@dataclass(frozen=True)
class RouterSpec:
    """One selectable router family."""

    id: str
    label: str
    family: str
    protocol: str
    simulator: SimulatorKind
    implemented: bool = False
    # Login fields the credentials popup shows. 'password' is always secret.
    fields: tuple[str, ...] = ('host', 'username', 'password')
    default_username: str = ''
    default_port: int | None = None
    # Where the credentials live: the original settings columns/secret files
    # ('settings', Sagemcom + MiWiFi only) or router_profiles + the
    # per-router secret file ('profile').
    credential_store: str = 'profile'

    def to_dict(self) -> dict:
        data = asdict(self)
        data['simulator'] = self.simulator.value
        data['fields'] = list(self.fields)
        return data


CATALOG: tuple[RouterSpec, ...] = (
    RouterSpec(
        id='sagemcom-xmo', label='Sagemcom F@st (XMO)', family='Sagemcom',
        protocol='XMO JSON over HTTP', simulator=SimulatorKind.WIREMOCK, implemented=True,
        fields=('username', 'password'), default_username='home', credential_store='settings',
    ),
    RouterSpec(
        id='miwifi-stok', label='Xiaomi / Redmi (MiWiFi)', family='Xiaomi',
        protocol='HTTP stok token', simulator=SimulatorKind.WIREMOCK, implemented=True,
        fields=('host', 'password'), credential_store='settings',
    ),
    RouterSpec(
        id='openwrt-ubus', label='OpenWrt (ubus)', family='OpenWrt',
        protocol='JSON-RPC 2.0 /ubus', simulator=SimulatorKind.DOCKER,
        default_username='root', default_port=80,
    ),
    RouterSpec(
        id='mikrotik-rest', label='MikroTik RouterOS 7 (REST)', family='MikroTik',
        protocol='HTTPS REST, Basic auth', simulator=SimulatorKind.DOCKER,
        default_username='admin', default_port=443,
    ),
    RouterSpec(
        id='unifi-network', label='Ubiquiti UniFi Network', family='Ubiquiti',
        protocol='HTTPS REST, cookie session', simulator=SimulatorKind.WIREMOCK, default_port=443,
    ),
    RouterSpec(
        id='opnsense-rest', label='OPNsense', family='OPNsense',
        protocol='HTTPS REST, API key + secret', simulator=SimulatorKind.WIREMOCK, default_port=443,
    ),
    RouterSpec(
        id='pfsense-rest', label='pfSense (REST API package)', family='pfSense',
        protocol='HTTPS REST, API key', simulator=SimulatorKind.WIREMOCK, default_port=443,
    ),
    RouterSpec(
        id='fritzbox-tr064', label='AVM FRITZ!Box (TR-064)', family='AVM',
        protocol='TR-064 SOAP', simulator=SimulatorKind.WIREMOCK, default_port=49000,
    ),
    RouterSpec(
        id='asus-http', label='ASUS / Asuswrt-Merlin', family='ASUS',
        protocol='HTTP login.cgi + appGet.cgi', simulator=SimulatorKind.WIREMOCK,
        default_username='admin', default_port=80,
    ),
    RouterSpec(
        id='tplink-router', label='TP-Link Archer / Deco', family='TP-Link',
        protocol='Encrypted HTTP login', simulator=SimulatorKind.WIREMOCK,
        default_username='admin', default_port=80,
    ),
    RouterSpec(
        id='netgear-soap', label='Netgear Nighthawk / Orbi', family='Netgear',
        protocol='SOAP /soap/server_sa', simulator=SimulatorKind.WIREMOCK,
        default_username='admin', default_port=80,
    ),
    RouterSpec(
        id='keenetic-rci', label='Keenetic (RCI)', family='Keenetic',
        protocol='REST RCI, challenge-response', simulator=SimulatorKind.WIREMOCK,
        default_username='admin', default_port=80,
    ),
)

_BY_ID: dict[str, RouterSpec] = {spec.id: spec for spec in CATALOG}


def get_spec(router_id: str) -> RouterSpec | None:
    """Return the catalog entry for `router_id`, or None if unknown."""
    return _BY_ID.get(router_id)
