"""Driver registry: maps a catalog entry's `driver` to the code that builds a SwitchSource for it.

Adding a switch that an existing driver can already read needs no change here: add a definition file and a
catalog entry. Adding a new protocol (SNMP, a vendor REST API) means one SwitchSource class and one
register_driver() call.
"""
from __future__ import annotations

from collections.abc import Callable

import httpx

from sentinel.switches.catalog import SwitchSpec
from sentinel.switches.source import SwitchSource

DriverFactory = Callable[..., SwitchSource]

DRIVERS: dict[str, DriverFactory] = {}


def register_driver(name: str) -> Callable[[DriverFactory], DriverFactory]:
    """Decorator: register a factory(spec, host, username, password, *, transport=None) -> SwitchSource."""
    def decorate(factory: DriverFactory) -> DriverFactory:
        """Record the factory under `name` and return it unchanged."""
        DRIVERS[name] = factory
        return factory
    return decorate


@register_driver('web-definition')
def _web_definition(
    spec: SwitchSpec, host: str, username: str, password: str, *, transport: httpx.AsyncBaseTransport | None = None,
) -> SwitchSource:
    from sentinel.switches.web.definition import load_definition
    from sentinel.switches.web.source import WebDefinitionSource
    return WebDefinitionSource(load_definition(spec.definition), host, username, password, transport=transport)


def build_source(
    spec: SwitchSpec, host: str, username: str, password: str, *, transport: httpx.AsyncBaseTransport | None = None,
) -> SwitchSource:
    """Build the driver for `spec`. Raises ValueError for a catalog entry whose driver is not registered."""
    factory = DRIVERS.get(spec.driver)
    if factory is None:
        raise ValueError(f'switch {spec.id!r} names driver {spec.driver!r}, which is not registered')
    return factory(spec, host, username, password, transport=transport)
