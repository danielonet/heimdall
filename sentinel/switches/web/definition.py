"""The schema of a switch definition, and the loader.

A definition is a JSON file under sentinel/switches/definitions/ that says how to log in to one family of
web-managed switches and where its port counters and MAC table are. It is data, never code: the schema
rejects unknown keys, URLs must be paths on the switch itself, and values go through the whitelist
evaluator in template.py. There are no loops or conditions: pagination is a declared capability the driver
implements, and anything a definition cannot express is a code driver instead.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, TypeAdapter, ValidationError, field_validator, model_validator
from pydantic.dataclasses import dataclass

from sentinel.switches.web import template

DEFINITIONS_DIR = Path(__file__).resolve().parent.parent / 'definitions'
TEMPLATE_VARIABLES = {'username', 'password', 'host', 'base_url'}
_STRICT = ConfigDict(extra='forbid')
_ID = re.compile(r'^[a-z0-9][a-z0-9-]{0,39}$')


class DefinitionError(ValueError):
    """A definition file that does not validate."""


def _check_path(value: str) -> str:
    if not value.startswith('/') or value.startswith('//') or '://' in value:
        raise ValueError(f'{value!r} must be a path on the switch (start with a single "/")')
    return value


def _check_regex(value: str) -> str:
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError(f'{value!r} is not a valid regular expression: {exc}') from exc
    return value


@dataclass(config=_STRICT)
class Match:
    """How "detect my switch" recognises this family from its front page."""

    title: str = ''


@dataclass(config=_STRICT)
class AuthSpec:
    """A form login. Values are templates ("${md5(username + password)}"); `cookies` are set client-side."""

    type: Literal['form']
    login_url: str
    fields: dict[str, str]
    verify_url: str
    logged_out_marker: str
    cookies: dict[str, str] = Field(default_factory=dict)

    _paths = field_validator('login_url', 'verify_url')(_check_path)
    _marker = field_validator('logged_out_marker')(_check_regex)


@dataclass(config=_STRICT)
class Pagination:
    """A table spread over pages that the switch pages through with POSTed commands.

    `first` and `next` are the form fields to POST. The driver reads the page count with `total_pages`
    (a regex with one group), walks at most `max_pages`, and with `restore` puts the switch's own view back
    on the first page afterwards so it does not disturb someone browsing the switch at the same time.
    """

    url: str
    first: dict[str, str]
    next: dict[str, str]
    total_pages: str
    max_pages: int = Field(default=20, ge=1, le=200)
    restore: bool = True

    _path = field_validator('url')(_check_path)
    _total = field_validator('total_pages')(_check_regex)


@dataclass(config=_STRICT)
class PageSpec:
    """One page of the switch, fetched by GET (or by `paginate`)."""

    url: str
    paginate: Pagination | None = None

    _path = field_validator('url')(_check_path)


@dataclass(config=_STRICT)
class TableSpec:
    """Find a table by header text and map its columns by header text (never by position)."""

    page: str
    header_match: list[str]
    columns: dict[str, str]

    @field_validator('header_match')
    @classmethod
    def _headers(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError('header_match needs at least one pattern')
        for pattern in value:
            _check_regex(pattern)
        return value

    @field_validator('columns')
    @classmethod
    def _columns(cls, value: dict[str, str]) -> dict[str, str]:
        for pattern in value.values():
            _check_regex(pattern)
        return value


@dataclass(config=_STRICT)
class SpeedsSpec:
    """Link speeds from a second table (a different page than the counters)."""

    table: TableSpec


@dataclass(config=_STRICT)
class IdentitySpec:
    """Model, firmware and the switch's own MAC, read from "<th>label</th><td>value</td>" pairs."""

    page: str
    labels: dict[str, str]


@dataclass(config=_STRICT)
class PortsSpec:
    """The port counters table.

    number_format: `plain` or `hi_lo` ("<high>-<low>", two 32-bit words). perspective: `port` when the
    page's Rx is what the switch received on the port; `device` when the firmware labels it from the
    attached device's side (the driver swaps, so snapshots are always port-perspective).
    """

    table: TableSpec
    port_id: str = r'^Port\s*(\S+)$'
    number_format: Literal['plain', 'hi_lo'] = 'plain'
    counter_bits: Literal[32, 64] = 64
    perspective: Literal['port', 'device'] = 'port'
    link_up_text: str | None = None
    speeds: SpeedsSpec | None = None

    _port_id = field_validator('port_id')(_check_regex)

    @model_validator(mode='after')
    def _columns_present(self) -> 'PortsSpec':
        missing = {'port', 'rx_bytes', 'tx_bytes'} - set(self.table.columns)
        if missing:
            raise ValueError(f'ports.table.columns is missing {sorted(missing)}')
        return self


@dataclass(config=_STRICT)
class MacsSpec:
    """The MAC address table."""

    table: TableSpec
    port_id: str = r'^(\S+)$'
    dynamic_text: str = 'dynamic'

    _port_id = field_validator('port_id')(_check_regex)

    @model_validator(mode='after')
    def _columns_present(self) -> 'MacsSpec':
        missing = {'mac', 'port'} - set(self.table.columns)
        if missing:
            raise ValueError(f'macs.table.columns is missing {sorted(missing)}')
        return self


@dataclass(config=_STRICT)
class Definition:
    """A whole switch definition."""

    version: Literal[1]
    id: str
    auth: AuthSpec
    pages: dict[str, PageSpec]
    identity: IdentitySpec
    ports: PortsSpec
    macs: MacsSpec
    match: Match = Field(default_factory=Match)
    request_headers: dict[str, str] = Field(default_factory=dict)

    @field_validator('id')
    @classmethod
    def _id_shape(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError('id must be lower-case letters, digits and "-"')
        return value

    @model_validator(mode='after')
    def _cross_checks(self) -> 'Definition':
        for name in (self.identity.page, self.ports.table.page, self.macs.table.page,
                     *( [self.ports.speeds.table.page] if self.ports.speeds else [] )):
            if name not in self.pages:
                raise ValueError(f'unknown page {name!r} (declared pages: {sorted(self.pages)})')
        for text in (*self.auth.fields.values(), *self.auth.cookies.values(), *self.request_headers.values()):
            template.check(text, TEMPLATE_VARIABLES)
        return self


_ADAPTER = TypeAdapter(Definition)


def parse_definition(raw: dict) -> Definition:
    """Validate a definition dict. Raises DefinitionError with every problem listed."""
    try:
        return _ADAPTER.validate_python(raw)
    except (ValidationError, template.TemplateError) as exc:
        raise DefinitionError(str(exc)) from exc


@lru_cache(maxsize=None)
def load_definition(definition_id: str) -> Definition:
    """Load and validate sentinel/switches/definitions/<definition_id>.json."""
    if not _ID.match(definition_id):
        raise DefinitionError(f'bad definition id {definition_id!r}')
    path = DEFINITIONS_DIR / f'{definition_id}.json'
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise DefinitionError(f'cannot read {path.name}: {exc}') from exc
    definition = parse_definition(raw)
    if definition.id != definition_id:
        raise DefinitionError(f'{path.name} declares id {definition.id!r}')
    return definition
