"""Turn fetched pages into a SwitchSnapshot, following a definition. Pure: no I/O.

A page that no longer matches the definition raises SwitchParseError (a "layout changed" message that names
what was missing). It never returns zeros: a counter that is not a number is an error, not 0.
"""
from __future__ import annotations

import re
from datetime import datetime

from sentinel.net_common import norm_mac
from sentinel.switches.models import MacEntry, PortCounters, SwitchIdentity, SwitchSnapshot
from sentinel.switches.source import SwitchParseError
from sentinel.switches.web.definition import Definition, TableSpec
from sentinel.switches.web.extract.html_table import (
    Table, column_index, find_table, labelled_values, parse_tables,
)
from sentinel.switches.web.extract.values import parse_number, parse_speed_mbps, port_id


def needed_pages(definition: Definition) -> list[str]:
    """Names of the pages a poll must fetch, each once, in a stable order."""
    names = [definition.identity.page, definition.ports.table.page]
    if definition.ports.speeds:
        names.append(definition.ports.speeds.table.page)
    names.append(definition.macs.table.page)
    return list(dict.fromkeys(names))


def snapshot_from_pages(definition: Definition, pages: dict[str, list[str]], taken_at: datetime) -> SwitchSnapshot:
    """Build the snapshot from page bodies keyed by page name (a paginated page has several bodies)."""
    warnings: list[str] = []
    identity = _identity(definition, pages)
    ports = _ports(definition, pages)
    macs = _macs(definition, pages, warnings)
    if not ports:
        raise SwitchParseError('the port table has no rows: the switch layout may have changed')
    if not identity.mac:
        warnings.append("the switch's own MAC address was not found; it may be counted as a device on its port")
    return SwitchSnapshot(identity=identity, ports=ports, macs=macs, taken_at=taken_at, warnings=warnings)


def _tables(pages: dict[str, list[str]], page: str) -> list[Table]:
    return [table for body in pages.get(page, []) for table in parse_tables(body)]


def _table(pages: dict[str, list[str]], spec: TableSpec, what: str) -> tuple[list[Table], list[str]]:
    """Every matching table across the page's bodies, and the header row of the first one."""
    found = [t for body in pages.get(spec.page, []) if (t := find_table(parse_tables(body), spec.header_match))]
    if not found:
        raise SwitchParseError(f'the {what} table was not found on page {spec.page!r}: the switch layout may have changed')
    return found, found[0].headers()


def _columns(headers: list[str], spec: TableSpec, required: set[str], what: str) -> dict[str, int | None]:
    indexes = {name: column_index(headers, pattern) for name, pattern in spec.columns.items()}
    missing = sorted(name for name in required if indexes.get(name) is None)
    if missing:
        raise SwitchParseError(f'the {what} table has no column for {missing}: the switch layout may have changed')
    return indexes


def _cell(row: list[str], index: int | None) -> str:
    return row[index] if index is not None and index < len(row) else ''


def _identity(definition: Definition, pages: dict[str, list[str]]) -> SwitchIdentity:
    values = labelled_values(_tables(pages, definition.identity.page))
    labels = definition.identity.labels
    return SwitchIdentity(
        model=values.get(labels.get('model', ''), ''),
        firmware=values.get(labels.get('firmware', ''), ''),
        mac=norm_mac(values.get(labels.get('mac', ''), '')),
    )


def _ports(definition: Definition, pages: dict[str, list[str]]) -> list[PortCounters]:
    spec = definition.ports
    tables, headers = _table(pages, spec.table, 'port counters')
    col = _columns(headers, spec.table, {'port', 'rx_bytes', 'tx_bytes'}, 'port counters')
    speeds = _speeds(definition, pages)
    ports: list[PortCounters] = []
    for table in tables:
        for row in table.data_rows():
            pid = port_id(_cell(row, col['port']), spec.port_id)
            if pid is None:
                continue
            rx = parse_number(_cell(row, col['rx_bytes']), spec.number_format)
            tx = parse_number(_cell(row, col['tx_bytes']), spec.number_format)
            if rx is None or tx is None:
                raise SwitchParseError(f'port {pid}: a byte counter is not a number: the switch layout may have changed')
            rx_pk = parse_number(_cell(row, col.get('rx_packets')), spec.number_format) if col.get('rx_packets') is not None else None
            tx_pk = parse_number(_cell(row, col.get('tx_packets')), spec.number_format) if col.get('tx_packets') is not None else None
            if spec.perspective == 'device':   # the firmware labels counters from the device's side: swap to port side
                rx, tx, rx_pk, tx_pk = tx, rx, tx_pk, rx_pk
            link = _cell(row, col.get('link')) if col.get('link') is not None else ''
            ports.append(PortCounters(
                port=pid, rx_bytes=rx, tx_bytes=tx, rx_packets=rx_pk, tx_packets=tx_pk,
                link_up=(link == spec.link_up_text) if spec.link_up_text and link else None,
                speed_mbps=speeds.get(pid), counter_bits=spec.counter_bits,
            ))
    return ports


def _speeds(definition: Definition, pages: dict[str, list[str]]) -> dict[str, int]:
    spec = definition.ports.speeds
    if spec is None:
        return {}
    tables, headers = _table(pages, spec.table, 'port speeds')
    col = _columns(headers, spec.table, {'port', 'speed'}, 'port speeds')
    speeds: dict[str, int] = {}
    for table in tables:
        for row in table.data_rows():
            pid = port_id(_cell(row, col['port']), definition.ports.port_id)
            speed = parse_speed_mbps(_cell(row, col['speed']))
            if pid is not None and speed is not None:
                speeds[pid] = speed
    return speeds


def _macs(definition: Definition, pages: dict[str, list[str]], warnings: list[str]) -> list[MacEntry]:
    spec = definition.macs
    tables, headers = _table(pages, spec.table, 'MAC address')
    col = _columns(headers, spec.table, {'mac', 'port'}, 'MAC address')
    entries: list[MacEntry] = []
    skipped = 0
    for table in tables:
        for row in table.data_rows():
            mac = norm_mac(_cell(row, col['mac']))
            pid = port_id(_cell(row, col['port']), spec.port_id)
            if not mac or pid is None:
                skipped += 1
                continue
            vlan_text = _cell(row, col.get('vlan')) if col.get('vlan') is not None else ''
            entries.append(MacEntry(
                mac=mac, port=pid, vlan=int(vlan_text) if re.fullmatch(r'\d+', vlan_text) else None,
                dynamic=_cell(row, col.get('type')).lower() == spec.dynamic_text.lower() if col.get('type') is not None else True,
            ))
    if skipped:
        warnings.append(f'{skipped} MAC table row(s) could not be read and were skipped')
    return entries
