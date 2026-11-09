#!/usr/bin/env python3
"""Scrub captured switch pages before they become test fixtures.

    python3 scripts/scrub-switch-pages.py SRC_DIR DST_DIR [FIRST_FILE ...]

Every MAC address becomes 02:00:00:00:00:NN (a locally administered address that belongs to no vendor) and every
private IPv4 address becomes 192.168.0.N, numbered in order of first appearance. Files named after SRC_DIR are
read in the order given, then alphabetically, so list the info page first if you want the switch's own address
to be 02:00:00:00:00:01. The mapping is printed so you can write expected.json.

This removes the obvious identifiers only. Read the result before committing it: host names, serial numbers,
SSIDs and anything else personal still have to be checked by a person. tests/test_switches/test_fixture_privacy.py
fails if a fixture still contains a real-looking MAC or a non-example address.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

MAC = re.compile(r'(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])')
IP = re.compile(
    r'(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])'
)


def scrub(texts: dict[str, str]) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Return (scrubbed texts, mac mapping, ip mapping)."""
    macs: dict[str, str] = {}
    ips: dict[str, str] = {}

    def mac_sub(match: re.Match[str]) -> str:
        key = match.group(0).lower().replace('-', ':')
        if key not in macs:
            macs[key] = f'02:00:00:00:00:{len(macs) + 1:02x}'
        new = macs[key]
        return new.upper() if match.group(0).upper() == match.group(0) else new

    def ip_sub(match: re.Match[str]) -> str:
        key = match.group(0)
        if key not in ips:
            ips[key] = f'192.168.0.{len(ips) + 2}'
        return ips[key]

    out = {name: IP.sub(ip_sub, MAC.sub(mac_sub, text)) for name, text in texts.items()}
    return out, macs, ips


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    src, dst = Path(argv[1]), Path(argv[2])
    first = argv[3:]
    names = [n for n in first if (src / n).is_file()] + sorted(
        p.name for p in src.iterdir() if p.is_file() and p.name not in first
    )
    texts = {n: (src / n).read_text(encoding='utf-8', errors='replace') for n in names}
    scrubbed, macs, ips = scrub(texts)
    dst.mkdir(parents=True, exist_ok=True)
    for name, text in scrubbed.items():
        (dst / name).write_text(text, encoding='utf-8')
    print(f'{len(scrubbed)} files written to {dst}')
    for old, new in macs.items():
        print(f'  mac #{new[-2:]} <- (original not printed)')
    print(f'  {len(macs)} MAC(s) and {len(ips)} IP(s) replaced. Now read the files for anything else personal.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
