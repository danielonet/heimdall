"""Turning page text into numbers, ports and addresses."""
from __future__ import annotations

import re

from sentinel.net_common import norm_mac  # noqa: F401  (re-exported: definitions refer to MAC normalisation here)


def parse_number(text: str, fmt: str = 'plain') -> int | None:
    """A counter from page text. None when the text is not a number (never a silent 0).

    plain: "1234" or "1,234,567".  hi_lo: "<high>-<low>", two 32-bit words, value = high * 2**32 + low.
    """
    text = (text or '').strip()
    if fmt == 'hi_lo':
        match = re.fullmatch(r'(\d+)-(\d+)', text)
        return int(match.group(1)) * (1 << 32) + int(match.group(2)) if match else None
    if fmt == 'plain':
        cleaned = text.replace(',', '').replace(' ', '')
        return int(cleaned) if re.fullmatch(r'\d+', cleaned) else None
    raise ValueError(f'unknown number format {fmt!r}')


def parse_speed_mbps(text: str) -> int | None:
    """Link speed in Mb/s from "1000M", "10M" or "1G"; None for "Auto" or anything else."""
    match = re.fullmatch(r'\s*(\d+)\s*([MG])(?:bps|b/s)?\s*', text or '', re.IGNORECASE)
    if not match:
        return None
    value = int(match.group(1))
    return value * 1000 if match.group(2).upper() == 'G' else value


def port_id(text: str, pattern: str) -> str | None:
    """The port id from a cell: group 1 of `pattern` (or the whole match), e.g. "Port 3" with "^Port\\s*(\\S+)$" → "3"."""
    match = re.search(pattern, text or '', re.IGNORECASE)
    if not match:
        return None
    return (match.group(1) if match.groups() else match.group(0)).strip()
