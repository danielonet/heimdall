"""MAC OUI vendor lookup — identifies device manufacturers from their MAC
address prefix, using the IEEE OUI database bundled with Scapy. Local lookup
only: no network calls, no API key, no rate limits.
"""
from __future__ import annotations

from scapy.data import MANUFDB


def lookup_vendor(mac: str) -> str:
    """Return the manufacturer name for a MAC address's OUI prefix.

    Returns '' if the address is locally administered (a randomized/private
    MAC — common on modern phones and laptops for WiFi privacy, and
    structurally has no real manufacturer to look up) or the prefix isn't in
    the database.
    """
    mac = mac.strip().lower()
    if not mac or is_locally_administered(mac):
        return ''

    prefix = ':'.join(mac.split(':')[:3])
    if not prefix:
        return ''

    vendor = MANUFDB._get_manuf(prefix.upper())
    # Scapy's ManufDB returns the queried prefix back verbatim when it has no entry.
    if not vendor or vendor.upper() == prefix.upper():
        return ''
    return vendor


def is_locally_administered(mac: str) -> bool:
    """True if the MAC's U/L bit (bit 1 of the first octet) is set.

    Locally administered addresses are assigned by software rather than
    burned into hardware by a manufacturer — e.g. WiFi MAC randomization on
    modern phones/laptops — so there's no OUI vendor to resolve.
    """
    try:
        first_octet = int(mac.split(':')[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b10)
