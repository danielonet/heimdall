"""Coarse OS-family bucketing, so two differently-shaped OS guesses can be
compared without a literal-string mismatch.

Heimdall has two independent OS signals per device: PassiveFingerprinter's
passive TCP fingerprint (a broad family string like 'Windows', 'Linux /
Android', 'macOS / iOS' — see sentinel/security/fingerprint.py's
OS_SIGNATURES) and NetworkScanner's active nmap `-O` scan (a much more
specific osmatch name like 'Linux 3.10 - 4.11' or 'Microsoft Windows 10
1607' — see sentinel/security/scanner.py). Comparing those two raw strings
directly would mismatch on nearly every scan even when they agree about
the actual OS; os_family() buckets both into the same coarse category
first so a real disagreement (e.g. passively "Windows", actively "Linux")
stands out from a shape-of-string difference.
"""
from __future__ import annotations

from typing import Optional


def os_family(os_string: Optional[str]) -> str:
    """Returns one of 'windows', 'macos_ios', 'linux_android', 'other', or
    'unknown' (for a blank string or one containing 'unknown')."""
    if not os_string:
        return 'unknown'
    lowered = os_string.lower()
    if 'unknown' in lowered:
        return 'unknown'
    if 'windows' in lowered:
        return 'windows'
    if 'mac' in lowered or 'ios' in lowered or 'darwin' in lowered:
        return 'macos_ios'
    if 'linux' in lowered or 'android' in lowered:
        return 'linux_android'
    return 'other'
