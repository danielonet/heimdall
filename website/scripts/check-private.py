#!/usr/bin/env python3
"""Fail if the built site contains something that looks like private network data:
real-looking MAC addresses, private (RFC 1918) IPv4 addresses, or secret-looking tokens.
Placeholders are allowed (aa:bb:cc:dd:ee:ff, 192.168.1.0/24-style examples must be listed below)."""
import re
import sys
from pathlib import Path

ALLOWED = {'aa:bb:cc:dd:ee:ff', '00:00:00:00:00:00'}
MAC = re.compile(r'\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', re.I)
PRIVATE_IP = re.compile(r'\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b')
SECRET = re.compile(r'(?:ghp_|github_pat_|sk-[A-Za-z0-9]{20}|-----BEGIN [A-Z ]*PRIVATE KEY)')

dist = Path(sys.argv[1] if len(sys.argv) > 1 else 'dist')
bad = []
for f in dist.rglob('*'):
    if not f.is_file() or f.suffix in {'.png', '.woff', '.woff2', '.pf_fragment', '.pf_index', '.pf_meta', '.pagefind', '.wasm', '.js'} or 'pagefind' in f.parts:
        continue
    text = f.read_text(errors='ignore')
    for rx, what in ((MAC, 'MAC address'), (PRIVATE_IP, 'private IP address'), (SECRET, 'secret-looking token')):
        for m in rx.finditer(text):
            if m.group(0).lower() not in ALLOWED:
                bad.append(f'{f.relative_to(dist)}: {what} {m.group(0)!r}')
print('\n'.join(sorted(set(bad))) or 'check-private: clean')
sys.exit(1 if bad else 0)
