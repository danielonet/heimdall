"""Fixtures are committed to a public repository: only synthetic addresses may appear in them."""
import re

from tests.test_switches.simulator import FIXTURES_DIR

MAC = re.compile(r'(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])')
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
ALLOWED_IP = re.compile(r'^(192\.168\.0\.\d+|255\.255\.255\.\d+|0\.0\.0\.0|127\.0\.0\.1)$')


def test_fixtures_contain_only_synthetic_macs_and_example_addresses():
    files = [p for p in FIXTURES_DIR.rglob('*') if p.is_file()]
    assert files
    for path in files:
        text = path.read_text(encoding='utf-8', errors='replace')
        for mac in MAC.findall(text):
            assert mac.lower().startswith('02:00:00:00:00:'), f'{path}: {mac} is not a synthetic MAC (run scripts/scrub-switch-pages.py)'
        for ip in IPV4.findall(text):
            assert ALLOWED_IP.match(ip), f'{path}: {ip} is not an example address (run scripts/scrub-switch-pages.py)'
