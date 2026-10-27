#!/usr/bin/env python3
"""Fail if any built page links to a file or page that does not exist.
/download/* is excluded: those are redirects to GitHub releases (public/.htaccess)."""
import re
import sys
from pathlib import Path

dist = Path(sys.argv[1] if len(sys.argv) > 1 else 'dist')
files = {'/' + p.relative_to(dist).as_posix() for p in dist.rglob('*') if p.is_file()}
pages = {f[:-len('index.html')] if f.endswith('index.html') else f for f in files if f.endswith('.html')}
bad = []
for html in dist.rglob('*.html'):
    for m in re.finditer(r'(?:href|src)="([^"#]+)(?:#[^"]*)?"', html.read_text()):
        url = m.group(1)
        if url.startswith(('http', 'mailto:', 'data:', '/download/')):
            continue
        if url not in files and url not in pages:
            bad.append((html.relative_to(dist).as_posix(), url))
for page, url in sorted(set(bad)):
    print(f'broken link on {page}: {url}')
sys.exit(1 if bad else 0)
