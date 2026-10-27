#!/usr/bin/env python3
"""Write src/data/routers.json from the adapter catalog plus
docs/router/equipment-facts.json, so the website's equipment table cannot
drift from the code. Fails if a catalog entry has no facts."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sentinel.adapter.catalog import CATALOG  # noqa: E402

facts = json.loads((ROOT / 'docs/router/equipment-facts.json').read_text())
missing = [s.id for s in CATALOG if s.id not in facts]
if missing:
    sys.exit(f'gen-routers: no entry in docs/router/equipment-facts.json for: {", ".join(missing)}')

rows = []
for s in CATALOG:
    f = facts[s.id]
    rows.append(dict(id=s.id, label=s.label, family=s.family, protocol=s.protocol,
                     implemented=s.implemented, simulator=s.simulator.value,
                     hardware=f['hardware'], block=f['block'], quarantine=f['quarantine'],
                     traffic=f['traffic'], notes=s.notes))
out = Path(__file__).resolve().parents[1] / 'src/data/routers.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(rows, indent=2) + '\n')
print(f'gen-routers: {len(rows)} routers -> {out.relative_to(ROOT)}')
