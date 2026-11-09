#!/usr/bin/env python3
"""Write src/data/switches.json from the switch catalog plus docs/router/switch-facts.json,
so the website's switch table cannot drift from the code. Fails if a catalog entry has no facts."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sentinel.switches.catalog import CATALOG  # noqa: E402

facts = json.loads((ROOT / 'docs/router/switch-facts.json').read_text())
missing = [s.id for s in CATALOG if s.id not in facts]
if missing:
    sys.exit(f'gen-switches: no entry in docs/router/switch-facts.json for: {", ".join(missing)}')

rows = []
for s in CATALOG:
    f = facts[s.id]
    rows.append(dict(id=s.id, label=s.label, family=s.family, protocol=s.protocol,
                     implemented=s.implemented, simulator=s.simulator.value,
                     hardware=f['hardware'], ports=f['ports'], traffic=f['traffic'],
                     limits=f['limits'], notes=s.notes))
out = Path(__file__).resolve().parents[1] / 'src/data/switches.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(rows, indent=2) + '\n')
print(f'gen-switches: {len(rows)} switches -> {out.relative_to(ROOT)}')
