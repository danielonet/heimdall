#!/usr/bin/env python3
"""Keep docs/INDEX.md in step with the documents it indexes.

docs/INDEX.md is the map an agent reads to decide which documents matter for a task.
This check fails when the map has drifted from the repository:

  * a document in scope has no row            (missing)
  * a row names a file that no longer exists  (stale)
  * a row has an unknown kind or no real "read when" text (unfinished)
  * CLAUDE.md does not point at the index, or names a docs/ path that does not exist

`--fix` closes the mechanical part of the gap: it drops stale rows and appends a stub row for
every missing document. The stubs still fail the check until someone writes the "read when" text,
because that sentence is the part only a reader can supply.

Standard library only, so it runs in CI and in `npm run build` without installing anything.
"""
from __future__ import annotations

import argparse
import glob
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger('check-docs-index')

INDEX = 'docs/INDEX.md'
ENTRYPOINT = 'CLAUDE.md'

# Documents that must each have a row. A row may also name any other existing file or a glob
# (those are only checked for existing), so source-of-truth code and data files can be indexed too.
SCOPE = (
    '*.md',
    'docs/**/*.md',
    'docs/**/*.json',
    'website/README.md',
    'website/src/content/docs/**/*.md',
    'tests/simulators/README.md',
    'wiremock/README.md',
    'wiremock/__files/*/NOTES.md',
)
EXCLUDED = (ENTRYPOINT, INDEX, 'docs/images/')

# How far to trust a document. This is the column that stops an agent from treating a shipped
# plan as a to-do list, or a proposal as a description of the product.
KINDS = {
    'reference': 'describes what exists now; trust it, and fix it when the code changes',
    'plan': 'how a feature was designed and built; history and rationale, not current behaviour',
    'proposal': 'not built, or only partly built; never describe it as shipped',
    'runbook': 'steps for a person to follow',
    'guide': 'written for users or contributors',
    'record': 'a log, checklist or report; evidence, not specification',
    'data': 'machine-read facts that other files are generated or checked from',
    'mockup': 'design artefacts; open in a browser',
}
UNFINISHED = 'TODO'
UNSORTED_HEADING = '## Unsorted'
ROW = re.compile(r'^\|\s*`([^`]+)`\s*\|\s*([A-Za-z-]+)\s*\|\s*(.*?)\s*\|\s*$')
CLAUDE_DOCS_REF = re.compile(r'`(docs/[^`\s]+)`')


@dataclass
class Row:
    """One line of the index table."""

    path: str
    kind: str
    note: str
    line: int


@dataclass
class Report:
    """What the check found; `ok` is true when nothing needs a person's attention."""

    problems: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    stale: list[Row] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def expand(root: Path, pattern: str) -> list[str]:
    """Repo-relative files matching a path or glob; directories count when named exactly."""
    hits = glob.glob(pattern, root_dir=root, recursive=True)
    return sorted(h for h in hits if (root / h).exists())


def documents_in_scope(root: Path) -> list[str]:
    """Every file that must be indexed."""
    found: set[str] = set()
    for pattern in SCOPE:
        for rel in expand(root, pattern):
            if (root / rel).is_file() and not rel.startswith(EXCLUDED):
                found.add(rel)
    return sorted(found)


def parse_rows(text: str) -> list[Row]:
    """The table rows of the index: | `path` | kind | read when |."""
    rows = []
    for number, line in enumerate(text.splitlines(), start=1):
        m = ROW.match(line)
        if m:
            rows.append(Row(path=m.group(1), kind=m.group(2).lower(), note=m.group(3), line=number))
    return rows


def check_claude_md(root: Path, report: Report) -> None:
    """CLAUDE.md must lead to the index, and every docs/ path it names must exist."""
    entry = root / ENTRYPOINT
    if not entry.is_file():
        report.problems.append(f'{ENTRYPOINT} is missing')
        return
    text = entry.read_text(encoding='utf-8')
    if INDEX not in text:
        report.problems.append(f'{ENTRYPOINT} does not mention {INDEX}; an agent starting there would never find the map')
    for ref in sorted(set(CLAUDE_DOCS_REF.findall(text))):
        if ref != INDEX and not expand(root, ref.rstrip('/')):
            report.problems.append(f'{ENTRYPOINT} names {ref}, which does not exist')


def build_report(root: Path) -> Report:
    """Compare the index with the repository."""
    report = Report()
    index_path = root / INDEX
    if not index_path.is_file():
        report.problems.append(f'{INDEX} is missing')
        report.missing = documents_in_scope(root)
        return report

    rows = parse_rows(index_path.read_text(encoding='utf-8'))
    covered: set[str] = set()
    seen: set[str] = set()
    for row in rows:
        where = f'{INDEX}:{row.line}'
        if row.path in seen:
            report.problems.append(f'{where}: {row.path} is listed twice')
        seen.add(row.path)
        matches = expand(root, row.path)
        if not matches:
            report.stale.append(row)
            report.problems.append(f'{where}: {row.path} does not exist (renamed or deleted?)')
        covered.update(matches)
        if row.kind not in KINDS:
            report.problems.append(f'{where}: kind {row.kind!r} is not one of {", ".join(sorted(KINDS))}')
        if not row.note or row.note.startswith(UNFINISHED):
            report.problems.append(f'{where}: {row.path} still needs its "read when" text')

    report.missing = [d for d in documents_in_scope(root) if d not in covered]
    report.problems.extend(f'{d} is not in {INDEX}' for d in report.missing)
    check_claude_md(root, report)
    return report


def guess_kind(path: str) -> str:
    """A starting kind for a stub row; a person confirms it when writing the note."""
    if path.endswith('.json'):
        return 'data'
    if '/mockups/' in path:
        return 'mockup'
    if path.startswith('website/src/content/'):
        return 'guide'
    if path.endswith('-plan.md'):
        return 'plan'
    return 'reference'


def apply_fix(root: Path, report: Report) -> None:
    """Drop stale rows and append a stub for each missing document."""
    index_path = root / INDEX
    drop = {row.line for row in report.stale}
    lines = index_path.read_text(encoding='utf-8').splitlines() if index_path.is_file() else ['# Documentation index', '']
    kept = [line for number, line in enumerate(lines, start=1) if number not in drop]
    text = '\n'.join(kept).rstrip('\n') + '\n'
    # A previous --fix leaves an empty "Unsorted" table once its rows are written up elsewhere.
    text = re.sub(rf'\n{UNSORTED_HEADING}\n\n\| Document[^\n]*\n\|---[^\n]*\n?\Z', '\n', text)
    if report.missing:
        if UNSORTED_HEADING not in text:
            text += f'\n{UNSORTED_HEADING}\n\n| Document | Kind | Read when |\n|---|---|---|\n'
        text += ''.join(f'| `{path}` | {guess_kind(path)} | {UNFINISHED}: say when an agent should read this |\n' for path in report.missing)
    index_path.write_text(text, encoding='utf-8')


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; the exit status is non-zero while the index needs attention."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--fix', action='store_true', help='drop stale rows and add stub rows for missing documents')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent, help='repository root')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stdout)

    report = build_report(args.root)
    if args.fix and (report.stale or report.missing):
        apply_fix(args.root, report)
        logger.info('%s: removed %d stale row(s), added %d stub row(s)', INDEX, len(report.stale), len(report.missing))
        report = build_report(args.root)
    for problem in report.problems:
        logger.error('check-docs-index: %s', problem)
    if report.ok:
        logger.info('check-docs-index: %s is complete and current', INDEX)
        return 0
    if not args.fix and (report.missing or report.stale):
        logger.error('check-docs-index: run `python3 scripts/check-docs-index.py --fix`, then write the "read when" text for new rows')
    return 1


if __name__ == '__main__':
    sys.exit(main())
