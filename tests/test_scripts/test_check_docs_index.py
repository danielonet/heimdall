"""Tests for scripts/check-docs-index.py, the guard that keeps docs/INDEX.md current."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'check-docs-index.py'
spec = importlib.util.spec_from_file_location('check_docs_index', SCRIPT)
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker  # dataclasses resolves annotations through sys.modules
spec.loader.exec_module(checker)

HEADER = '| Document | Kind | Read when |\n|---|---|---|\n'


def write(root: Path, rel: str, text: str = '# T\n') -> None:
    """Create a file under the fake repository."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A tiny repository whose index is complete."""
    write(tmp_path, 'CLAUDE.md', 'See `docs/INDEX.md` and `docs/a.md`.\n')
    write(tmp_path, 'README.md')
    write(tmp_path, 'docs/a.md')
    write(tmp_path, 'docs/images/shot.png', 'x')
    write(tmp_path, 'wiremock/__files/r1/NOTES.md')
    write(tmp_path, 'wiremock/__files/r2/NOTES.md')
    write(
        tmp_path,
        'docs/INDEX.md',
        '# Index\n\n' + HEADER
        + '| `README.md` | guide | Read for the pitch. |\n'
        + '| `docs/a.md` | reference | Read when you change a. |\n'
        + '| `wiremock/__files/*/NOTES.md` | data | Read for simulator fidelity. |\n',
    )
    return tmp_path


def test_complete_index_passes(repo: Path) -> None:
    assert checker.build_report(repo).ok


def test_new_document_without_row_is_reported(repo: Path) -> None:
    write(repo, 'docs/new.md')
    report = checker.build_report(repo)
    assert report.missing == ['docs/new.md']
    assert not report.ok


def test_deleted_document_leaves_a_stale_row(repo: Path) -> None:
    (repo / 'docs/a.md').unlink()
    write(repo, 'CLAUDE.md', 'See `docs/INDEX.md`.\n')
    report = checker.build_report(repo)
    assert [r.path for r in report.stale] == ['docs/a.md']


def test_glob_row_covers_every_match(repo: Path) -> None:
    write(repo, 'wiremock/__files/r3/NOTES.md')
    assert checker.build_report(repo).ok


def test_unknown_kind_and_todo_text_fail(repo: Path) -> None:
    index = repo / 'docs/INDEX.md'
    index.write_text(index.read_text().replace('| reference |', '| essay |'), encoding='utf-8')
    assert any('kind' in p for p in checker.build_report(repo).problems)
    index.write_text(index.read_text().replace('Read when you change a.', 'TODO: later'), encoding='utf-8')
    assert any('read when' in p for p in checker.build_report(repo).problems)


def test_claude_md_must_point_at_the_index(repo: Path) -> None:
    write(repo, 'CLAUDE.md', 'No pointer here.\n')
    assert any('does not mention' in p for p in checker.build_report(repo).problems)


def test_claude_md_dead_docs_reference_fails(repo: Path) -> None:
    write(repo, 'CLAUDE.md', 'See `docs/INDEX.md` and `docs/gone.md`.\n')
    assert any('docs/gone.md' in p for p in checker.build_report(repo).problems)


def test_fix_drops_stale_rows_adds_stubs_and_still_fails_until_described(repo: Path) -> None:
    (repo / 'docs/a.md').unlink()
    write(repo, 'CLAUDE.md', 'See `docs/INDEX.md`.\n')
    write(repo, 'docs/b-plan.md')
    checker.apply_fix(repo, checker.build_report(repo))
    text = (repo / 'docs/INDEX.md').read_text()
    assert '`docs/a.md`' not in text
    assert '| `docs/b-plan.md` | plan | TODO' in text
    report = checker.build_report(repo)
    assert report.missing == [] and report.stale == []
    assert not report.ok  # the stub still needs its sentence

