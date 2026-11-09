"""HTML tables from a switch page, with the standard-library parser (no extra dependency).

Switch pages are small and mostly well formed: what matters is finding the right table by its header text
(so a firmware that inserts a column does not silently shift the data) and reading its cells.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class Cell:
    """One <th> or <td>, with its whitespace-collapsed text."""

    tag: str
    text: str


@dataclass
class Table:
    """One <table>: rows of cells, in document order."""

    rows: list[list[Cell]] = field(default_factory=list)

    def headers(self) -> list[str]:
        """Texts of the first row that contains a <th>, or [] when there is none."""
        for row in self.rows:
            if any(c.tag == 'th' for c in row):
                return [c.text for c in row]
        return []

    def data_rows(self) -> list[list[str]]:
        """Texts of every row that has at least one <td> and no <th>."""
        return [[c.text for c in row] for row in self.rows if row and all(c.tag == 'td' for c in row)]


class _TableParser(HTMLParser):
    """Collects every <table> into Table objects, tolerating the unclosed and mismatched tags cheap firmware emits."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[Table] = []
        self._stack: list[Table] = []
        self._row: list[Cell] | None = None
        self._cell_tag: str | None = None
        self._cell_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Open a table, row or cell; a new row or cell closes the previous one."""
        if tag == 'table':
            table = Table()
            self.tables.append(table)
            self._stack.append(table)
            self._row = None
            self._cell_tag = None
        elif tag == 'tr' and self._stack:
            self._end_cell()
            self._end_row()
            self._row = []
        elif tag in ('td', 'th') and self._stack:
            self._end_cell()
            if self._row is None:
                self._row = []
            self._cell_tag = tag
            self._cell_text = []

    def handle_endtag(self, tag: str) -> None:
        """Close a cell, row or table."""
        if tag in ('td', 'th'):
            self._end_cell()
        elif tag == 'tr':
            self._end_cell()
            self._end_row()
        elif tag == 'table' and self._stack:
            self._end_cell()
            self._end_row()
            self._stack.pop()

    def handle_data(self, data: str) -> None:
        """Collect text while inside a cell."""
        if self._cell_tag is not None:
            self._cell_text.append(data)

    def _end_cell(self) -> None:
        if self._cell_tag is not None and self._row is not None:
            self._row.append(Cell(self._cell_tag, re.sub(r'\s+', ' ', ''.join(self._cell_text)).strip()))
        self._cell_tag = None
        self._cell_text = []

    def _end_row(self) -> None:
        if self._row and self._stack:
            self._stack[-1].rows.append(self._row)
        self._row = None


def parse_tables(html: str) -> list[Table]:
    """Every table in the document, outer tables first."""
    parser = _TableParser()
    parser.feed(html)
    parser.close()
    return [t for t in parser.tables if t.rows]


def find_table(tables: list[Table], header_patterns: list[str]) -> Table | None:
    """The first table whose header cells match every regex in header_patterns (case-insensitive)."""
    for table in tables:
        headers = table.headers()
        if headers and all(any(re.search(p, h, re.IGNORECASE) for h in headers) for p in header_patterns):
            return table
    return None


def column_index(headers: list[str], pattern: str) -> int | None:
    """Index of the first header matching the regex, or None."""
    for i, header in enumerate(headers):
        if re.search(pattern, header, re.IGNORECASE):
            return i
    return None


def labelled_values(tables: list[Table]) -> dict[str, str]:
    """Label → value for layouts like <th>Device Model:</th><td>HC-…</td>, across every table."""
    pairs: dict[str, str] = {}
    for table in tables:
        for row in table.rows:
            for left, right in zip(row, row[1:]):
                if left.tag == 'th' and right.tag == 'td':
                    pairs.setdefault(left.text, right.text)
    return pairs
