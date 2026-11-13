"""Bounded incremental reading of the append-only logs Heimdall tails (Zeek dns.log, Suricata eve.json, OpenCanary).

These files are never rotated on this deployment, so they only grow. Reading one with `readlines()` from byte 0
loads the whole file into memory: on the first poll after every backend restart, and again whenever the backend
falls behind. On a small box that is enough to get the backend OOM-killed, and because the file is still there
after the restart, to do it again. read_new_lines() bounds both cases:

- the first read of a file bigger than FIRST_READ_BACKLOG_BYTES starts that far from the end instead of at byte 0
  (older events are not replayed: they were either handled before the restart or are too old to matter);
- no read takes more than MAX_READ_BYTES; what is left is read on the next poll, so the backend catches up
  gradually and its memory use stays flat.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 4_000_000
FIRST_READ_BACKLOG_BYTES = 8_000_000


def read_new_lines(
    path: str, offset: int, *, max_bytes: int = MAX_READ_BYTES, first_read_backlog: int = FIRST_READ_BACKLOG_BYTES,
) -> tuple[list[str], int]:
    """Return (non-blank lines with their newline, new offset) for what was appended after `offset`.

    A file that does not exist or cannot be read gives ([], offset). A file smaller than `offset` was replaced
    (a container restart recreates it) and is read again from the start. When more than `max_bytes` is waiting,
    only whole lines up to that size are returned and the offset stops there. A single line longer than
    `max_bytes` is skipped rather than allowed to stall the reader. A last line that has not been completed yet
    is returned as it is, as it always was.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return [], offset

    if size < offset:
        logger.warning('%s is smaller than the last tracked offset (%d < %d): treating it as a fresh file.', path, size, offset)
        offset = 0

    skip_partial_line = False
    if offset == 0 and size > first_read_backlog:
        logger.warning('%s is %d bytes: reading only its last %d bytes instead of all of it.', path, size, first_read_backlog)
        offset = size - first_read_backlog
        skip_partial_line = True

    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            chunk = f.read(max_bytes)
    except OSError:
        return [], offset

    if skip_partial_line:
        newline = chunk.find(b'\n')
        if newline == -1:
            return [], offset + len(chunk)
        offset += newline + 1
        chunk = chunk[newline + 1:]

    if offset + len(chunk) < size:                  # more is waiting: stop at the last complete line
        cut = chunk.rfind(b'\n')
        if cut == -1:
            logger.warning('%s has a line longer than %d bytes: skipping it.', path, max_bytes)
            return [], offset + len(chunk)
        chunk = chunk[:cut + 1]

    # Split on newlines only, as readlines() did: str.splitlines() would also split on characters such as U+2028.
    *complete, last = chunk.decode('utf-8', errors='replace').split('\n')
    lines = [line + '\n' for line in complete] + ([last] if last else [])
    return [line for line in lines if line.strip()], offset + len(chunk)
