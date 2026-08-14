"""alerts lifecycle

Revision ID: f7a3c95d8e21
Revises: e91a4c7d3f28
Create Date: 2026-08-14 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f7a3c95d8e21'
down_revision: Union[str, None] = 'e91a4c7d3f28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Alert lifecycle redesign — see sentinel/db/repositories.py:AlertRepository.
    A still-true condition now touches its one open row instead of inserting
    a fresh row every poll; these columns carry the "is this still
    happening" signal that a plain created_at/resolved boolean couldn't.
    """
    # last_seen: no natural per-row default for pre-existing rows, so
    # backfill from created_at before enforcing NOT NULL — same two-step
    # pattern as every other "add a NOT NULL column to a populated table"
    # migration in this project.
    op.execute("ALTER TABLE alerts ADD COLUMN last_seen TIMESTAMPTZ")
    op.execute("UPDATE alerts SET last_seen = created_at")
    op.execute("ALTER TABLE alerts ALTER COLUMN last_seen SET NOT NULL")
    op.execute("ALTER TABLE alerts ALTER COLUMN last_seen SET DEFAULT now()")

    op.execute("ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1")
    op.execute("ALTER TABLE alerts ADD COLUMN resolved_at TIMESTAMPTZ")
    op.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TIMESTAMPTZ")
    op.execute("ALTER TABLE alerts ADD COLUMN dedup_key VARCHAR(100)")

    # Every AlertRepository.upsert()/resolve() call looks up the currently-
    # open row for (device_mac, alert_type, dedup_key) — without this index
    # that lookup is a growing sequential scan over the whole table.
    op.execute(
        "CREATE INDEX ix_alerts_open_dedup ON alerts (device_mac, alert_type, dedup_key) "
        "WHERE resolved = false"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_alerts_open_dedup")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS dedup_key")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS acknowledged_at")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS resolved_at")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS occurrence_count")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS last_seen")
