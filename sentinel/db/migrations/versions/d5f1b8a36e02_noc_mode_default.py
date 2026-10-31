"""New installs start in NOC mode: auto_block_on_threat defaults to false

Revision ID: d5f1b8a36e02
Revises: c4e8a2d17f93
Create Date: 2026-10-31

Only the column default changes. A row that already exists keeps the value the
admin has (SOC stays SOC), so an upgrade never switches the mode by itself.
"""
from typing import Sequence, Union

from alembic import op

revision: str = 'd5f1b8a36e02'
down_revision: Union[str, None] = 'c4e8a2d17f93'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE app_settings ALTER COLUMN auto_block_on_threat SET DEFAULT FALSE")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings ALTER COLUMN auto_block_on_threat SET DEFAULT TRUE")
