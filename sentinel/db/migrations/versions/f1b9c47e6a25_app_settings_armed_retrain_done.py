"""app settings armed retrain done

Revision ID: f1b9c47e6a25
Revises: e5f27a83c1d4
Create Date: 2026-07-17 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1b9c47e6a25'
down_revision: Union[str, None] = 'e5f27a83c1d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Tracks whether _retrain_once_armed (jobs.py) has already refit every
    device's ML model from the full learning-window history for the current
    learning cycle — see AppSettings.armed_retrain_done's docstring. Defaults
    to FALSE for existing rows too, which is deliberate: any system that's
    already ARMED right now is almost certainly running on a stale,
    narrowly-trained bootstrap model and needs this retrain on its very next
    poll cycle.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN armed_retrain_done BOOLEAN NOT NULL DEFAULT FALSE")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS armed_retrain_done")
