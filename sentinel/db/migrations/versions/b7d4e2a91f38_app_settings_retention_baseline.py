"""app settings retention and baseline

Revision ID: b7d4e2a91f38
Revises: a1c3f9b7d2e6
Create Date: 2026-07-15 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7d4e2a91f38'
down_revision: Union[str, None] = 'a1c3f9b7d2e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the data-retention window (traffic_samples/port_stats/alerts/
    wan_status_history roll off after this many days — see the nightly
    _data_retention_job in sentinel/scheduler/scheduler.py) and
    baseline_established_at, which drives the frontend's LEARNING/ARMED
    status badge — stamped when a fresh-install baseline is established,
    cleared by POST /api/settings/purge.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN data_retention_days INTEGER NOT NULL DEFAULT 90")
    op.execute("ALTER TABLE app_settings ADD COLUMN baseline_established_at TIMESTAMPTZ")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS baseline_established_at")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS data_retention_days")
