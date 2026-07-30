"""device block expiry

Revision ID: e1a5c9d3f728
Revises: d94c1b6e8a37
Create Date: 2026-07-30 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1a5c9d3f728'
down_revision: Union[str, None] = 'd94c1b6e8a37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """blocked_at/blocked_until support time-limited auto-blocks —
    SentinelScheduler._raise_threat_alert sets/refreshes both on every
    auto-block; manual blocks (POST /devices/<mac>/block) leave
    blocked_until NULL, which means "no expiry" by design. See
    SentinelScheduler._block_expiry_job.
    """
    op.execute("ALTER TABLE devices ADD COLUMN blocked_at TIMESTAMPTZ")
    op.execute("ALTER TABLE devices ADD COLUMN blocked_until TIMESTAMPTZ")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS blocked_at")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS blocked_until")
