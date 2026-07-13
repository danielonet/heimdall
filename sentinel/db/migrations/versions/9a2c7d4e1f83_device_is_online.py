"""device is_online

Revision ID: 9a2c7d4e1f83
Revises: 7f3b9e21a6c4
Create Date: 2026-07-13 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a2c7d4e1f83'
down_revision: Union[str, None] = '7f3b9e21a6c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add devices.is_online — the router adapter already computes this
    correctly per-poll (DeviceSnapshot.is_online, from the Hosts table's
    Active field), but it was never persisted, so the frontend's ONLINE/
    OFFLINE filter fell back to guessing from last_seen recency. Since
    last_seen was bumped for every device on every poll regardless of its
    actual Active status, that guess was always wrong — this column fixes it
    at the source instead of patching the guess.
    """
    op.execute("ALTER TABLE devices ADD COLUMN is_online BOOLEAN DEFAULT FALSE")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS is_online")
