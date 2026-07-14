"""device signal strength/rate

Revision ID: e4b6a19f2d05
Revises: c1d8f3a72b90
Create Date: 2026-07-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e4b6a19f2d05'
down_revision: Union[str, None] = 'c1d8f3a72b90'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add devices.signal_strength_dbm/signal_rate_mbps — the adapter has
    computed these correctly since the AssociatedDevices fix (real dBm/kbps
    for WiFi clients, 0 for wired), but they were never persisted past
    DeviceSnapshot or exposed by the API. 0 for wired devices.
    """
    op.execute("ALTER TABLE devices ADD COLUMN signal_strength_dbm INTEGER DEFAULT 0")
    op.execute("ALTER TABLE devices ADD COLUMN signal_rate_mbps INTEGER DEFAULT 0")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS signal_strength_dbm")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS signal_rate_mbps")
