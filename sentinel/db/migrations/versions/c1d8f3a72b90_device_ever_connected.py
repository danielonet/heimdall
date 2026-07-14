"""device ever connected

Revision ID: c1d8f3a72b90
Revises: 9a2c7d4e1f83
Create Date: 2026-07-14 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1d8f3a72b90'
down_revision: Union[str, None] = '9a2c7d4e1f83'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add devices.ever_connected — distinct from a devices row simply
    existing. A row gets created for every MAC the router's Hosts/
    AssociatedDevices tables ever mention, active or not (e.g. a stale DHCP
    reservation, a device only briefly visible, never a real connection).
    NewDeviceDetector previously used row-existence as its "already known"
    check, which meant a device seen-but-never-connected would silently
    suppress the real NEW_DEVICE alert the first time it actually did
    connect. This column tracks the real thing.
    """
    op.execute("ALTER TABLE devices ADD COLUMN ever_connected BOOLEAN DEFAULT FALSE")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS ever_connected")
