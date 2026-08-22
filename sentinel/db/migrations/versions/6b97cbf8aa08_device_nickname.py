"""device nickname

Revision ID: 6b97cbf8aa08
Revises: d2b6c94a1f83
Create Date: 2026-08-22 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6b97cbf8aa08'
down_revision: Union[str, None] = 'd2b6c94a1f83'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """A user-set label, independent of the router-reported hostname.

    Confirmed a real bug, not just a missing feature: devices.hostname is
    unconditionally overwritten with the router's own DHCP hostname on
    every poll cycle (sentinel/scheduler/jobs.py:_upsert_devices,
    POLL_INTERVAL_SECONDS=15 default) — a PATCH /api/devices/<mac> hostname
    edit already existed and looked like a rename feature, but got reverted
    within ~15 seconds by the very next poll, silently. This column is
    never touched by _upsert_devices, so a rename actually sticks. Kept
    separate from hostname (not repurposed) so DeviceIdentityLinker's
    hostname-match heuristic keeps comparing what the router actually
    reports, unaffected by whatever a user has renamed a device to.
    """
    op.execute("ALTER TABLE devices ADD COLUMN nickname TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS nickname")
