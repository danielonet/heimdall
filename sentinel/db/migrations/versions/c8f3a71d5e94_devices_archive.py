"""devices archive

Revision ID: c8f3a71d5e94
Revises: b6e2d84f19a3
Create Date: 2026-08-18 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c8f3a71d5e94'
down_revision: Union[str, None] = 'b6e2d84f19a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Stale device cleanup — see sentinel/db/repositories.py:DeviceRepository.
    archive_stale()/unarchive() and SentinelScheduler._device_archive_sweep_job.
    A device unseen for AppSettings.device_archive_after_days (default 90)
    gets soft-archived: hidden from device counts/lists (see
    sentinel/api/routes/devices.py:list_devices), but nothing is deleted —
    fully reversible via unarchive(). Deliberately distinct from the
    identity-link columns (linked_to_mac/linked_at/link_reason, see
    b6e2d84f19a3) — archiving is "this device just hasn't been seen in a
    long time", not "this row is a stale duplicate of another live device".
    """
    op.execute("ALTER TABLE devices ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT false")
    op.execute("ALTER TABLE devices ADD COLUMN archived_at TIMESTAMPTZ")
    op.execute("ALTER TABLE devices ADD COLUMN archive_reason TEXT")
    op.execute(
        "CREATE INDEX ix_devices_is_archived ON devices (mac_address) WHERE is_archived = true"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_devices_is_archived")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS archive_reason")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS archived_at")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS is_archived")
