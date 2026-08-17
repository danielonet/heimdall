"""devices identity link

Revision ID: b6e2d84f19a3
Revises: a4e19d6b3c72
Create Date: 2026-08-14 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b6e2d84f19a3'
down_revision: Union[str, None] = 'a4e19d6b3c72'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Device-identity linking — see sentinel/detection/device_identity.py:
    DeviceIdentityLinker and sentinel/db/repositories.py:DeviceRepository.link().
    A phone with a randomized/rotating WiFi MAC (Apple Private Wi-Fi Address,
    Android's randomized-per-network or non-persistent MAC — both on by
    default on modern phones) creates a brand-new `devices` row every time
    it reconnects with a new MAC, inflating device counts with duplicates of
    the same physical device.

    All three columns are set/cleared together (all-NULL = not linked, never
    a partial state) — see DeviceRepository.link()/unlink().
    linked_to_mac always points at the CURRENT live canonical row, never a
    multi-hop chain (link() repoints any existing followers transactionally
    at write time), so every reader stays a flat, single-hop
    `WHERE linked_to_mac IS NULL` / `= :mac` check — see
    sentinel/api/routes/devices.py:list_devices()/get_device() and
    sentinel/api/routes/metrics.py.
    """
    op.execute("ALTER TABLE devices ADD COLUMN linked_to_mac VARCHAR(17)")
    op.execute("ALTER TABLE devices ADD COLUMN linked_at TIMESTAMPTZ")
    op.execute("ALTER TABLE devices ADD COLUMN link_reason TEXT")
    op.execute(
        "CREATE INDEX ix_devices_linked_to_mac ON devices (linked_to_mac) "
        "WHERE linked_to_mac IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_devices_linked_to_mac")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS link_reason")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS linked_at")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS linked_to_mac")
