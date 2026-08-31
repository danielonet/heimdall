"""app settings device purge after days

Revision ID: f2c8b53e947a
Revises: 83dc363fea90
Create Date: 2026-08-31 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f2c8b53e947a'
down_revision: Union[str, None] = '83dc363fea90'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Days a device may sit *archived* (see device_archive_after_days)
    before the same sweep job permanently deletes it — see
    DeviceRepository.purge_archived(). A second, later stage on top of
    archiving, not a replacement for it: archive_stale() only ever hides a
    stale device (is_archived=True), nothing about it is ever removed on
    its own. Requested directly: archived-forever isn't actually cleanup,
    it just relocates the clutter — a device genuinely gone should
    eventually have its row, alerts, DNS/traffic history, and persisted ML
    model actually deleted. Additive on top of device_archive_after_days
    (measured from archived_at, not last_seen), so raising or lowering one
    doesn't silently change the other's meaning. See
    AppSettings.device_purge_after_days.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN device_purge_after_days INTEGER NOT NULL DEFAULT 90")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS device_purge_after_days")
