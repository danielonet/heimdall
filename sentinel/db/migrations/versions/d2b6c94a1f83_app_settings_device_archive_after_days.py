"""app settings device archive after days

Revision ID: d2b6c94a1f83
Revises: c8f3a71d5e94
Create Date: 2026-08-18 09:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd2b6c94a1f83'
down_revision: Union[str, None] = 'c8f3a71d5e94'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Days of no activity before the device-archive sweep job
    (SentinelScheduler._device_archive_sweep_job) soft-archives a device —
    see DeviceRepository.archive_stale(). Deliberately a separate setting
    from data_retention_days: retention prunes time-series history
    (traffic_samples/alerts/...), this decides when a *device record itself*
    is hidden as stale — conflating them would mean turning up retention
    accidentally starts hiding devices, or vice versa. See
    AppSettings.device_archive_after_days.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN device_archive_after_days INTEGER NOT NULL DEFAULT 90")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS device_archive_after_days")
