"""wifi sightings

Revision ID: d1a9c6e438b7
Revises: c7e5b3a92f14
Create Date: 2026-09-18 20:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd1a9c6e438b7'
down_revision: Union[str, None] = 'c7e5b3a92f14'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Passive nearby-WiFi-device inventory — see
    sentinel/db/models.py:WifiSighting and sentinel/security/wifi_monitor.py.
    No FK to devices (deliberately — a sighting is very often a MAC that
    never becomes a Device at all), and a plain table, not a hypertable:
    this is "one row per distinct MAC, touched on every re-sighting" (same
    upsert shape as `alerts`), not a high-frequency time-series.
    """
    op.execute("""
        CREATE TABLE wifi_sightings (
            mac_address TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL DEFAULT '',
            first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            strongest_signal_dbm INTEGER,
            times_seen INTEGER NOT NULL DEFAULT 1,
            last_probed_ssid VARCHAR(32)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS wifi_sightings")
