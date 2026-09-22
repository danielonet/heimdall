"""wifi networks

Revision ID: e3c8a5d1f296
Revises: d1a9c6e438b7
Create Date: 2026-09-19 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = 'e3c8a5d1f296'
down_revision: Union[str, None] = 'd1a9c6e438b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Nearby access points seen via beacon frames — see
    sentinel/db/models.py:WifiNetwork. Plain table keyed by BSSID, same
    "one row touched on every re-sighting" shape as wifi_sightings."""
    op.execute("""
        CREATE TABLE wifi_networks (
            bssid TEXT PRIMARY KEY,
            ssid VARCHAR(32) NOT NULL DEFAULT '',
            vendor_name TEXT NOT NULL DEFAULT '',
            channel INTEGER,
            strongest_signal_dbm INTEGER,
            secured BOOLEAN NOT NULL DEFAULT true,
            first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS wifi_networks")
