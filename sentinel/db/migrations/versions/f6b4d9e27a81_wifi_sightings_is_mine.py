"""wifi sightings is mine

Revision ID: f6b4d9e27a81
Revises: e3c8a5d1f296
Create Date: 2026-09-22 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = 'f6b4d9e27a81'
down_revision: Union[str, None] = 'e3c8a5d1f296'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Admin-set "this is mine" label on a WiFi sighting — see
    sentinel/db/models.py:WifiSighting.is_mine."""
    op.execute("ALTER TABLE wifi_sightings ADD COLUMN is_mine BOOLEAN NOT NULL DEFAULT false")


def downgrade() -> None:
    op.execute("ALTER TABLE wifi_sightings DROP COLUMN IF EXISTS is_mine")
