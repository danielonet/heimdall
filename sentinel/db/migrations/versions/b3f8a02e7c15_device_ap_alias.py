"""device ap_alias

Revision ID: b3f8a02e7c15
Revises: c3d8e5a1f907
Create Date: 2026-07-27 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3f8a02e7c15'
down_revision: Union[str, None] = 'c3d8e5a1f907'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Which AP a WiFi client is associated with ('PRIV0'/'VID1'/'GUEST2G'/
    'GUEST5G'/'AP_BACKHAUL') — fetched by the adapter while merging
    AssociatedDevices across access points but previously discarded before
    reaching the database. See SagemcomXmoAdapter._get_associated_devices.
    """
    op.execute("ALTER TABLE devices ADD COLUMN ap_alias VARCHAR(20)")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS ap_alias")
