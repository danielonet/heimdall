"""app settings sniff iface

Revision ID: c92e5f18a4d7
Revises: b7d4e2a91f38
Create Date: 2026-07-16 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c92e5f18a4d7'
down_revision: Union[str, None] = 'b7d4e2a91f38'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Runtime-configurable SNIFF_IFACE override — lets an admin pick the
    LAN-facing NIC for ARP watch / passive fingerprinting from the Settings
    tab dropdown (see sentinel/security/interfaces.py) instead of editing
    .env and restarting. NULL means "use the Settings.SNIFF_IFACE env
    default".
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN sniff_iface VARCHAR(20)")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS sniff_iface")
