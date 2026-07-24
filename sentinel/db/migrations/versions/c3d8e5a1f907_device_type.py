"""device type

Revision ID: c3d8e5a1f907
Revises: a7c4e91b2f6d
Create Date: 2026-07-24 08:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d8e5a1f907'
down_revision: Union[str, None] = 'a7c4e91b2f6d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """The router's own DHCP-fingerprint device classification (e.g.
    'Smartphone', 'Multimedia device') — previously read from the XMO API
    response but discarded before reaching the database. See
    SagemcomXmoAdapter._to_device_snapshot.
    """
    op.execute("ALTER TABLE devices ADD COLUMN device_type VARCHAR(50)")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS device_type")
