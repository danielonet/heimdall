"""device quarantine

Revision ID: f4b2e6a91c53
Revises: e1a5c9d3f728
Create Date: 2026-07-30 13:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4b2e6a91c53'
down_revision: Union[str, None] = 'e1a5c9d3f728'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """WAN-only "cut internet, allow LAN" response tier, distinct from
    is_blocked's full removal. See SagemcomXmoAdapter.quarantine_device.
    """
    op.execute("ALTER TABLE devices ADD COLUMN is_quarantined BOOLEAN NOT NULL DEFAULT false")


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS is_quarantined")
