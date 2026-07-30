"""app settings auto block expiry

Revision ID: a3d7f18b6e42
Revises: f4b2e6a91c53
Create Date: 2026-07-30 13:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3d7f18b6e42'
down_revision: Union[str, None] = 'f4b2e6a91c53'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Hours an auto-block stays in effect before SentinelScheduler.
    _block_expiry_job auto-unblocks and notifies for review — 0 means
    auto-blocks never expire. Manual blocks are never affected.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN auto_block_expiry_hours INTEGER NOT NULL DEFAULT 24")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS auto_block_expiry_hours")
