"""app settings last digest

Revision ID: b8e4a02d9f61
Revises: a3d7f18b6e42
Create Date: 2026-07-30 13:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8e4a02d9f61'
down_revision: Union[str, None] = 'a3d7f18b6e42'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """When the last security digest notification was sent — NULL means
    never sent yet. See SentinelScheduler._security_digest_job.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN last_digest_sent_at TIMESTAMPTZ")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS last_digest_sent_at")
