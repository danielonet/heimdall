"""alerts mitigation

Revision ID: c4f6a83d2e17
Revises: b8e4a02d9f61
Create Date: 2026-08-08 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4f6a83d2e17'
down_revision: Union[str, None] = 'b8e4a02d9f61'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Canned "what to do about this" guidance for confirmed-attack alerts —
    see sentinel/security/remediation.py:build_mitigation(). NULL for
    RuleEngine/detector-pipeline alerts and for every alert raised before
    this migration. See SentinelScheduler._raise_threat_alert.
    """
    op.execute("ALTER TABLE alerts ADD COLUMN mitigation TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS mitigation")
