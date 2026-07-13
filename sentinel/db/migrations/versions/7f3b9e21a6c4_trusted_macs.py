"""trusted macs

Revision ID: 7f3b9e21a6c4
Revises: d57a12ca025d
Create Date: 2026-07-13 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7f3b9e21a6c4'
down_revision: Union[str, None] = 'd57a12ca025d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create trusted_macs — a persistent trust registry independent of the
    devices table's lifecycle, so NewDeviceDetector can recognise a
    previously-trusted MAC even after `devices` has been cleared/reset (e.g.
    re-baselining after a dev reset), instead of re-flagging every known
    device as CRITICAL on the next poll.
    """
    op.execute("""
        CREATE TABLE trusted_macs (
            mac_address  VARCHAR(17)  PRIMARY KEY,
            trusted_at   TIMESTAMPTZ  DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS trusted_macs")
