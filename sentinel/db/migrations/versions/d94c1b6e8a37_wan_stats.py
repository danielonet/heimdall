"""wan stats

Revision ID: d94c1b6e8a37
Revises: b3f8a02e7c15
Create Date: 2026-07-27 09:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd94c1b6e8a37'
down_revision: Union[str, None] = 'b3f8a02e7c15'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Household-total WAN traffic delta per poll interval (TimescaleDB
    hypertable) — no device/port dimension, `time` alone identifies a row.
    Populated from an unverified xpath (see docs/router/sagemcom-xmo-api.md
    and SagemcomXmoAdapter.get_wan_stats); this table exists regardless of
    whether that xpath resolves, it just stays empty if it doesn't.
    """
    op.execute("""
        CREATE TABLE wan_stats (
            time                 TIMESTAMPTZ  NOT NULL,
            bytes_sent_delta     BIGINT,
            bytes_recv_delta     BIGINT,
            throughput_up_kbps   BIGINT,
            throughput_dn_kbps   BIGINT
        )
    """)
    op.execute("SELECT create_hypertable('wan_stats', 'time')")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS wan_stats")
