"""alert snoozes

Revision ID: d095d2a6308f
Revises: 6b97cbf8aa08
Create Date: 2026-08-22 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd095d2a6308f'
down_revision: Union[str, None] = '6b97cbf8aa08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Per-(device, alert_type) suppression window — see
    sentinel/db/repositories.py:AlertSnoozeRepository and AlertRepository.
    upsert()'s snooze check.

    No FK to devices, deliberately — same reasoning as trusted_macs: a
    snooze should stay valid even across a devices-table purge/reset, and
    must never cascade-delete just because the device row it was set
    against happened to get archived or purged. PK is (device_mac,
    alert_type), not a surrogate id — there's at most one active snooze per
    pair, and re-snoozing is meant to just replace/extend it, not
    accumulate rows.
    """
    op.execute("""
        CREATE TABLE alert_snoozes (
            device_mac TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            snoozed_until TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (device_mac, alert_type)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS alert_snoozes")
