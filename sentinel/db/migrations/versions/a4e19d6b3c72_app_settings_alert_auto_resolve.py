"""app settings alert auto resolve hours

Revision ID: a4e19d6b3c72
Revises: f7a3c95d8e21
Create Date: 2026-08-14 09:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a4e19d6b3c72'
down_revision: Union[str, None] = 'f7a3c95d8e21'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Hours of no recurrence before the alert_auto_resolve sweep job
    (SentinelScheduler._alert_auto_resolve_job) closes an open alert that has
    no natural "this stopped" signal of its own (ArpWatcher/DhcpWatcher/
    OpenCanary/Zeek/Suricata/nmap findings — see AlertRepository.resolve_stale_open).
    Deliberately a separate setting from alert_stale_hours: staleness is
    cosmetic (dims a badge, reversible); this one is a state mutation that
    closes the alert outright. See AppSettings.alert_auto_resolve_hours.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN alert_auto_resolve_hours INTEGER NOT NULL DEFAULT 72")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS alert_auto_resolve_hours")
