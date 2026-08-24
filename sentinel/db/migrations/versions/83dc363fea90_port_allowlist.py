"""port allowlist

Revision ID: 83dc363fea90
Revises: d095d2a6308f
Create Date: 2026-08-24 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '83dc363fea90'
down_revision: Union[str, None] = 'd095d2a6308f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Per-(device, port) exception to NetworkScanner's HIGH_RISK_PORTS
    check — see sentinel/db/repositories.py:PortAllowlistRepository and
    SentinelScheduler._nmap_scan_job's allowed_ports filter.

    No FK to devices, deliberately — same reasoning as trusted_macs/
    alert_snoozes: must survive a devices-table purge/reset rather than
    cascade-deleting with it. PK is (device_mac, port), not a surrogate id
    — at most one allowlist entry per pair; re-adding replaces it (a
    changed note/service label) rather than accumulating rows.
    """
    op.execute("""
        CREATE TABLE port_allowlist (
            device_mac TEXT NOT NULL,
            port INTEGER NOT NULL,
            service TEXT NOT NULL,
            note TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (device_mac, port)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS port_allowlist")
