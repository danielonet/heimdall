"""app settings auto block on threat

Revision ID: a7c4e91b2f6d
Revises: f1b9c47e6a25
Create Date: 2026-07-19 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7c4e91b2f6d'
down_revision: Union[str, None] = 'f1b9c47e6a25'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Whether ArpWatcher/PassiveFingerprinter/NetworkScanner should call
    adapter.block_device() automatically the moment they identify an attack
    (ARP spoofing, an OS-fingerprint mismatch on a known MAC, a newly-opened
    high-risk port, or an nmap vuln-scan finding), instead of only raising an
    alert. Defaults to TRUE — see SentinelScheduler._raise_threat_alert.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN auto_block_on_threat BOOLEAN NOT NULL DEFAULT TRUE")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS auto_block_on_threat")
