"""app settings wifi monitor

Revision ID: c7e5b3a92f14
Revises: a3f7c81e6b4d
Create Date: 2026-09-18 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7e5b3a92f14'
down_revision: Union[str, None] = 'a3f7c81e6b4d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """WiFi Monitor tab settings — see sentinel/security/wifi_monitor.py and
    AppSettings.wifi_monitor_iface's docstring. wifi_monitor_iface starts
    NULL (feature disabled, unlike sniff_iface there's no env-config
    fallback — no deployment can assume a monitor-capable adapter exists).
    wifi_protected_ssids/wifi_trusted_bssids start as empty arrays, not
    NULL, so callers can always iterate them without a None-guard.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN wifi_monitor_iface VARCHAR(20)")
    op.execute("ALTER TABLE app_settings ADD COLUMN wifi_protected_ssids TEXT[] NOT NULL DEFAULT '{}'")
    op.execute("ALTER TABLE app_settings ADD COLUMN wifi_trusted_bssids TEXT[] NOT NULL DEFAULT '{}'")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS wifi_monitor_iface")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS wifi_protected_ssids")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS wifi_trusted_bssids")
