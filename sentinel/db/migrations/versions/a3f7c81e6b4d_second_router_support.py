"""second router support (devices.source_router, app_settings.miwifi_ip/active_router)

Revision ID: a3f7c81e6b4d
Revises: f2c8b53e947a
Create Date: 2026-09-13 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3f7c81e6b4d'
down_revision: Union[str, None] = 'f2c8b53e947a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Adds support for a second, optional router (a Redmi/Xiaomi unit on
    stock MiWiFi firmware — see sentinel/adapter/miwifi/) alongside the
    permanent Sagemcom.

    devices.source_router records which configured router most recently
    reported a given MAC, defaulting every existing row to 'sagemcom' (the
    only router that has ever existed before this migration) rather than
    leaving it NULL — SentinelScheduler._adapter_for_mac always needs a
    concrete value to route block/unblock/quarantine actions correctly.

    app_settings.miwifi_ip and .active_router back the new Settings-tab
    "REDMI ROUTER" section and its primary-router dropdown, following the
    exact pattern of the existing router_username/sniff_iface columns.
    active_router defaults to 'sagemcom' so every pre-existing install keeps
    behaving exactly as before until an admin explicitly configures and
    selects the second router.
    """
    op.execute("ALTER TABLE devices ADD COLUMN source_router VARCHAR(20) NOT NULL DEFAULT 'sagemcom'")
    op.execute("ALTER TABLE app_settings ADD COLUMN miwifi_ip VARCHAR(45)")
    op.execute("ALTER TABLE app_settings ADD COLUMN active_router VARCHAR(20) NOT NULL DEFAULT 'sagemcom'")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS active_router")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS miwifi_ip")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS source_router")
