"""app settings alert stale hours

Revision ID: d8b3f4a91c62
Revises: c4f6a83d2e17
Create Date: 2026-08-08 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd8b3f4a91c62'
down_revision: Union[str, None] = 'c4f6a83d2e17'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Hours after which an unresolved alert is considered stale — excluded
    from the Dashboard/Network Map (both filter on Alert.created_at via the
    existing `from` query param) and shown with a STALE badge instead of
    OPEN on the full Alerts page. Nothing is deleted. See AppSettings.
    alert_stale_hours and frontend/src/lib/alertStaleness.js.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN alert_stale_hours INTEGER NOT NULL DEFAULT 24")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS alert_stale_hours")
