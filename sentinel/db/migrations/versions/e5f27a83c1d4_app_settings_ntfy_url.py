"""app settings ntfy url

Revision ID: e5f27a83c1d4
Revises: d3a8f61c9b52
Create Date: 2026-07-17 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f27a83c1d4'
down_revision: Union[str, None] = 'd3a8f61c9b52'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Runtime-configurable ntfy.sh push URL — editable from the new
    Notifications tab alongside SMTP, instead of only Settings.NTFY_URL
    (env-only). Not a secret (a topic URL, not a credential), so unlike
    router/SMTP passwords this lives directly in app_settings.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN ntfy_url VARCHAR(500)")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS ntfy_url")
