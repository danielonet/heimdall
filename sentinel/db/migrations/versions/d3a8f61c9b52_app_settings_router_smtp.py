"""app settings router and smtp config

Revision ID: d3a8f61c9b52
Revises: c92e5f18a4d7
Create Date: 2026-07-17 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3a8f61c9b52'
down_revision: Union[str, None] = 'c92e5f18a4d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Runtime-configurable router username + SMTP notification settings,
    editable from the Settings tab. Passwords are deliberately excluded —
    router_password/smtp_password are written to their *_FILE secret files
    on disk instead (see Settings.ROUTER_PASSWORD_FILE/SMTP_PASSWORD_FILE
    and sentinel/config.py:write_secret_file), keeping CLAUDE.md's "secrets
    via Docker secrets only" rule intact.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN router_username VARCHAR(100)")
    op.execute("ALTER TABLE app_settings ADD COLUMN smtp_host VARCHAR(255)")
    op.execute("ALTER TABLE app_settings ADD COLUMN smtp_port INTEGER")
    op.execute("ALTER TABLE app_settings ADD COLUMN smtp_from VARCHAR(255)")
    op.execute("ALTER TABLE app_settings ADD COLUMN smtp_to VARCHAR(255)")
    op.execute("ALTER TABLE app_settings ADD COLUMN smtp_username VARCHAR(255)")
    op.execute("ALTER TABLE app_settings ADD COLUMN smtp_use_tls BOOLEAN")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS smtp_use_tls")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS smtp_username")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS smtp_to")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS smtp_from")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS smtp_port")
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS router_username")
