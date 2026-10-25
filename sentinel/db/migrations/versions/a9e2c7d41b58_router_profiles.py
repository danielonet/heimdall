"""router_profiles table for the Equipment tab's router selection

Revision ID: a9e2c7d41b58
Revises: f6b4d9e27a81
Create Date: 2026-10-25 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a9e2c7d41b58'
down_revision: Union[str, None] = 'f6b4d9e27a81'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """One row per selected router family. Passwords are deliberately not
    stored — they go to a per-router file under ROUTER_SECRETS_DIR."""
    op.execute("""
        CREATE TABLE router_profiles (
            router_id  VARCHAR(40) PRIMARY KEY,
            host       VARCHAR(255) NOT NULL DEFAULT '',
            username   VARCHAR(100) NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS router_profiles")
