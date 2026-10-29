"""admin_account: the dashboard login created on first run

Revision ID: b3d7e1f94c26
Revises: a9e2c7d41b58
Create Date: 2026-10-29 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'b3d7e1f94c26'
down_revision: Union[str, None] = 'a9e2c7d41b58'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """One row at most (id is pinned to 1), holding a salted scrypt hash and never the password."""
    op.execute("""
        CREATE TABLE admin_account (
            id            SMALLINT PRIMARY KEY CHECK (id = 1),
            username      VARCHAR(32) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS admin_account")
