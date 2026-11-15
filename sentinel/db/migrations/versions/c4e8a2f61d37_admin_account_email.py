"""admin_account.email: where a password-reset link is sent; required from now on

Every admin must have a reset email, so an account without one (every account
made before this) is removed here and its owner creates it again in the browser,
email included. Only the login row goes: devices, alerts and settings stay.

Revision ID: c4e8a2f61d37
Revises: a8d3f1c7e925
Create Date: 2026-11-15 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c4e8a2f61d37'
down_revision: Union[str, None] = 'a8d3f1c7e925'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE admin_account ADD COLUMN email VARCHAR(254)")
    op.execute("DELETE FROM admin_account WHERE email IS NULL")
    op.execute("ALTER TABLE admin_account ALTER COLUMN email SET NOT NULL")


def downgrade() -> None:
    """Keeps the account (the older code ignores the column it no longer knows)."""
    op.execute("ALTER TABLE admin_account DROP COLUMN IF EXISTS email")
