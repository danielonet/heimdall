"""app settings

Revision ID: a1c3f9b7d2e6
Revises: e4b6a19f2d05
Create Date: 2026-07-15 08:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1c3f9b7d2e6'
down_revision: Union[str, None] = 'e4b6a19f2d05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Singleton settings row for values that must be changeable at runtime
    from the Settings tab (currently just the ML learning-period window) —
    Settings (pydantic, env/.env-backed) is loaded once at process start and
    isn't writable, so this table is the override layer on top of it.
    """
    op.execute(
        "CREATE TABLE app_settings ("
        "id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1), "
        "ml_learning_period_hours INTEGER NOT NULL DEFAULT 72"
        ")"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS app_settings")
