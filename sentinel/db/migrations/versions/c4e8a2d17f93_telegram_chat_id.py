"""app settings telegram chat id

Revision ID: c4e8a2d17f93
Revises: b3d7e1f94c26
Create Date: 2026-10-29 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c4e8a2d17f93'
down_revision: Union[str, None] = 'b3d7e1f94c26'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Telegram channel/chat to push to — editable from the Notifications
    section. Not a secret (a channel name or numeric id), so it lives in
    app_settings; the bot token is a secret and stays in its *_FILE.
    """
    op.execute("ALTER TABLE app_settings ADD COLUMN telegram_chat_id VARCHAR(255)")


def downgrade() -> None:
    op.execute("ALTER TABLE app_settings DROP COLUMN IF EXISTS telegram_chat_id")
