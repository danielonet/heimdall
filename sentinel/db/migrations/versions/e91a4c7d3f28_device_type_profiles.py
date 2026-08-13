"""device type profiles

Revision ID: e91a4c7d3f28
Revises: d8b3f4a91c62
Create Date: 2026-08-09 12:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e91a4c7d3f28'
down_revision: Union[str, None] = 'd8b3f4a91c62'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Replaces sentinel/detection/device_profiles.py's hardcoded
    DEVICE_TYPE_PROFILES dict with an admin-editable table, seeded with the
    same four rows that dict used to have — with one deliberate fix:
    Smartphone previously had no volume_sustained_polls override at all
    (silently fell back to the generic default of 3), which is the direct
    cause of a phone that's normally idle and then bursts (video call,
    streaming) reliably tripping ANOMALOUS_VOLUME every time. Also adds a
    contamination column (higher for Smartphone) — see AnomalyEngine/
    ModelTrainer.retrain_all() for why contamination, not just the poll
    count, matters for a recurring-but-infrequent legitimate burst pattern.
    """
    op.execute("""
        CREATE TABLE device_type_profiles (
            device_type VARCHAR(50) PRIMARY KEY,
            high_upload_ratio_threshold DOUBLE PRECISION NOT NULL,
            volume_sustained_polls INTEGER NOT NULL,
            contamination DOUBLE PRECISION NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        INSERT INTO device_type_profiles
            (device_type, high_upload_ratio_threshold, volume_sustained_polls, contamination)
        VALUES
            ('Network Attached Storage', 8.0, 5, 0.05),
            ('IP Camera', 10.0, 5, 0.05),
            ('Printer', 2.0, 2, 0.03),
            ('Smartphone', 2.5, 6, 0.10)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS device_type_profiles")
