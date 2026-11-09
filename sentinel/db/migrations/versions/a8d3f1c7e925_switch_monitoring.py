"""managed switch monitoring: switch_targets, switch_port_stats, devices.switch_*

Revision ID: a8d3f1c7e925
Revises: d5f1b8a36e02
Create Date: 2026-11-09 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a8d3f1c7e925'
down_revision: Union[str, None] = 'd5f1b8a36e02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """switch_targets: one row per configured switch (non-secret fields only; the password is a secret file,
    CLAUDE.md rule 6). switch_port_stats: per-port deltas, a TimescaleDB hypertable. devices.switch_*: which
    switch port currently gives a device its own traffic figures, and when the switch last confirmed it."""
    op.execute("""
        CREATE TABLE switch_targets (
            id                   SERIAL PRIMARY KEY,
            spec_id              VARCHAR(40)  NOT NULL,
            name                 VARCHAR(60)  NOT NULL,
            host                 VARCHAR(255) NOT NULL,
            username             VARCHAR(100) NOT NULL DEFAULT '',
            poll_interval_s      INTEGER      NOT NULL DEFAULT 15,
            enabled              BOOLEAN      NOT NULL DEFAULT TRUE,
            model                VARCHAR(100),
            firmware             VARCHAR(50),
            last_ok_at           TIMESTAMPTZ,
            last_error           TEXT,
            consecutive_failures INTEGER      NOT NULL DEFAULT 0,
            created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
            updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE switch_port_stats (
            time                TIMESTAMPTZ NOT NULL,
            switch_id           INTEGER     NOT NULL,
            port                VARCHAR(20) NOT NULL,
            link_up             BOOLEAN,
            speed_mbps          INTEGER,
            bytes_in_delta      BIGINT,
            bytes_out_delta     BIGINT,
            throughput_in_kbps  BIGINT,
            throughput_out_kbps BIGINT,
            macs                INTEGER,
            attributed_mac      VARCHAR(17)
        )
    """)
    op.execute("SELECT create_hypertable('switch_port_stats', 'time')")
    op.execute("CREATE INDEX ix_switch_port_stats_switch_port_time ON switch_port_stats (switch_id, port, time DESC)")
    op.execute("""
        ALTER TABLE devices
            ADD COLUMN switch_target_id INTEGER,
            ADD COLUMN switch_name      VARCHAR(60),
            ADD COLUMN switch_port      VARCHAR(20),
            ADD COLUMN switch_seen_at   TIMESTAMPTZ
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE devices
            DROP COLUMN IF EXISTS switch_target_id,
            DROP COLUMN IF EXISTS switch_name,
            DROP COLUMN IF EXISTS switch_port,
            DROP COLUMN IF EXISTS switch_seen_at
    """)
    op.execute("DROP TABLE IF EXISTS switch_port_stats")
    op.execute("DROP TABLE IF EXISTS switch_targets")
