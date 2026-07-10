"""initial schema

Revision ID: d57a12ca025d
Revises: 
Create Date: 2026-07-04 20:09:24.906300

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd57a12ca025d'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the core schema per docs/architecture/07-database-schema.md."""
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")

    op.execute("""
        CREATE TABLE devices (
            mac_address          VARCHAR(17)  PRIMARY KEY,
            ip_address           VARCHAR(15),
            hostname             VARCHAR(255),
            vendor_name          VARCHAR(255),
            interface_name       VARCHAR(20),
            traffic_granularity  VARCHAR(12)  DEFAULT 'per_device',
            port_alias           VARCHAR(10),
            os_fingerprint       VARCHAR(100),
            nmap_profile         JSONB,
            tags                 TEXT[],
            is_blocked           BOOLEAN      DEFAULT FALSE,
            is_trusted           BOOLEAN      DEFAULT FALSE,
            first_seen           TIMESTAMPTZ  DEFAULT now(),
            last_seen            TIMESTAMPTZ  DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE traffic_samples (
            time                 TIMESTAMPTZ  NOT NULL,
            mac_address          VARCHAR(17)  NOT NULL,
            bytes_sent_delta     BIGINT,
            bytes_recv_delta     BIGINT,
            throughput_up_kbps   BIGINT,
            throughput_dn_kbps   BIGINT,
            anomaly_score        FLOAT,
            granularity          VARCHAR(12),
            poll_interval_s      INT
        )
    """)
    op.execute("SELECT create_hypertable('traffic_samples', 'time')")
    op.execute("CREATE INDEX ON traffic_samples (mac_address, time DESC)")

    op.execute("""
        CREATE TABLE port_stats (
            time                 TIMESTAMPTZ  NOT NULL,
            port_alias           VARCHAR(10)  NOT NULL,
            status               VARCHAR(10),
            link_speed_mbps      INT,
            bytes_sent_delta     BIGINT,
            bytes_recv_delta     BIGINT,
            errors_recv          INT,
            discards_recv        INT,
            broadcast_recv       BIGINT,
            last_change_secs     BIGINT
        )
    """)
    op.execute("SELECT create_hypertable('port_stats', 'time')")

    op.execute("""
        CREATE TABLE dns_queries (
            time                 TIMESTAMPTZ  NOT NULL,
            device_mac           VARCHAR(17),
            query                VARCHAR(500),
            blocked              BOOLEAN,
            list_name            VARCHAR(100)
        )
    """)
    op.execute("SELECT create_hypertable('dns_queries', 'time')")
    op.execute("CREATE INDEX ON dns_queries (device_mac, time DESC)")

    op.execute("""
        CREATE TABLE alerts (
            id           BIGSERIAL    PRIMARY KEY,
            device_mac   VARCHAR(17),
            alert_type   VARCHAR(50)  NOT NULL,
            severity     VARCHAR(10)  NOT NULL,
            description  TEXT,
            raw_data     JSONB,
            acknowledged BOOLEAN      DEFAULT FALSE,
            resolved     BOOLEAN      DEFAULT FALSE,
            created_at   TIMESTAMPTZ  DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ON alerts (severity, created_at DESC)")
    op.execute("CREATE INDEX ON alerts (device_mac, created_at DESC)")

    op.execute("""
        CREATE TABLE rules (
            id             BIGSERIAL    PRIMARY KEY,
            name           VARCHAR(100) NOT NULL,
            condition_json JSONB        NOT NULL,
            action_json    JSONB        NOT NULL,
            enabled        BOOLEAN      DEFAULT TRUE,
            created_at     TIMESTAMPTZ  DEFAULT now(),
            last_triggered TIMESTAMPTZ
        )
    """)

    op.execute("""
        CREATE TABLE threat_intel_cache (
            ip_or_domain  VARCHAR(255) PRIMARY KEY,
            is_malicious  BOOLEAN,
            threat_type   VARCHAR(100),
            source_feed   VARCHAR(50),
            score         INT,
            cached_at     TIMESTAMPTZ  DEFAULT now(),
            expires_at    TIMESTAMPTZ
        )
    """)

    op.execute("""
        CREATE TABLE wan_status_history (
            id           BIGSERIAL    PRIMARY KEY,
            changed_at   TIMESTAMPTZ  DEFAULT now(),
            status       VARCHAR(10)  NOT NULL,
            wan_mode     VARCHAR(30),
            duration_s   BIGINT
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS wan_status_history")
    op.execute("DROP TABLE IF EXISTS threat_intel_cache")
    op.execute("DROP TABLE IF EXISTS rules")
    op.execute("DROP TABLE IF EXISTS alerts")
    op.execute("DROP TABLE IF EXISTS dns_queries")
    op.execute("DROP TABLE IF EXISTS port_stats")
    op.execute("DROP TABLE IF EXISTS traffic_samples")
    op.execute("DROP TABLE IF EXISTS devices")
