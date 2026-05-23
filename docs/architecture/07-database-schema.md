# Database Schema

PostgreSQL 16 + TimescaleDB. All time-series tables are TimescaleDB hypertables
for efficient range queries and automatic time-based partitioning.

## Core tables

```sql
-- Device registry
CREATE TABLE devices (
    mac_address          VARCHAR(17)  PRIMARY KEY,  -- lowercase colon-separated
    ip_address           VARCHAR(15),
    hostname             VARCHAR(255),
    vendor_name          VARCHAR(255),
    interface_name       VARCHAR(20),               -- 'WiFi' | 'Ethernet'
    traffic_granularity  VARCHAR(12)  DEFAULT 'per_device',
    port_alias           VARCHAR(10),               -- NULL=WiFi, 'PHY5'=wired
    os_fingerprint       VARCHAR(100),              -- from passive fingerprinting
    nmap_profile         JSONB,                     -- last Nmap scan result
    tags                 TEXT[],                    -- 'trusted','suspicious', etc.
    is_blocked           BOOLEAN      DEFAULT FALSE,
    is_trusted           BOOLEAN      DEFAULT FALSE,
    first_seen           TIMESTAMPTZ  DEFAULT now(),
    last_seen            TIMESTAMPTZ  DEFAULT now()
);

-- Known wired devices (update after first deployment)
UPDATE devices
SET traffic_granularity = 'per_port', port_alias = 'PHY5'
WHERE mac_address IN ('0c:11:05:a6:b6:18', '0c:11:05:61:ad:5b');
```

## Time-series tables (TimescaleDB hypertables)

```sql
-- Per-device traffic samples
CREATE TABLE traffic_samples (
    time                 TIMESTAMPTZ  NOT NULL,
    mac_address          VARCHAR(17)  NOT NULL,
    bytes_sent_delta     BIGINT,
    bytes_recv_delta     BIGINT,
    throughput_up_kbps   BIGINT,
    throughput_dn_kbps   BIGINT,
    anomaly_score        FLOAT,        -- ML score; NULL during bootstrap
    granularity          VARCHAR(12),
    poll_interval_s      INT
);
SELECT create_hypertable('traffic_samples', 'time');
CREATE INDEX ON traffic_samples (mac_address, time DESC);

-- Per-port Ethernet stats
CREATE TABLE port_stats (
    time                 TIMESTAMPTZ  NOT NULL,
    port_alias           VARCHAR(10)  NOT NULL,   -- 'PHY1'..'PHY5'
    status               VARCHAR(10),
    link_speed_mbps      INT,
    bytes_sent_delta     BIGINT,
    bytes_recv_delta     BIGINT,
    errors_recv          INT,
    discards_recv        INT,
    broadcast_recv       BIGINT,
    last_change_secs     BIGINT
);
SELECT create_hypertable('port_stats', 'time');

-- DNS queries (from Pi-hole API)
CREATE TABLE dns_queries (
    time                 TIMESTAMPTZ  NOT NULL,
    device_mac           VARCHAR(17),
    query                VARCHAR(500),
    blocked              BOOLEAN,
    list_name            VARCHAR(100)
);
SELECT create_hypertable('dns_queries', 'time');
CREATE INDEX ON dns_queries (device_mac, time DESC);
```

## Operational tables

```sql
-- Alerts
CREATE TABLE alerts (
    id           BIGSERIAL    PRIMARY KEY,
    device_mac   VARCHAR(17),
    alert_type   VARCHAR(50)  NOT NULL,
    severity     VARCHAR(10)  NOT NULL,   -- INFO | WARNING | CRITICAL
    description  TEXT,
    raw_data     JSONB,
    acknowledged BOOLEAN      DEFAULT FALSE,
    resolved     BOOLEAN      DEFAULT FALSE,
    created_at   TIMESTAMPTZ  DEFAULT now()
);
CREATE INDEX ON alerts (severity, created_at DESC);
CREATE INDEX ON alerts (device_mac, created_at DESC);

-- User-defined rules
CREATE TABLE rules (
    id             BIGSERIAL    PRIMARY KEY,
    name           VARCHAR(100) NOT NULL,
    condition_json JSONB        NOT NULL,
    action_json    JSONB        NOT NULL,
    enabled        BOOLEAN      DEFAULT TRUE,
    created_at     TIMESTAMPTZ  DEFAULT now(),
    last_triggered TIMESTAMPTZ
);

-- Threat intel cache (avoid repeated API calls)
CREATE TABLE threat_intel_cache (
    ip_or_domain  VARCHAR(255) PRIMARY KEY,
    is_malicious  BOOLEAN,
    threat_type   VARCHAR(100),
    source_feed   VARCHAR(50),
    score         INT,
    cached_at     TIMESTAMPTZ  DEFAULT now(),
    expires_at    TIMESTAMPTZ
);

-- WAN status history
CREATE TABLE wan_status_history (
    id           BIGSERIAL    PRIMARY KEY,
    changed_at   TIMESTAMPTZ  DEFAULT now(),
    status       VARCHAR(10)  NOT NULL,   -- 'UP' | 'DOWN'
    wan_mode     VARCHAR(30),
    duration_s   BIGINT                  -- filled when next change arrives
);
```

## Useful queries

```sql
-- Device throughput over last hour
SELECT time_bucket('1 minute', time) AS bucket,
       mac_address,
       avg(throughput_up_kbps)   AS avg_up_kbps,
       avg(throughput_dn_kbps)   AS avg_dn_kbps
FROM traffic_samples
WHERE time > now() - INTERVAL '1 hour'
  AND mac_address = 'da:d4:19:31:c0:e9'
GROUP BY bucket, mac_address
ORDER BY bucket DESC;

-- Devices with anomalous scores in last 24 hours
SELECT DISTINCT d.hostname, d.mac_address, d.ip_address,
       min(t.anomaly_score) AS worst_score
FROM traffic_samples t
JOIN devices d ON d.mac_address = t.mac_address
WHERE t.time > now() - INTERVAL '24 hours'
  AND t.anomaly_score < -0.1
GROUP BY d.hostname, d.mac_address, d.ip_address
ORDER BY worst_score ASC;

-- Unacknowledged critical alerts
SELECT a.id, a.alert_type, a.description, a.created_at,
       d.hostname, d.ip_address
FROM alerts a
LEFT JOIN devices d ON d.mac_address = a.device_mac
WHERE a.severity = 'CRITICAL'
  AND a.acknowledged = FALSE
ORDER BY a.created_at DESC;
```

## Migrations

Managed by Alembic. Migration scripts in `sentinel/db/migrations/`.

```bash
# Create a new migration
alembic revision --autogenerate -m "add os_fingerprint column"

# Apply all pending migrations
alembic upgrade head

# Roll back one migration
alembic downgrade -1
```
