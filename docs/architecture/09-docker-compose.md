# Docker Compose

## docker-compose.yml

```yaml
services:

  sentinel-backend:
    build: ./sentinel
    network_mode: host          # must reach 10.100.102.1 AND sniff ARP on LAN
    cap_add:
      - NET_RAW                 # required by Scapy for ARP packet sniffing
      - NET_ADMIN               # required for network interface operations
    environment:
      - ROUTER_ADAPTER=sagemcom
      - ROUTER_IP=              # blank = auto-discover from default route
      - ROUTER_PORT=80
      - ROUTER_USERNAME=home
      - ROUTER_PASSWORD_FILE=/run/secrets/router_password
      - DATABASE_URL=postgresql+asyncpg://sentinel:${DB_PASS}@localhost/sentinel
      - REDIS_URL=redis://localhost:6379
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - OTX_API_KEY_FILE=/run/secrets/otx_api_key
      - ADMIN_PASSWORD_FILE=/run/secrets/admin_password
      - SNIFF_IFACE=eth0        # LAN-facing interface on monitoring machine
      - POLL_INTERVAL_SECONDS=15
    secrets:
      - router_password
      - jwt_secret
      - otx_api_key
      - db_pass
      - admin_password
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    volumes:
      - ml-models:/data/models        # persist trained ML models across restarts
      - opencanary-logs:/var/log/opencanary:ro  # read by OpenCanaryIngester

  frontend:
    build: ./frontend
    ports:
      - "3000:80"               # React app via Nginx
    depends_on:
      - sentinel-backend
    restart: unless-stopped

  postgres:
    image: timescale/timescaledb-ha:pg16
    network_mode: host          # sentinel-backend on host net needs localhost DB
    environment:
      POSTGRES_DB: sentinel
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD_FILE: /run/secrets/db_pass
    volumes:
      - pgdata:/var/lib/postgresql/data
    secrets:
      - db_pass
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    network_mode: host
    command: redis-server --save 60 1 --loglevel warning
    restart: unless-stopped

  suricata:
    image: jasonish/suricata:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_NICE
    volumes:
      - ./suricata/suricata.yaml:/etc/suricata/suricata.yaml
      - suricata-logs:/var/log/suricata
    restart: unless-stopped

  clamav:
    image: clamav/clamav:stable
    ports:
      - "3310:3310"             # TCP socket for pyclamd
    volumes:
      - clamav-db:/var/lib/clamav
    restart: unless-stopped

  opencanary:
    image: thinkst/opencanary:latest
    network_mode: host          # must appear as a real LAN device
    volumes:
      - ./opencanary/opencanary.conf:/etc/opencanaryd/opencanary.conf:ro
      - opencanary-logs:/var/log/opencanary
    restart: unless-stopped

secrets:
  router_password: { file: ./secrets/router_password.txt }
  jwt_secret:      { file: ./secrets/jwt_secret.txt }
  otx_api_key:     { file: ./secrets/otx_api_key.txt }
  db_pass:         { file: ./secrets/db_pass.txt }
  admin_password:  { file: ./secrets/admin_password.txt }

volumes:
  pgdata:
  ml-models:
  suricata-logs:
  clamav-db:
  opencanary-logs:
```

## First-run setup

```bash
# 1. Clone the repository
git clone https://gitlab.com/yourname/heimdall.git
cd heimdall

# 2. Create secrets (never committed to git)
mkdir -p secrets
echo "your_router_admin_password" > secrets/router_password.txt
openssl rand -base64 64 > secrets/jwt_secret.txt
echo "your_otx_api_key"           > secrets/otx_api_key.txt
openssl rand -base64 32            > secrets/db_pass.txt
openssl rand -hex 32               > secrets/admin_password.txt   # dashboard login
chmod 600 secrets/*.txt

# 3. Configure LAN interface (find yours with: ip link show)
# Edit docker-compose.yml: SNIFF_IFACE=eth0  (or enp3s0, etc.)

# 4. Start the stack
docker compose up -d

# 5. Run database migrations
docker compose exec sentinel-backend alembic upgrade head
```

## Suricata configuration

Minimal `suricata/suricata.yaml` additions:

```yaml
# Output EVE JSON for ingestion by sentinel-backend
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - dns
        - http
        - tls

# Capture interface
af-packet:
  - interface: eth0

# Rule sources
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# Update rules (run suricata-update in container)
```

## OpenCanary configuration

Minimal `opencanary/opencanary.conf`:

```json
{
    "device.node_id": "heimdall-canary",
    "ip.ignorelist": [],
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {"format": "%(message)s"}
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/log/opencanary/opencanary.log"
                }
            }
        }
    },
    "ftp.enabled": true,
    "ftp.port": 21,
    "http.enabled": true,
    "http.port": 8880,
    "ssh.enabled": true,
    "ssh.port": 2222,
    "telnet.enabled": true,
    "telnet.port": 2323,
    "smb.enabled": true
}
```

## .gitignore entries (critical)

```
secrets/
*.txt
.env
__pycache__/
*.pyc
*.pyo
.pytest_cache/
/data/models/
*.joblib
node_modules/
dist/
```
