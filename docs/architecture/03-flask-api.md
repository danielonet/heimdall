# Flask API

## App factory — `sentinel/api/app.py`

```python
from flask import Flask
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
from sentinel.db.session import init_db
from sentinel.api.routes import devices, alerts, rules, ports, threats, auth

socketio = SocketIO(cors_allowed_origins='*', async_mode='threading')

def create_app(config=None) -> Flask:
    app = Flask(__name__)
    app.config.from_object('sentinel.config.Settings')
    if config:
        app.config.update(config)

    JWTManager(app)
    socketio.init_app(app)

    app.register_blueprint(auth.bp,    url_prefix='/api')
    app.register_blueprint(devices.bp, url_prefix='/api/devices')
    app.register_blueprint(alerts.bp,  url_prefix='/api/alerts')
    app.register_blueprint(rules.bp,   url_prefix='/api/rules')
    app.register_blueprint(ports.bp,   url_prefix='/api/ports')
    app.register_blueprint(threats.bp, url_prefix='/api/threats')

    return app
```

## REST endpoints

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/login` | Username + password → JWT access token (15 min) + refresh token (7 days) |
| POST | `/api/refresh` | Exchange refresh token for new access token |
| POST | `/api/logout` | Revoke refresh token |

### Devices

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/devices` | All connected devices with latest snapshot, traffic, and threat score |
| GET | `/api/devices/<mac>` | Full device detail: history, open ports, Nmap profile, alerts, DNS queries |
| POST | `/api/devices/<mac>/block` | Issue `block_device()` via adapter — JWT required |
| POST | `/api/devices/<mac>/unblock` | Issue `unblock_device()` via adapter — JWT required |
| PATCH | `/api/devices/<mac>` | Update device metadata (hostname alias, tags, trusted flag) |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/alerts` | Paginated alert list — filter by `severity`, `device_mac`, `acknowledged`, `from`, `to` |
| GET | `/api/alerts/<id>` | Single alert detail |
| PATCH | `/api/alerts/<id>` | Acknowledge or resolve — body: `{"acknowledged": true}` or `{"resolved": true}` |
| DELETE | `/api/alerts/<id>` | Delete alert — JWT required |

### Rules

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/rules` | All user-defined detection rules |
| POST | `/api/rules` | Create a new rule (JSON body — see rule schema) |
| PUT | `/api/rules/<id>` | Update a rule |
| DELETE | `/api/rules/<id>` | Delete a rule |
| POST | `/api/rules/<id>/test` | Dry-run a rule against recent traffic |

### Ports

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ports` | Current PHY1–PHY5 stats with throughput deltas and status |
| GET | `/api/ports/<alias>` | History for a specific port (e.g. `PHY5`) |

### Threat Intelligence

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threats/feeds` | Status and last-refresh timestamp of all threat feeds |
| GET | `/api/threats/lookup/<ip>` | On-demand IP reputation check against all feeds + OTX |
| GET | `/api/threats/dns-stats` | Pi-hole block statistics by category |

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/router` | Router info: model, firmware, WAN status, WAN mode, uptime |
| GET | `/api/health` | Service health: adapter poll status, Redis, PostgreSQL, ML engine |

## WebSocket events — Flask-SocketIO

Namespace: `/sentinel`

### Server → Client (emitted by backend)

| Event | Payload | Trigger |
|-------|---------|---------|
| `alert:new` | Alert object | New alert created by any detector |
| `device:update` | DeviceSnapshot dict | Device snapshot refreshed (every 15 s) |
| `device:joined` | DeviceSnapshot dict | New device seen for first time |
| `port:update` | PortStats dict | Port stats refreshed |
| `wan:status` | `{"status": "UP"\|"DOWN"}` | WAN state change |
| `feed:refresh` | Feed name + timestamp | Threat feed successfully refreshed |
| `ml:trained` | `{"mac": "...", "samples": 100}` | ML model trained for a device |

### Client → Server

| Event | Payload | Action |
|-------|---------|--------|
| `subscribe:device` | `{"mac": "..."}` | Subscribe to updates for a specific device |
| `unsubscribe:device` | `{"mac": "..."}` | Unsubscribe |

## WebSocket emit helpers — `sentinel/api/websocket.py`

```python
from sentinel.api.app import socketio

def emit_alert(alert: dict):
    socketio.emit('alert:new', alert, namespace='/sentinel')

def emit_device_update(device: dict):
    socketio.emit('device:update', device, namespace='/sentinel')

def emit_port_update(port: dict):
    socketio.emit('port:update', port, namespace='/sentinel')

def emit_wan_status(status: str):
    socketio.emit('wan:status', {'status': status}, namespace='/sentinel')
```

## Configuration — `sentinel/config.py`

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Router
    ROUTER_ADAPTER: str = 'sagemcom'
    ROUTER_IP: str = ''              # blank = auto-discover
    ROUTER_PORT: int = 80
    ROUTER_USERNAME: str = 'admin'
    ROUTER_PASSWORD: str = ''        # loaded from Docker secret
    POLL_INTERVAL_SECONDS: int = 15

    # Database
    DATABASE_URL: str = 'postgresql+asyncpg://sentinel:pass@postgres/sentinel'

    # Redis
    REDIS_URL: str = 'redis://redis:6379'

    # JWT
    JWT_SECRET_KEY: str = ''         # loaded from Docker secret
    JWT_ACCESS_TOKEN_EXPIRES: int = 900    # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES: int = 604800  # 7 days

    # ML
    ML_MIN_SAMPLES_TO_TRAIN: int = 100
    ML_CONTAMINATION: float = 0.05
    ML_RETRAIN_CRON: str = '0 3 * * *'   # 03:00 daily

    # Security services
    OTX_API_KEY: str = ''            # loaded from Docker secret
    SNIFF_IFACE: str = 'eth0'
    NMAP_SCAN_CRON: str = '0 2 * * *'  # 02:00 daily

    # Notifications
    NTFY_URL: str = ''               # e.g. https://ntfy.sh/heimdall-alerts
    SMTP_HOST: str = ''
    SMTP_FROM: str = ''

    class Config:
        env_file = '.env'
```
