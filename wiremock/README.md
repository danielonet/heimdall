# WireMock Stubs for Sagemcom Router Simulator

This directory contains WireMock stub mappings that simulate a Sagemcom F@st 5670 router's XMO JSON API responses. Use this for **offline development and testing** when the physical router is unavailable.

## Structure

```
wiremock/
├── README.md                    ← you are here
├── __files__/                   ← response body templates
│   ├── device_list.json        ← connected devices
│   ├── port_stats.json         ← Ethernet port statistics
│   └── router_info.json        ← router metadata
└── mappings/                    ← request→response mappings
    ├── login.json              ← XMO session establishment
    └── queries.json            ← getValue/getValues queries
```

## How It Works

The mock router adapter (`sentinel/adapter/mock/mock_adapter.py`) returns synthetic data **directly** without making HTTP calls. If you want to use WireMock instead to test against actual XMO API-shaped responses, set `USE_WIREMOCK=true` to redirect the XMO client to WireMock.

## Enabling Mock Mode

### Option 1: Use the Direct Mock Adapter (Recommended for Development)

Fastest for offline development:

```bash
export USE_MOCK_ROUTER=true
# Flask API will use synthetic test data directly
```

### Option 2: Use WireMock HTTP Server (Advanced)

For testing against realistic XMO API response formats:

```bash
# Start WireMock container (see docker-compose.yml)
docker-compose up wiremock -d

# Redirect the XMO client to WireMock
export USE_MOCK_ROUTER=false
export ROUTER_IP=wiremock
export ROUTER_PORT=8080

# Now the Sagemcom adapter connects to WireMock instead of a real router
```

WireMock listens on `:8080` and the real Sagemcom adapter will make HTTP calls against these stubs.

## Recording Real Traffic

To populate these stubs with real data from your actual router:

```bash
# With real router running and accessible:
docker-compose up wiremock -d

# Enable WireMock recording mode (via admin endpoint)
curl -X POST http://localhost:8080/__admin/recordings/start

# Run your Sagemcom adapter normally
export USE_MOCK_ROUTER=false
export ROUTER_IP=192.168.1.1
# ... run the app ...

# Stop recording
curl -X POST http://localhost:8080/__admin/recordings/stop

# Recordings saved to wiremock/mappings/ automatically
```

See: [WireMock Recording](https://wiremock.org/docs/record-playback/)

## XMO API Endpoints Being Mocked

The XMO API is a POST-only protocol:

| Request | Purpose |
|---------|---------|
| `POST /cgi/json-req` (login envelope) | Establish session |
| `POST /cgi/json-req` (getValue "Device/Hosts/Host") | List connected devices |
| `POST /cgi/json-req` (getValue "Device/Ethernet/Interfaces/...") | Port statistics |
| `POST /cgi/json-req` (getValue "Device/DeviceInfo") | Router metadata |
| `POST /cgi/json-req` (addObject firewall chain) | Block device by MAC |
| `POST /cgi/json-req` (deleteObject firewall rule) | Unblock device |

All requests are URL-encoded JSON wrapped in `req=<JSON>`.

## Status

- ✅ Mock adapter fully functional
- ⏳ WireMock stubs (see templates in `__files__/`)
- ⏳ Recording script for real router traffic

