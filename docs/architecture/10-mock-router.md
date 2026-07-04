# Mock Router Adapter for Offline Development

When the physical router is unavailable, use Heimdall's **mock Sagemcom adapter** to continue testing the detection pipeline, ML engine, frontend, and API without network access to the real modem.

## Quick Start

### Enable Mock Mode

```bash
export USE_MOCK_ROUTER=true
docker-compose up sentinel-backend
```

The backend will now poll synthetic traffic data instead of querying the real router.

### Configuration Flag

In your `.env` or environment:

```bash
# Development: Use mock adapter (synthetic test data)
USE_MOCK_ROUTER=true

# Production: Connect to real router
USE_MOCK_ROUTER=false
```

This flag is checked in [sentinel/adapter/factory.py](sentinel/adapter/factory.py) during app initialization.

## What the Mock Adapter Provides

The mock adapter returns realistic, dynamically-generated data:

### Connected Devices (4 WiFi + 2 Wired)

```python
# WiFi devices with realistic signal strength variations
[
  # daniel-laptop (-45 dBm, 300 Mbps)
  # living-room-ipad (-68 dBm, 130 Mbps)
  # kitchen-speaker (-72 dBm, 72 Mbps)
  # guest-phone (offline)
  
  # Wired devices
  # nas-nas-01 (1 Gbps)
  # office-printer (100 Mbps)
]
```

### Traffic Patterns

Per-device traffic is simulated with realistic distributions:

| Pattern | % Chance | Bytes/Sample |
|---------|----------|-------------|
| Idle (browsing paused) | 40% | ~5 KB |
| Normal browsing | 40% | ~50 KB |
| Streaming | 15% | ~500 KB |
| Spike (download) | 5% | ~1 MB |

### Port Statistics (PHY1–PHY5)

```python
# PHY1: 1 Gbps wired (UP)
# PHY2: 100 Mbps wired (UP)
# PHY3, PHY4: DOWN
# PHY5: 100 Mbps wired (UP)
```

### Router Info

Returns metadata identifying itself as mock:

```json
{
  "model": "Sagemcom F@st 5670 (Mock)",
  "firmware": "TELNET_SE_17.06.12_AUPV5.6_27_Release",
  "serial": "6A1F2B3C4D5E"
}
```

### Device Blocking

Simulates MAC-based firewall rules:

```python
adapter.block_device('a8:5e:60:f1:2c:3d')    # ✓ device blocked
adapter.get_connected_devices()               # device still appears (offline)
adapter.unblock_device('a8:5e:60:f1:2c:3d')  # ✓ device unblocked
```

## Architecture

### Adapter Initialization

The adapter factory automatically chooses the correct implementation:

```python
# sentinel/adapter/factory.py
async def create_router_adapter() -> RouterAdapter:
    if settings.USE_MOCK_ROUTER:
        return MockSagemcomAdapter()  # Synthetic data
    else:
        return SagemcomXmoAdapter(...)  # Real router
```

### Mock Adapter Code

[sentinel/adapter/mock/mock_adapter.py](sentinel/adapter/mock/mock_adapter.py) implements the `RouterAdapter` interface. No other part of the system knows it's synthetic — the rest of Heimdall sees standard device snapshots, traffic samples, and port stats.

## Advanced: Recording Real Traffic with WireMock

If you want to **test against actual XMO API response formats** recorded from a real router:

### 1. Set Up WireMock

```bash
# In docker-compose.yml, uncomment or add wiremock service
docker-compose up wiremock -d
```

### 2. Record Real Traffic

```bash
# Start WireMock in record mode
curl -X POST http://localhost:8080/__admin/recordings/start

# Point the Sagemcom adapter to your real router
# (your adapter will proxy through WireMock)
export ROUTER_IP=192.168.1.1
export ROUTER_PORT=80

# Run Heimdall for a few minutes to capture traffic
docker-compose up sentinel-backend

# Stop recording
curl -X POST http://localhost:8080/__admin/recordings/stop

# Stubs saved to wiremock/mappings/
```

### 3. Replay Captured Traffic

Later, use the recorded stubs without the real router:

```bash
# Start WireMock with captured stubs
docker-compose up wiremock -d

# Point adapter to WireMock instead of real router
export USE_MOCK_ROUTER=false
export ROUTER_IP=wiremock
export ROUTER_PORT=8080

docker-compose up sentinel-backend
```

See [wiremock/README.md](wiremock/README.md) for details.

## Testing Scenarios

### 1. Test Detection Pipeline Offline

```bash
# Scenario: laptop generates suspicious traffic spike
USE_MOCK_ROUTER=true docker-compose up sentinel-backend

# Backend polls mock adapter → ML detects anomaly → frontend receives alert
```

### 2. Test Frontend Without Backend

```bash
# Frontend dev server (Vite)
cd frontend
npm run dev

# Backend (mock mode)
cd ..
USE_MOCK_ROUTER=true python -m sentinel.api.app

# Frontend connects to localhost:5000, receives synthetic data
```

### 3. Test Your Detection Rules

Create new threat detectors and verify them against predictable synthetic traffic:

```python
# tests/test_detectors/test_my_detector.py
from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.detection.detectors.my_detector import MyDetector

@pytest.mark.asyncio
async def test_detector_on_mock_data():
    adapter = MockSagemcomAdapter()
    devices = await adapter.get_connected_devices()
    samples = await adapter.get_traffic_samples()
    
    detector = MyDetector()
    threats = detector.analyze(devices, samples)
    assert len(threats) > 0
```

## Disabling Mock Mode

To return to production (real router):

```bash
# Either unset the flag:
unset USE_MOCK_ROUTER

# Or explicitly set it to false:
export USE_MOCK_ROUTER=false
export ROUTER_IP=192.168.1.1
export ROUTER_PASSWORD=your_admin_password

docker-compose up sentinel-backend
```

If auto-discovery is enabled, the adapter will find the router's IP automatically.

## Troubleshooting

### ❌ "MockSagemcomAdapter initialized" appears in logs but I want real router

Check:
```bash
echo $USE_MOCK_ROUTER    # Should be empty or "false"
```

### ❌ Mock adapter missing a device or port

The synthetic data is defined in [sentinel/adapter/mock/mock_adapter.py](sentinel/adapter/mock/mock_adapter.py) — edit `_generate_mock_devices()` or `_generate_mock_port_stats()`.

### ❌ Traffic patterns unrealistic

Edit the traffic simulation logic in `get_traffic_samples()` to adjust the distribution weights or byte ranges.

## File Reference

| File | Purpose |
|------|---------|
| [sentinel/adapter/mock/mock_adapter.py](sentinel/adapter/mock/mock_adapter.py) | Mock adapter implementation |
| [sentinel/adapter/factory.py](sentinel/adapter/factory.py) | Adapter factory (chooses mock vs real) |
| [sentinel/config.py](sentinel/config.py) | `USE_MOCK_ROUTER` setting |
| [wiremock/](wiremock/) | WireMock stubs & configuration (optional advanced usage) |
| [tests/](tests/) | Unit tests for adapter implementations |

