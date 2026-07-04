# 🛡️ Heimdall Mock Router — Complete Setup Guide

## Overview

You can now develop Heimdall **completely offline** without access to your physical Sagemcom router. The mock adapter returns realistic synthetic network data that exercises your detection pipeline, ML engine, and frontend.

## Files Created/Modified

### New Files ✨

```
sentinel/adapter/mock/
├── __init__.py
└── mock_adapter.py           # Mock RouterAdapter implementation

sentinel/adapter/factory.py    # Adapter factory (chooses mock vs real)

docs/architecture/
└── 10-mock-router.md          # Full documentation

wiremock/
├── README.md                  # WireMock usage guide
├── mappings/
│   └── 01-hosts.json          # Example XMO API mapping
└── __files__/
    ├── device_list.json       # Mock response templates
    └── port_stats.json

.env.example                   # Configuration template (all settings documented)

scripts/mock-router-start.sh   # Quick start shell script
```

### Modified Files 🔄

| File | Change |
|------|--------|
| `sentinel/config.py` | Added `USE_MOCK_ROUTER: bool = False` |
| `docker-compose.yml` | Added `# - USE_MOCK_ROUTER=true` to sentinel-backend env, added commented WireMock service |
| `README.md` | Added "Offline Development" section |

## Quick Start (3 Steps)

### 1. Enable Mock Mode

```bash
export USE_MOCK_ROUTER=true
```

Or set it in your `.env`:
```bash
USE_MOCK_ROUTER=true
```

### 2. Start the Backend

```bash
docker-compose up -d sentinel-backend
```

Or use the helper script:
```bash
bash scripts/mock-router-start.sh
```

### 3. Access the Dashboard

```
http://localhost:3000
```

✅ **Done!** You're now polling synthetic router data with no real modem required.

## What You Get

### Mock Network (Preconfigured)

```
📱 WiFi Devices:
  • daniel-laptop         (-45 dBm, 300 Mbps)
  • living-room-ipad      (-68 dBm, 130 Mbps)
  • kitchen-speaker       (-72 dBm, 72 Mbps)
  • guest-phone (offline)

🔌 Wired Devices:
  • nas-nas-01 (1 Gbps, PHY1)
  • office-printer (100 Mbps, PHY2)
  • Unconnected: PHY3, PHY4
  • Unconnected: PHY5 (100 Mbps, available)
```

### Traffic Simulation

Every poll cycle generates **realistic traffic patterns**:

- **40%** of time: Idle (~5 KB/s) — device barely using network
- **40%** of time: Normal browsing (~50 KB/s) — web, email, messaging
- **15%** of time: Streaming (~500 KB/s) — video, music
- **5%** of time: Spike (~1 MB/s) — downloads, backups

### Device Management

- ✅ **Block/Unblock** devices by MAC (simulated firewall rules)
- ✅ **Query devices** returns list with dynamic signal strength
- ✅ **Port stats** include UP/DOWN status and byte counters
- ✅ **Router info** identifies itself as mock for testing

## Switching Between Modes

### Real Router (Production)

```bash
unset USE_MOCK_ROUTER
export ROUTER_IP=192.168.1.1
export ROUTER_PASSWORD=your_admin_password

docker-compose up -d sentinel-backend
```

Auto-discovery enabled (finds router from default route):
```bash
unset USE_MOCK_ROUTER
unset ROUTER_IP  # blank triggers auto-discovery
docker-compose up -d sentinel-backend
```

### Mock Mode (Development)

```bash
export USE_MOCK_ROUTER=true
docker-compose up -d sentinel-backend
```

## Testing Scenarios

### Scenario 1: Frontend Development Without Router

```bash
# Backend (mock mode)
export USE_MOCK_ROUTER=true
python -m sentinel.api.app:create_app

# Frontend (separate terminal)
cd frontend
npm run dev

# Visit http://localhost:5173
```

### Scenario 2: Test Your Detection Rules

```python
# tests/test_detectors/test_my_detector.py
from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.detection.detectors.my_detector import MyDetector

@pytest.mark.asyncio
async def test_detector_finds_anomalies():
    adapter = MockSagemcomAdapter()
    devices = await adapter.get_connected_devices()
    samples = await adapter.get_traffic_samples()
    
    detector = MyDetector()
    threats = detector.analyze(devices, samples)
    
    assert len(threats) > 0, "Detector should find anomalies in synthetic traffic"
```

### Scenario 3: Load Testing

Run multiple poll cycles with mock data:

```bash
# Mock mode doesn't require network — you can stress-test
# the database, Redis, and frontend without router latency
export USE_MOCK_ROUTER=true
docker-compose up -d

# Then hammer the API in another terminal
ab -n 1000 -c 10 http://localhost:5000/api/devices
```

## Advanced: Record Real Traffic (Optional)

For testing against **actual** XMO API response formats:

### Step 1: Start WireMock

```bash
# Uncomment wiremock service in docker-compose.yml, then:
docker-compose up wiremock -d
```

### Step 2: Record from Real Router

```bash
# Start recording mode
curl -X POST http://localhost:8080/__admin/recordings/start

# Point to your real router and run some traffic
export USE_MOCK_ROUTER=false
export ROUTER_IP=192.168.1.1
docker-compose up sentinel-backend

# Let it run for a few minutes, then stop
curl -X POST http://localhost:8080/__admin/recordings/stop
```

### Step 3: Replay Recordings (Offline)

```bash
# Now use WireMock recordings instead of real router
export USE_MOCK_ROUTER=false
export ROUTER_IP=wiremock
export ROUTER_PORT=8080

docker-compose up wiremock sentinel-backend
```

See [wiremock/README.md](wiremock/README.md) for full details.

## Customizing Mock Data

Edit [sentinel/adapter/mock/mock_adapter.py](sentinel/adapter/mock/mock_adapter.py):

### Add More Devices

```python
def _generate_mock_devices(self) -> List[DeviceSnapshot]:
    return [
        # ... existing devices ...
        DeviceSnapshot(
            mac_address='00:11:22:33:44:55',
            ip_address='192.168.0.99',
            hostname='my-custom-device',
            vendor_name='My Vendor',
            interface_name='WiFi',
            signal_strength_dbm=-50,
            signal_rate_mbps=200,
            is_online=True,
        ),
    ]
```

### Adjust Traffic Distribution

```python
async def get_traffic_samples(self) -> List[TrafficSample]:
    # ... in the WiFi device loop:
    weights = [0.2, 0.5, 0.2, 0.1]  # More browsing, less idle
    pattern = random.choices([...], weights=weights)[0]
```

### Change Port States

```python
def _generate_mock_port_stats(self) -> List[PortStats]:
    return [
        # PHY3 is usually DOWN, make it UP instead:
        PortStats(
            port_alias='PHY3',
            status='UP',  # Changed
            link_speed_mbps=1000,
            # ...
        ),
    ]
```

## Troubleshooting

### ❌ Logs show "Connecting to real router" but I want mock mode

**Issue:** `USE_MOCK_ROUTER` not set correctly

**Fix:**
```bash
# Check it's set
echo $USE_MOCK_ROUTER

# If empty, set it:
export USE_MOCK_ROUTER=true

# Or in .env file:
echo "USE_MOCK_ROUTER=true" >> .env
```

### ❌ Backend won't start, says "Mock adapter already connected"

**Issue:** Multiple instances running

**Fix:**
```bash
docker-compose down -v    # Remove volumes too
docker-compose up -d sentinel-backend
```

### ❌ Frontend not receiving device updates

**Issue:** WebSocket disconnected or routes not implemented yet

**Note:** The adapter factory is ready, but routes/scheduler integration is Phase 2. Mock data is being generated but routes may not be polling it yet.

**Check:** Look at `sentinel/api/routes/devices.py` — is it calling `get_connected_devices()`?

### ❌ Traffic patterns seem too uniform

**Fix:** Edit the distribution weights in `get_traffic_samples()` to increase variety:

```python
weights = [0.3, 0.3, 0.25, 0.15]  # More spikes
```

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/architecture/10-mock-router.md](docs/architecture/10-mock-router.md) | Complete mock adapter guide |
| [docs/architecture/02-router-adapter.md](docs/architecture/02-router-adapter.md) | Router adapter abstraction layer |
| [wiremock/README.md](wiremock/README.md) | WireMock HTTP stubbing (advanced) |
| `.env.example` | All configuration options documented |

## Architecture Overview

```
┌─ Adapter Factory (sentinel/adapter/factory.py)
│  ├─ USE_MOCK_ROUTER=true
│  │  └─> MockSagemcomAdapter (synthetic data)
│  └─ USE_MOCK_ROUTER=false
│     └─> SagemcomXmoAdapter (real XMO API)
│
└─> Both implement RouterAdapter interface
   ├─ get_connected_devices()
   ├─ get_traffic_samples()
   ├─ get_port_stats()
   ├─ block_device()
   ├─ unblock_device()
   └─ get_router_info()
```

The rest of Heimdall (detection pipeline, ML, frontend, API) only knows the `RouterAdapter` interface — switching between real and mock is transparent.

## Next Steps

1. ✅ Set `USE_MOCK_ROUTER=true` and test offline
2. ✅ Customize mock devices in [mock_adapter.py](sentinel/adapter/mock/mock_adapter.py)
3. ✅ Add your detection rules and test them against synthetic traffic
4. ✅ Record real router traffic with WireMock (optional)
5. 📋 When ready for production: Set `USE_MOCK_ROUTER=false` and provide real router credentials

---

**Questions?** See [docs/architecture/10-mock-router.md](docs/architecture/10-mock-router.md) or open an issue.
