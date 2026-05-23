# Wired Device Monitoring — The Port-vs-Device Problem

## The problem

The Sagemcom XMO API provides traffic statistics at two different granularities:

**WiFi devices** — `Device/Hosts/Host` returns `BytesSent` and `BytesReceived`
per individual device MAC address. Each client's traffic is measured independently
by the router's wireless subsystem.

**Wired devices** — `Device/Ethernet/Interfaces/Interface[Alias="PHY5"]/Stats`
returns `BytesSent` and `BytesReceived` for the **entire physical port**.
If multiple wired devices connect via a downstream switch to Port 5, all their
traffic is aggregated into a single counter. The router cannot distinguish
individual devices behind the switch.

## Your specific situation

Port 5 (PHY5) has two devices connected via a downstream switch:
- `Akuvox-R20K` — door intercom (10.100.102.12)
- `0c:11:05:a6:b6:18` — Ringslink device (10.100.102.25)

The Port 5 cumulative counters (46.43 GB sent, 3.32 GB received) are the
**combined total** for both devices. There is no way to split this between them
using the router API alone.

## How the adapter handles this

The `TrafficGranularity` enum marks samples correctly:

```python
class TrafficGranularity(Enum):
    PER_DEVICE = 'per_device'   # WiFi: accurate per-device measurement
    PER_PORT   = 'per_port'     # Wired: port aggregate only
```

Wired `TrafficSample` objects carry:
- `granularity = TrafficGranularity.PER_PORT`
- `port_alias = 'PHY5'`
- `bytes_sent_delta` / `bytes_recv_delta` = port-level total (shared)

## UI rules — how to display wired devices

1. **Never show per-device traffic numbers** for wired devices without a caveat
2. Show a **"PORT TOTAL"** badge on wired device traffic figures
3. Tooltip: *"Traffic shown is the combined total for all devices on Port 5.
   Individual device traffic is not available from the router API."*
4. On the port detail panel, show: *"Port 5 total: X MB/s (shared by 2 wired devices)"*

## Anomaly detection rules for wired devices

- Do **not** run `AnomalousVolumeDetector` per-device for wired devices
- Run it against the **port aggregate** (PHY5 total) instead
- Do **not** run `HighUploadDetector` per-device for the same reason
- **Blocking still works** — `block_device(mac)` uses the Firewall API which
  is MAC-based, not port-based

## Future improvement

If per-device wired traffic is needed, place the monitoring machine **inline
between the router and the downstream switch** (transparent bridge with two NICs).
Zeek running on that bridge will see each wired device's traffic independently,
completely bypassing the router API limitation.
