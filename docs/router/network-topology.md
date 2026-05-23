# Network Topology

Your specific home LAN layout as observed from DHCP leases, ARP table,
and LAN port statistics.

## Router

| Field | Value |
|-------|-------|
| Model | Sagemcom F@st 5670 |
| IP | 10.100.102.1 |
| Subnet | 10.100.102.0/24 |
| WAN MAC | C4:EB:42:F1:26:85 |
| Firmware | SGFg12000116 |
| SSID (2.4GHz) | MyHomeWiFi |
| BSSID (2.4GHz) | C4:EB:42:94:80:4C |

## Physical port status

| Port | Alias | Status | Speed | Connected devices |
|------|-------|--------|-------|-------------------|
| Port 1 | PHY1 | DOWN | AUTO / HALF | None |
| Port 2 | PHY2 | DOWN | AUTO / HALF | None |
| Port 3 | PHY3 | DOWN | AUTO / FULL | None |
| Port 4 | PHY4 | DOWN | AUTO / FULL | None |
| Port 5 (2.5G) | PHY5 | **UP** | 100 Mbps / FULL | Akuvox-R20K + Ringslink device (via switch) |

> ⚠️ Ports 1–4 are all DOWN. Any transition to UP on these ports is an
> **immediate CRITICAL alert** (physical intrusion indicator).

## Network map

```
Sagemcom F@st 5670  (10.100.102.1)
│
├── Port 5 / PHY5 (2.5G, UP, 100 Mbps)
│   └── [Downstream switch]
│       ├── Akuvox-R20K            10.100.102.12  MAC: 0c:11:05:61:ad:5b
│       └── 0c:11:05:a6:b6:18     10.100.102.25  MAC: 0c:11:05:a6:b6:18
│           (Ringslink Xiamen — door/intercom system)
│
├── Ports 1–4 / PHY1–PHY4  (ALL DOWN)
│
└── WiFi (wl0=5GHz @ 907Mbps, wl1=2.4GHz @ 72Mbps)
    │
    ├── Redmi-Note-13-Pro-5G      10.100.102.10  MAC: da:d4:19:31:c0:e9
    ├── Redmi-Note-12-Pro-5G      10.100.102.6   MAC: 5a:86:56:72:cc:b8
    ├── Redmi-Note-14             10.100.102.7   MAC: 42:c9:a0:6a:bb:5d
    ├── DESKTOP-OFNIM7N           10.100.102.23  MAC: d0:39:57:3f:75:80
    ├── MiWiFi-RA67               10.100.102.17  MAC: 8c:de:f9:1a:5d:7e
    ├── Xiaomi                    10.100.102.15  MAC: 9c:9d:7e:14:0b:fe
    ├── daniel-Lenovo-V15-G4-AMN  10.100.102.22  MAC: 78:46:5c:98:69:4c
    ├── danielonnet-DP700A3D...   10.100.102.16  MAC: 50:b7:c3:b1:9e:57
    ├── chuangmi_camera_ipc019    10.100.102.20  MAC: 64:90:c1:6c:55:45  ⚠️
    ├── wlan0                     10.100.102.8   MAC: 38:a5:c9:05:9b:d4
    ├── f8:17:2d:b0:dd:cf         10.100.102.14  MAC: f8:17:2d:b0:dd:cf  (unknown)
    └── [ARP incomplete entries — recently seen, may be offline]
        ├── 10.100.102.9   MAC: a0:b3:39:de:75:75
        ├── 10.100.102.11  MAC: 28:00:af:48:e8:15
        └── 10.100.102.13  MAC: 62:91:37:6d:bc:c1
```

## Device notes

| Device | Notes |
|--------|-------|
| `chuangmi_camera_ipc019` | Chinese IoT camera — observed anomalous upload spike 1.4 MB/s. Monitor closely. |
| `MiWiFi-RA67` | Secondary router/AP on the network — unusual for a home LAN. DNS flagged. |
| `wlan0` | Generic hostname — device not advertising proper hostname. Unknown vendor. |
| `f8:17:2d:b0:dd:cf` | Unknown vendor — no hostname. New device — confirm identity. |
| `Akuvox-R20K` | Door intercom system. Wired to Port 5. Normal low-traffic device. |

## Wired devices — port monitoring only

Both `Akuvox-R20K` and `0c:11:05:a6:b6:18` share Port 5 (PHY5).
Their traffic cannot be individually measured from the router API alone.
See `docs/router/wired-monitoring-caveat.md`.
