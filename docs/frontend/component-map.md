# React Component Map

Tech stack: **React 19 + Vite + Tailwind CSS**

State: **Zustand** (global), **TanStack Query** (server state)
Real-time: **socket.io-client** (namespace `/sentinel`)
Charts: **Recharts**
Tables: **TanStack Table**
Network graph: **React Flow**

---

## Application shell

```
App
├── AuthGuard              — redirects to /login if no valid JWT
├── Layout
│   ├── Sidebar            — desktop: fixed left nav (220px)
│   ├── TopBar             — breadcrumb, live status pills, clock
│   ├── BottomNav          — mobile only: 5-tab bottom bar
│   └── <Outlet>           — page content
└── SocketProvider         — initialises socket.io, exposes context
```

## Pages / routes

| Route | Component | Description |
|-------|-----------|-------------|
| `/login` | `LoginPage` | Username + password, JWT fetch |
| `/` | `DashboardPage` | Main overview — metrics, alerts, traffic |
| `/devices` | `DevicesPage` | Full device list with filters |
| `/devices/:mac` | `DeviceDetailPage` | Per-device deep dive |
| `/alerts` | `AlertsPage` | Alert history with filters |
| `/ports` | `PortsPage` | PHY1–5 port status and history |
| `/threats` | `ThreatIntelPage` | Feed status, IP lookup |
| `/rules` | `RulesPage` | Rule list + editor |
| `/settings` | `SettingsPage` | Config, notifications, router info |

---

## Dashboard page components

```
DashboardPage
├── MetricStrip
│   ├── MetricCard (devices online)
│   ├── MetricCard (active alerts)
│   ├── MetricCard (threat score)
│   └── MetricCard (DNS blocked)
├── CriticalAlertBanner     — shown only when CRITICAL alerts exist
├── TrafficBarChart         — top-6 devices by throughput (Recharts)
├── DeviceTable (compact)   — 6-row preview, links to /devices
├── AlertFeed               — last 6 events, live updates via socket
├── ServiceStatusPanel      — XMO/Suricata/Pi-hole/Nmap/ClamAV status
└── PortSummary             — PHY1–5 status tiles
```

## Device list components

```
DevicesPage
├── DeviceFilters           — online/offline, WiFi/wired, trusted/suspect
├── DeviceSearch            — hostname / IP / MAC filter
└── DeviceTable (full)
    └── DeviceRow (per device)
        ├── StatusDot
        ├── DeviceIcon      — phone/laptop/camera/router/unknown
        ├── DeviceName + IP
        ├── TrafficDisplay  — see below
        ├── SignalStrength  — dBm bar (WiFi only)
        ├── InterfaceBadge  — WiFi | ETH
        └── BlockButton
```

### TrafficDisplay component

```jsx
// Must respect TrafficGranularity — see wired-monitoring-caveat.md
const TrafficDisplay = ({ sample }) => {
  if (sample.granularity === 'per_port') {
    return (
      <span>
        {formatMbps(sample.throughput_up_kbps)} ↑
        {formatMbps(sample.throughput_dn_kbps)} ↓
        <Badge variant="warning" title="Port 5 aggregate — not per-device">
          PORT TOTAL
        </Badge>
      </span>
    )
  }
  return (
    <span>
      {formatMbps(sample.throughput_up_kbps)} ↑
      {formatMbps(sample.throughput_dn_kbps)} ↓
    </span>
  )
}
```

## Device detail page components

```
DeviceDetailPage
├── DeviceHeader            — hostname, MAC, IP, vendor, OS, tags
├── BlockUnblockButton
├── TrafficTimelineChart    — 24h throughput sparkline (Recharts)
├── AnomalyScoreChart       — ML score over time
├── OpenPortsPanel          — from last Nmap scan
├── AlertHistoryTable       — alerts for this device
├── DnsQueryTable           — Pi-hole queries for this device
└── WiredPortNote           — shown for PER_PORT devices with caveat
```

## Alerts page components

```
AlertsPage
├── AlertFilters            — severity, device, date range, acknowledged
├── AlertHistogram          — 24h alert frequency bar chart (Recharts)
└── AlertTable
    └── AlertRow
        ├── SeverityBar     — 3px left strip: red/amber/blue
        ├── AlertType + Description
        ├── DeviceLink
        ├── Timestamp
        └── AckResolveButtons
```

## Port topology page components

```
PortsPage
└── PortGrid
    └── PortCard (× 5, PHY1–PHY5)
        ├── PortStatusBadge  — UP (green) | DOWN (muted)
        ├── LinkSpeedDisplay — "100 Mbps FULL"
        ├── ThroughputMini   — up/down arrows with Kbps
        ├── ErrorCounter     — errors + discards
        └── ShowMoreToggle   — expanded: full stats table + sparkline
```

## Rules page components

```
RulesPage
├── RuleList
│   └── RuleRow
│       ├── RuleName
│       ├── ActionBadge      — BLOCK | ALERT | NOTIFY | TAG
│       ├── EnableToggle
│       └── EditDeleteButtons
└── RuleEditor (modal)
    ├── NameInput
    ├── TriggerSelect        — TRAFFIC_SAMPLE | DEVICE_SNAPSHOT | PORT_STATS
    ├── ConditionBuilder     — field + operator + value + window
    ├── ActionBuilder        — action type + severity + notify
    └── TestRunButton        — dry-run against last 100 samples
```

## Shared components

| Component | Description |
|-----------|-------------|
| `StatusDot` | 7px circle with optional glow — green/amber/red/muted |
| `Badge` | Small pill — variant: `success \| warning \| danger \| info \| port` |
| `MetricCard` | Large number + label + sub-label, colour-coded |
| `SeverityBar` | 3px left border strip — red/amber/blue/green |
| `BlockButton` | Red bordered button — issues POST /api/devices/:mac/block |
| `UnblockButton` | Green bordered button |
| `LiveIndicator` | Pulsing dot + "LIVE" text |
| `TimeAgo` | Relative timestamp: "3m ago", "just now" |
| `MacAddress` | Monospace MAC with vendor tooltip |
| `ThroughputArrows` | `↑ 2.1 MB/s  ↓ 8.4 MB/s` formatted display |

## WebSocket integration

```jsx
// hooks/useSocket.js
import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { socket } from '../lib/socket'

export function useSocketEvents() {
  const qc = useQueryClient()

  useEffect(() => {
    socket.on('alert:new',      (a) => qc.invalidateQueries(['alerts']))
    socket.on('device:update',  (d) => qc.setQueryData(['device', d.mac_address], d))
    socket.on('device:joined',  (d) => qc.invalidateQueries(['devices']))
    socket.on('port:update',    (p) => qc.setQueryData(['port', p.port_alias], p))
    socket.on('wan:status',     (w) => qc.setQueryData(['wan'], w))
    return () => socket.removeAllListeners()
  }, [qc])
}
```
