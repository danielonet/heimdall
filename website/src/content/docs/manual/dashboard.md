---
title: Dashboard
description: The overview page.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


The first page after you sign in.

- **Unacknowledged alerts.** A feed of alerts nobody has acknowledged yet. Alerts older than the *stale after* setting are left out (see [Settings](/manual/settings/)). Click one to see it in the detail panel.
- **Critical banner.** If any alert is CRITICAL it is shown prominently.
- **Traffic.** The busiest devices by throughput. Wired devices show a **PORT TOTAL** badge: the router only counts bytes per port, so that figure is the port's total, not that one device's traffic.
- **Port summary.** The router's physical ports at a glance. See [Ports](/manual/ports/).
- **Services.** Whether Heimdall's own parts (PostgreSQL, Redis and the security sensors) are healthy, with version, database size, memory used and the time of the last alert.

An alert's colour in the services panel stays on until the alert is **resolved**, not merely acknowledged.
