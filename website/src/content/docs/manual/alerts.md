---
title: Alerts
description: Reading, filtering and clearing alerts.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


Alerts are grouped by device and type. For each you can **acknowledge** (I have seen it) or **resolve** (it is dealt with), singly or in bulk.

- Filter by severity, type and time range. The histogram shows when alerts happened.
- **Download CSV** exports exactly the alerts that match your current filters, for your records.
- Some alerts carry a note: a *mitigation* hint, or whether a remote address is internal, verified clean, or known malicious.
- **Clear alerts…** deletes alerts and asks you to confirm first.

Severities: **CRITICAL**, **WARNING**, **INFO**. For what each alert type means, see the [Security pages](/security/).
