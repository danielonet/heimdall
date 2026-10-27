---
title: Alerts
description: Reading, filtering and clearing alerts.
---

The page opens in **Grouped** view, where repeated alerts of the same type on the same device are folded into one row showing how many times it fired, when it first happened and when it last did. Switch to **List** to see every alert on its own, with its full description, the device and time.

In List view you also get a 24-hour **alert frequency** chart and three filters:

- **Severity:** all, critical, warning or info.
- **Status:** all, open or acked.
- **Range:** 24 hours, 7 days (the default) or all time.

What you can do with an alert:

- **Acknowledge** means "I have seen it". **Resolve** means "it is dealt with". Both work on a single alert, and **Ack all** and **Resolve all** do a whole group. A resolved alert can be reopened.
- The **Actions** menu on an alert can also **snooze** it for an hour, a day or a week, cancel a snooze, and, for a port alert, add an exception so that port is allowed from then on (the same thing as the port allowlist on [Rules](/manual/rules/)).
- Some alerts carry a note: a *mitigation* hint, or whether a remote address is internal, verified clean, or known malicious.
- **Export CSV** downloads the alerts that match your current severity, status and range filters, for your records.
- **Clear alerts…** deletes alerts, and asks you to confirm first.

Severities are **CRITICAL**, **WARNING** and **INFO**. For what each alert type means, see the [Security pages](/security/).
