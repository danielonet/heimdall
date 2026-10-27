---
title: Threats
description: Threat-intelligence feeds and IP lookups.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


- **Threat intel feeds:** whether each feed (Feodo Tracker, Tor exit nodes, Spamhaus DROP, URLhaus) has loaded, and when.
- **abuse.ch Auth-Key:** the URLhaus feed needs a free key from abuse.ch. Paste it here and save. Until then you can import a URLhaus CSV instead.
- **IP reputation lookup:** type an address to see whether it is **MALICIOUS** or **CLEAN**. This sends that one address to the lookup service (AlienVault OTX), and needs an OTX key.
