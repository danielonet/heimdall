---
title: Threats
description: Threat-intelligence feeds and IP lookups.
---

- **Threat intel feeds:** one row per feed (Feodo Tracker, Spamhaus DROP, Tor exit nodes, URLhaus) with how many entries it holds, when it was last refreshed and where the data came from (for example "live feed"). A feed that has not loaded says "never refreshed".
- **abuse.ch Auth-Key:** the URLhaus feed needs a free key from abuse.ch. Paste it under the URLhaus row and press **Save key**. If you would rather wait, **choose CSV** imports a URLhaus export you already have, as a saved copy until a live refresh works. Once a key is saved the row says so and offers **remove**. If abuse.ch rejects the key the row says so, and you should check it was copied in full.
- **IP reputation lookup:** type an address and press **Lookup** to see whether it is **MALICIOUS** or **CLEAN**, whether it is in Heimdall's blocklists, and how many AlienVault OTX reports mention it. The blocklists work with no setup. The OTX count stays at 0 unless you have put an OTX key in `secrets/otx_api_key.txt`; with a key, the address you look up is sent to OTX.
