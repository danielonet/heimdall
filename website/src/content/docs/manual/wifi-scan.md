---
title: WiFi scan
description: Nearby WiFi devices and networks, and rogue access point detection.
---

This page lists what Heimdall hears over the air. It needs a **second WiFi adapter that supports monitor mode**, dedicated to listening: it cannot be the adapter that connects the Heimdall machine to your network. Pick it under **WiFi monitor** on [Settings](/manual/settings/). Until you do, both lists say so ("No sightings yet", "No networks heard yet") and nothing is overheard.

- **Nearby WiFi devices:** phones and laptops announcing themselves nearby, right now. A device drops off the list once it has not been heard for over a minute. A device you own can appear too (its radio is on even if it is plugged in by cable), and the status column says which is which. Markers show a device you marked as yours, or one that shares a manufacturer prefix with a device Heimdall already knows.
- **Nearby WiFi networks:** the routers and access points heard nearby, like the list your phone shows. One network often appears several times (2.4 GHz, 5 GHz, guest, mesh), one row per radio. Mark your own networks as **MINE** so the rogue access point check knows them.

## Rogue access points

If you give the monitor a list of **protected network names** and your own access points' real addresses (BSSIDs), Heimdall raises a **CRITICAL ROGUE_AP** alert when something that is not yours broadcasts one of those names, which is how an "evil twin" attack looks. It does not block anything: there is no device to block.

Be aware of the limits. It listens only on 2.4 GHz channels 1, 6 and 11 and not on 5 GHz, so it can miss an access point on another channel or band. It is off until you set it up, and it needs the extra adapter.
