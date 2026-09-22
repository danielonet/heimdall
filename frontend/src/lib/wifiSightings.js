// Shared "is this sighting still worth showing as a nearby, unaccounted-for
// device" logic — used by both the WIFI tab's NEARBY WIFI DEVICES table and
// the Network Map's NOT ASSOCIATED sector, so the two views can't quietly
// drift apart into disagreeing about which devices count as "nearby".

// A device this long out of earshot (no probe request heard) is treated as
// out of range — requested directly: these views are meant to read as
// "who's actually around right now", not a permanent log of everything ever
// overheard (that history still lives in the database — a WifiSighting row
// is never touched by this, only what's rendered is filtered). Kept well
// above useWifiSightings' 15s poll interval so a device isn't flickered off
// the list by one missed poll.
export const OUT_OF_RANGE_AFTER_MS = 60_000

export function isSightingInRange(sighting, now) {
  return now - new Date(sighting.last_seen).getTime() <= OUT_OF_RANGE_AFTER_MS
}

// True if this sighting is already represented some other way and
// shouldn't also show up as an unidentified "nearby" device: it's the exact
// MAC of a device Heimdall already tracks, it's a "probable" OUI match
// (same manufacturer prefix as a known device — the WiFi radio of a machine
// you already know, most often one connected by cable with its WiFi just
// left on), or it's been hand-marked as belonging to the household (is_mine,
// see the WIFI tab's MARK AS MINE button). Requested directly: a wired
// device's WiFi radio was showing up as an unassociated "nearby" node on
// the map and as an unaccounted-for row on the WIFI tab, even though it's
// plainly a device you already own — a "probable" match is still a guess
// (see routes/wifi.py:_match_known_device), so the WIFI tab still labels it
// as one rather than asserting it outright, but it no longer reads as a
// stranger.
export function isSightingAccountedFor(sighting) {
  return sighting.is_mine || Boolean(sighting.known_device)
}

export function visibleSightings(sightings, now) {
  return (sightings || []).filter((s) => isSightingInRange(s, now) && !isSightingAccountedFor(s))
}
