"""Managed-switch monitoring: per-port counters and the MAC table, turned into per-device traffic.

Layout (docs/router-and-switch-expansion-plan.md, Part 2):

    drivers (web/, later snmp/)  ->  SwitchSnapshot  ->  core/ (deltas, attribution)  ->  store

Only this package talks to a switch. A driver returns facts and nothing else; everything that is the same
for every switch (counter deltas, which device a port belongs to, direction, scheduling, storage) is in core/.
"""
