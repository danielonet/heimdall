"""WanBandwidthDetector — flags household WAN throughput that's a
statistical outlier relative to its own recent history.

Not a BaseDetector subclass — that interface is per-device-shaped
(inspect_traffic(sample, snapshot)), and a household total has no device to
key on or auto-block. A small standalone class instead, called directly
from poll_cycle() alongside the per-device detection pipeline; its Alert
(device_mac=None) is added straight into poll_cycle's existing alerts list,
the same way DetectionPipeline-produced alerts already flow into that list.
"""
from __future__ import annotations

import statistics
from collections import deque
from typing import Optional

from sentinel.adapter.models import WanStats
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository

WINDOW_SIZE = 20  # ~5 minutes of history at the default 15s poll interval
MIN_SAMPLES = 10  # don't judge "abnormal" against too short a baseline
STDDEV_MULTIPLIER = 3.0
SUSTAINED_POLLS = 2
_ALERT_TYPE = 'WAN_BANDWIDTH_SPIKE'


class WanBandwidthDetector:
    """Flags total (up+down) WAN throughput more than STDDEV_MULTIPLIER
    standard deviations above the rolling mean of the last WINDOW_SIZE
    polls, sustained for SUSTAINED_POLLS in a row — same streak shape as
    HighUploadDetector, with an adaptive rather than fixed threshold: a
    fixed Mbps number would need hand-tuning per household's actual ISP
    plan, while a rolling baseline adapts automatically and needs no new
    admin-configurable setting. Deduped via AlertRepository.upsert() (see
    poll_cycle) rather than a cooldown timer — a still-elevated household
    total just bumps the same open row's occurrence_count; resolve() fires
    the moment throughput drops back under threshold.
    """

    def __init__(self) -> None:
        self._history: deque[int] = deque(maxlen=WINDOW_SIZE)
        self._consecutive_high = 0
        self._alert_open = False

    async def inspect(self, wan_sample: WanStats) -> Optional[Alert]:
        total_kbps = wan_sample.throughput_up_kbps + wan_sample.throughput_dn_kbps

        if len(self._history) < MIN_SAMPLES:
            self._history.append(total_kbps)
            return None

        mean = statistics.mean(self._history)
        stdev = statistics.pstdev(self._history)
        self._history.append(total_kbps)

        threshold = mean + STDDEV_MULTIPLIER * stdev
        if stdev == 0 or total_kbps <= threshold:
            self._consecutive_high = 0
            if self._alert_open:
                await AlertRepository().resolve(device_mac=None, alert_type=_ALERT_TYPE)
                self._alert_open = False
            return None

        self._consecutive_high += 1
        if self._consecutive_high < SUSTAINED_POLLS:
            return None  # matched, but not sustained long enough yet
        self._consecutive_high = 0  # reset so we don't alert every poll
        self._alert_open = True

        return Alert(
            device_mac=None,
            alert_type='WAN_BANDWIDTH_SPIKE',
            severity='WARNING',
            description=(
                f'Household WAN throughput ({total_kbps} kbps) is well above its recent '
                f'baseline (~{int(mean)} kbps avg) for {SUSTAINED_POLLS} consecutive polls'
            ),
            raw_data={
                'total_kbps': total_kbps,
                'baseline_mean_kbps': int(mean),
                'baseline_stdev_kbps': int(stdev),
            },
        )
