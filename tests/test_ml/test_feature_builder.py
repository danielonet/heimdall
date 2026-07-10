from datetime import datetime, timezone

from sentinel.adapter.models import TrafficGranularity, TrafficSample
from sentinel.ml.feature_builder import FEATURE_NAMES, build_feature_vector


def _sample(ts: datetime, up: int = 100, down: int = 200) -> TrafficSample:
    return TrafficSample(
        mac_address='aa:bb:cc:dd:ee:ff',
        timestamp=ts,
        throughput_up_kbps=up,
        throughput_dn_kbps=down,
        granularity=TrafficGranularity.PER_DEVICE,
    )


class TestBuildFeatureVector:
    def test_vector_length_matches_feature_names(self):
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)))
        assert len(vec) == len(FEATURE_NAMES) == 6

    def test_throughput_fields_pass_through(self):
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc), up=500, down=1000))
        assert vec[0] == 500
        assert vec[1] == 1000

    def test_ratio_computed_correctly(self):
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc), up=300, down=100))
        assert vec[2] == 3.0

    def test_ratio_avoids_division_by_zero(self):
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc), up=300, down=0))
        assert vec[2] == 300.0  # down treated as max(down, 1)

    def test_hour_and_weekday(self):
        # 2026-01-05 is a Monday
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 14, 30, tzinfo=timezone.utc)))
        assert vec[3] == 14
        assert vec[4] == 0  # Monday

    def test_is_night_true_late(self):
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 23, 0, tzinfo=timezone.utc)))
        assert vec[5] == 1

    def test_is_night_true_early(self):
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 3, 0, tzinfo=timezone.utc)))
        assert vec[5] == 1

    def test_is_night_false_daytime(self):
        vec = build_feature_vector(_sample(datetime(2026, 1, 5, 14, 0, tzinfo=timezone.utc)))
        assert vec[5] == 0
