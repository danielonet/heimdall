"""Pure unit tests for evaluate_condition() — no DB, no adapter, no notifier."""
from dataclasses import dataclass

from sentinel.detection.rules_engine import evaluate_condition


@dataclass
class _Obj:
    throughput_up_kbps: int = 0
    hostname: str = ''
    tags: list = None


class TestOperators:
    def test_gt_true(self):
        matched, actual = evaluate_condition({'field': 'throughput_up_kbps', 'op': 'GT', 'value': 100}, _Obj(throughput_up_kbps=200))
        assert matched is True
        assert actual == 200

    def test_gt_false(self):
        matched, _ = evaluate_condition({'field': 'throughput_up_kbps', 'op': 'GT', 'value': 100}, _Obj(throughput_up_kbps=50))
        assert matched is False

    def test_lt(self):
        matched, _ = evaluate_condition({'field': 'throughput_up_kbps', 'op': 'LT', 'value': 100}, _Obj(throughput_up_kbps=50))
        assert matched is True

    def test_gte_equal_matches(self):
        matched, _ = evaluate_condition({'field': 'throughput_up_kbps', 'op': 'GTE', 'value': 100}, _Obj(throughput_up_kbps=100))
        assert matched is True

    def test_lte_equal_matches(self):
        matched, _ = evaluate_condition({'field': 'throughput_up_kbps', 'op': 'LTE', 'value': 100}, _Obj(throughput_up_kbps=100))
        assert matched is True

    def test_eq(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'EQ', 'value': 'nas'}, _Obj(hostname='nas'))
        assert matched is True

    def test_neq(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'NEQ', 'value': 'nas'}, _Obj(hostname='printer'))
        assert matched is True

    def test_contains(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'CONTAINS', 'value': 'cam'}, _Obj(hostname='front-camera'))
        assert matched is True

    def test_contains_false(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'CONTAINS', 'value': 'cam'}, _Obj(hostname='printer'))
        assert matched is False

    def test_in(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'IN', 'value': ['nas', 'printer']}, _Obj(hostname='nas'))
        assert matched is True

    def test_in_false(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'IN', 'value': ['nas', 'printer']}, _Obj(hostname='laptop'))
        assert matched is False


class TestEdgeCases:
    def test_unknown_field_returns_none_actual(self):
        matched, actual = evaluate_condition({'field': 'nonexistent', 'op': 'GT', 'value': 1}, _Obj())
        assert matched is False
        assert actual is None

    def test_unknown_operator_no_match(self):
        matched, _ = evaluate_condition({'field': 'throughput_up_kbps', 'op': 'WAT', 'value': 1}, _Obj(throughput_up_kbps=5))
        assert matched is False

    def test_gt_on_none_field_no_crash(self):
        matched, actual = evaluate_condition({'field': 'missing', 'op': 'GT', 'value': 100}, _Obj())
        assert matched is False
        assert actual is None

    def test_type_mismatch_does_not_raise(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'GT', 'value': 100}, _Obj(hostname='abc'))
        assert matched is False

    def test_in_with_empty_list(self):
        matched, _ = evaluate_condition({'field': 'hostname', 'op': 'IN', 'value': []}, _Obj(hostname='abc'))
        assert matched is False
