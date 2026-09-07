from datetime import datetime, timezone

from sentinel.notifications.digest import (
    MAX_ALERT_TYPES, SEVERITY_RANK_TO_NAME, DigestTypeGroup, render_digest_html, render_digest_text,
)

_NOW = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
_CUTOFF = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


def _group(**overrides) -> DigestTypeGroup:
    defaults = dict(
        alert_type='ARP_SPOOF', severity='CRITICAL', count=1, device_count=1,
        latest_description='spoofing suspected', latest_created_at=_NOW,
    )
    defaults.update(overrides)
    return DigestTypeGroup(**defaults)


class TestSeverityRankToName:
    def test_covers_exactly_the_three_severities(self):
        assert set(SEVERITY_RANK_TO_NAME.values()) == {'CRITICAL', 'WARNING', 'INFO'}

    def test_higher_rank_is_more_severe(self):
        assert SEVERITY_RANK_TO_NAME[3] == 'CRITICAL'
        assert SEVERITY_RANK_TO_NAME[2] == 'WARNING'
        assert SEVERITY_RANK_TO_NAME[1] == 'INFO'


class TestRenderDigestText:
    def test_all_clear_when_total_is_zero(self):
        text = render_digest_text([], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0)
        assert 'all clear' in text
        assert f'{_CUTOFF:%Y-%m-%d %H:%M}' in text

    def test_includes_severity_breakdown_and_each_group(self):
        groups = [
            _group(alert_type='ARP_SPOOF', severity='CRITICAL', count=1, device_count=1),
            _group(alert_type='HIGH_UPLOAD', severity='WARNING', count=3, device_count=2),
        ]
        text = render_digest_text(
            groups, total=4, severity_counts={'CRITICAL': 1, 'WARNING': 3}, cutoff=_CUTOFF,
            truncated=False, total_types=2,
        )
        assert '1 CRITICAL' in text
        assert '3 WARNING' in text
        assert '[CRITICAL] ARP_SPOOF — 1 occurrence across 1 device: spoofing suspected' in text
        assert '[WARNING] HIGH_UPLOAD — 3 occurrences across 2 devices:' in text

    def test_severity_counts_reflect_the_true_total_not_just_shown_groups(self):
        """The whole reason severity_counts is a separate param, not derived
        from `groups` — see the function's own docstring."""
        groups = [_group()]  # only 1 group shown
        text = render_digest_text(
            groups, total=50, severity_counts={'CRITICAL': 30, 'WARNING': 20}, cutoff=_CUTOFF,
            truncated=True, total_types=12,
        )
        assert '30 CRITICAL' in text
        assert '20 WARNING' in text

    def test_a_burst_of_one_type_still_costs_exactly_one_line(self):
        """The actual point of grouping: 500 occurrences of the same type
        is still one row, not 500."""
        groups = [_group(alert_type='ARP_SPOOF', count=500, device_count=1)]
        text = render_digest_text(
            groups, total=500, severity_counts={'CRITICAL': 500}, cutoff=_CUTOFF,
            truncated=False, total_types=1,
        )
        assert text.count('ARP_SPOOF') == 1
        assert '500 occurrences' in text

    def test_truncated_adds_a_pointer_with_the_remaining_type_count(self):
        groups = [_group()]
        text = render_digest_text(
            groups, total=25, severity_counts={'CRITICAL': 25}, cutoff=_CUTOFF,
            truncated=True, total_types=13,
        )
        assert '...and 12 more alert type(s). See the Alerts tab in Heimdall for the full list.' in text

    def test_not_truncated_has_no_pointer(self):
        groups = [_group()]
        text = render_digest_text(
            groups, total=1, severity_counts={'CRITICAL': 1}, cutoff=_CUTOFF, truncated=False, total_types=1,
        )
        assert 'more' not in text

    def test_falls_back_to_alert_type_when_description_is_blank(self):
        groups = [_group(latest_description=None, alert_type='NEW_DEVICE')]
        text = render_digest_text(
            groups, total=1, severity_counts={'CRITICAL': 1}, cutoff=_CUTOFF, truncated=False, total_types=1,
        )
        assert 'device: NEW_DEVICE' in text  # falls back to the alert_type itself as the description


class TestRenderDigestHtml:
    def test_is_well_formed_html_with_doctype(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
        )
        assert html.strip().startswith('<!DOCTYPE html>')
        assert '</html>' in html

    def test_references_the_embedded_logo_by_cid(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
        )
        assert 'src="cid:heimdall-logo"' in html

    def test_all_clear_shows_the_all_clear_panel(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
        )
        assert 'ALL CLEAR' in html

    def test_renders_a_row_per_group_with_escaped_content(self):
        groups = [_group(latest_description='<script>alert(1)</script>', alert_type='ARP_SPOOF')]
        html = render_digest_html(
            groups, total=1, severity_counts={'CRITICAL': 1}, cutoff=_CUTOFF, now=_NOW,
            truncated=False, total_types=1,
        )
        assert '<script>alert(1)</script>' not in html  # must be HTML-escaped, not injected raw
        assert '&lt;script&gt;' in html
        assert 'ARP_SPOOF' in html

    def test_a_burst_of_one_type_still_costs_exactly_one_row(self):
        groups = [_group(alert_type='ARP_SPOOF', count=500, device_count=3)]
        html = render_digest_html(
            groups, total=500, severity_counts={'CRITICAL': 500}, cutoff=_CUTOFF, now=_NOW,
            truncated=False, total_types=1,
        )
        assert html.count('ARP_SPOOF') == 1
        assert '>500<' in html
        assert '3 devices' in html

    def test_truncated_adds_a_pointer_row_with_remaining_type_count(self):
        groups = [_group()]
        html = render_digest_html(
            groups, total=25, severity_counts={'CRITICAL': 25}, cutoff=_CUTOFF, now=_NOW,
            truncated=True, total_types=13,
        )
        assert 'and 12 more alert type(s)' in html

    def test_severity_pill_color_differs_by_severity(self):
        groups = [_group(alert_type='A', severity='CRITICAL'), _group(alert_type='B', severity='INFO')]
        html = render_digest_html(
            groups, total=2, severity_counts={'CRITICAL': 1, 'INFO': 1}, cutoff=_CUTOFF, now=_NOW,
            truncated=False, total_types=2,
        )
        assert '#ff5a3a' in html  # CRITICAL
        assert '#a3854d' in html  # INFO

    def test_singular_device_count_is_grammatically_correct(self):
        groups = [_group(device_count=1)]
        html = render_digest_html(
            groups, total=1, severity_counts={'CRITICAL': 1}, cutoff=_CUTOFF, now=_NOW,
            truncated=False, total_types=1,
        )
        assert '1 device<' in html
        assert '1 devices' not in html


def test_max_alert_types_is_a_sane_positive_bound():
    assert 0 < MAX_ALERT_TYPES <= 30
