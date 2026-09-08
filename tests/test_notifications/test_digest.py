from datetime import datetime, timedelta, timezone

from sentinel.notifications.digest import (
    MAX_ALERT_TYPES, MAX_BANDWIDTH_HOURS, MAX_TRAFFIC_DEVICES, SEVERITY_RANK_TO_NAME, DigestDeviceTraffic,
    DigestHourlyBandwidth, DigestTypeGroup, render_digest_html, render_digest_text, resolve_device_label,
)
from sentinel.notifications.digest import _sparkline

_NOW = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
_CUTOFF = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


def _group(**overrides) -> DigestTypeGroup:
    defaults = dict(
        alert_type='ARP_SPOOF', severity='CRITICAL', count=1, device_count=1,
        latest_description='spoofing suspected', latest_created_at=_NOW,
    )
    defaults.update(overrides)
    return DigestTypeGroup(**defaults)


def _traffic(**overrides) -> DigestDeviceTraffic:
    defaults = dict(device_label='laptop', upload_bytes=1024 * 1024, download_bytes=1024 * 1024 * 4)
    defaults.update(overrides)
    return DigestDeviceTraffic(**defaults)


def _hours(*total_bytes: int, start: datetime = _CUTOFF) -> list[DigestHourlyBandwidth]:
    return [DigestHourlyBandwidth(hour=start + timedelta(hours=i), total_bytes=b) for i, b in enumerate(total_bytes)]


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


def test_max_traffic_devices_is_a_sane_positive_bound():
    assert 0 < MAX_TRAFFIC_DEVICES <= 50


class TestResolveDeviceLabel:
    def test_prefers_nickname_over_hostname_and_mac(self):
        assert resolve_device_label('laptop-hostname', 'My Laptop', 'aa:bb:cc:dd:ee:ff') == 'My Laptop'

    def test_falls_back_to_hostname_when_no_nickname(self):
        assert resolve_device_label('laptop-hostname', None, 'aa:bb:cc:dd:ee:ff') == 'laptop-hostname'

    def test_falls_back_to_mac_when_neither_set(self):
        assert resolve_device_label(None, None, 'aa:bb:cc:dd:ee:ff') == 'aa:bb:cc:dd:ee:ff'


class TestRenderDigestTextTraffic:
    def test_no_traffic_section_when_traffic_is_none_or_empty(self):
        text = render_digest_text([], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0)
        assert 'DEVICE TRAFFIC' not in text

        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0, traffic=[],
        )
        assert 'DEVICE TRAFFIC' not in text

    def test_traffic_section_shows_even_on_an_all_clear_day(self):
        """The whole reason traffic is a separate, independent question from
        alert totals — see render_digest_text's own docstring."""
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0,
            traffic=[_traffic()],
        )
        assert 'all clear' in text
        assert 'DEVICE TRAFFIC' in text

    def test_lists_each_device_with_mb_formatted_upload_and_download(self):
        rows = [
            _traffic(device_label='laptop', upload_bytes=1024 * 1024 * 500, download_bytes=1024 * 1024 * 2000),
            _traffic(device_label='phone', upload_bytes=1024 * 1024 * 10, download_bytes=1024 * 1024 * 50),
        ]
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0, traffic=rows,
        )
        assert 'laptop: 500.00 MB up / 2000.00 MB down' in text
        assert 'phone: 10.00 MB up / 50.00 MB down' in text

    def test_truncated_adds_a_pointer_with_the_remaining_device_count(self):
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0,
            traffic=[_traffic()], traffic_truncated=True, total_traffic_devices=25,
        )
        assert '...and 24 more device(s), smaller usage.' in text

    def test_not_truncated_has_no_device_pointer(self):
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0,
            traffic=[_traffic()], traffic_truncated=False,
        )
        assert 'more device(s)' not in text

    def test_includes_the_wired_port_aggregation_footnote(self):
        """CLAUDE.md rule 5: PER_PORT wired devices are excluded from this
        section entirely (see SentinelScheduler._security_digest_job's
        query filter), so the footnote explaining why must always be
        present whenever the section renders at all."""
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0, traffic=[_traffic()],
        )
        assert "Wired devices sharing a physical port aren't broken out individually" in text


class TestRenderDigestHtmlTraffic:
    def test_no_traffic_section_when_traffic_is_none_or_empty(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
        )
        assert 'DEVICE TRAFFIC' not in html

    def test_traffic_section_shows_even_on_an_all_clear_day(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            traffic=[_traffic()],
        )
        assert 'ALL CLEAR' in html
        assert 'DEVICE TRAFFIC' in html

    def test_renders_a_row_per_device_with_escaped_label(self):
        rows = [_traffic(device_label='<script>alert(1)</script>')]
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            traffic=rows,
        )
        assert '<script>alert(1)</script>' not in html
        assert '&lt;script&gt;' in html

    def test_formats_upload_and_download_in_mb(self):
        rows = [_traffic(device_label='laptop', upload_bytes=1024 * 1024 * 500, download_bytes=1024 * 1024 * 2000)]
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            traffic=rows,
        )
        assert '500.00 MB' in html
        assert '2000.00 MB' in html

    def test_truncated_adds_a_pointer_row_with_remaining_device_count(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            traffic=[_traffic()], traffic_truncated=True, total_traffic_devices=25,
        )
        assert '...and 24 more device(s), smaller usage.' in html

    def test_includes_the_wired_port_aggregation_footnote(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            traffic=[_traffic()],
        )
        # escape() turns the apostrophe into &#x27; — assert on a
        # substring either side of it rather than the raw contraction.
        assert 'Wired devices sharing a physical port' in html
        assert "broken out individually" in html


def test_max_bandwidth_hours_is_a_sane_positive_bound():
    assert 0 < MAX_BANDWIDTH_HOURS <= 96


class TestSparkline:
    def test_scales_relative_to_the_peak_value(self):
        # peak (100) must map to the top block, 0 to a blank column, and
        # everything else somewhere in between in the same order.
        line = _sparkline([0, 25, 50, 100])
        assert line[0] == ' '
        assert line[-1] == '█'
        assert line[0] < line[1] < line[2] < line[3]  # block chars sort by codepoint = by height

    def test_all_zero_values_is_a_blank_line_not_a_crash(self):
        assert _sparkline([0, 0, 0]) == '   '

    def test_empty_input_is_a_sane_empty_string(self):
        assert _sparkline([]) == ''

    def test_output_length_matches_input_length(self):
        assert len(_sparkline([1, 2, 3, 4, 5])) == 5


class TestRenderDigestTextBandwidth:
    def test_no_bandwidth_section_when_hourly_bandwidth_is_none_or_empty(self):
        text = render_digest_text([], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0)
        assert 'BANDWIDTH BY HOUR' not in text

        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0, hourly_bandwidth=[],
        )
        assert 'BANDWIDTH BY HOUR' not in text

    def test_shows_even_on_an_all_clear_day(self):
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0,
            hourly_bandwidth=_hours(100, 200, 300),
        )
        assert 'all clear' in text
        assert 'BANDWIDTH BY HOUR' in text

    def test_header_reports_the_time_range_and_the_peak_hour(self):
        hours = _hours(10, 20, 500, 30, start=datetime(2026, 9, 6, 6, 0, tzinfo=timezone.utc))
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0, hourly_bandwidth=hours,
        )
        assert '06:00-09:00 UTC' in text
        assert 'peak 08:00' in text  # index 2 (10, 20, 500, 30) is the largest

    def test_includes_a_sparkline_line_the_same_length_as_the_hours_given(self):
        hours = _hours(1, 2, 3, 4, 5)
        text = render_digest_text(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False, total_types=0, hourly_bandwidth=hours,
        )
        lines = text.splitlines()
        sparkline_line = lines[-1]
        assert len(sparkline_line) == 5


class TestRenderDigestHtmlBandwidth:
    def test_no_bandwidth_section_when_hourly_bandwidth_is_none_or_empty(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
        )
        assert 'BANDWIDTH BY HOUR' not in html

    def test_shows_even_on_an_all_clear_day(self):
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=_hours(100, 200, 300),
        )
        assert 'ALL CLEAR' in html
        assert 'BANDWIDTH BY HOUR' in html

    def test_renders_one_bar_cell_per_hour(self):
        hours = _hours(10, 20, 30, 40, 50)
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=hours,
        )
        assert html.count('bgcolor=') == len(hours)

    def test_peak_bar_is_accented_and_others_are_muted(self):
        hours = _hours(10, 999, 10)
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=hours,
        )
        assert html.count('bgcolor="#ffb02d"') == 1  # exactly one accented (peak) bar
        assert html.count('bgcolor="#a3854d"') == 2  # the other two are muted

    def test_a_true_zero_hour_still_gets_a_visible_minimum_height_bar(self):
        """A missing/blank column would read as "no data", not "zero
        traffic" — every hour, including a genuine zero, must draw
        something."""
        hours = _hours(0, 500)
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=hours,
        )
        assert 'height="2"' in html  # MIN_BAR_PX for the zero hour

    def test_all_zero_hours_does_not_crash_on_division_by_the_peak(self):
        hours = _hours(0, 0, 0)
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=hours,
        )
        assert html.count('bgcolor="#a3854d"') == 3  # no peak when everything is tied at zero

    def test_labels_every_hour_when_24_or_fewer(self):
        hours = _hours(*range(24))
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=hours,
        )
        for h in hours:
            assert f'>{h.hour:%H}<' in html

    def test_thins_labels_when_more_than_24_hours(self):
        """A missed-digest window spanning multiple days would otherwise
        crowd the label axis unreadably."""
        hours = _hours(*range(30))
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=hours,
        )
        assert f'>{hours[0].hour:%H}<' in html
        assert f'>{hours[1].hour:%H}<' not in html  # thinned out (every-2nd labeling)

    def test_footnote_reports_the_time_range_and_peak(self):
        mb = 1024 * 1024
        hours = _hours(10 * mb, 500 * mb, 30 * mb, start=datetime(2026, 9, 6, 6, 0, tzinfo=timezone.utc))
        html = render_digest_html(
            [], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False, total_types=0,
            hourly_bandwidth=hours,
        )
        assert '2026-09-06 06:00' in html
        assert 'peak 07:00' in html
        assert '500.00' in html.split('peak 07:00')[1][:40]  # MB figure follows the peak label closely
