from datetime import datetime, timezone

from sentinel.notifications.digest import (
    MAX_ALERT_ROWS, DigestAlertRow, device_label, render_digest_html, render_digest_text,
)

_NOW = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
_CUTOFF = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


def _row(**overrides) -> DigestAlertRow:
    defaults = dict(
        severity='CRITICAL', alert_type='ARP_SPOOF', description='spoofing suspected',
        device_mac='aa:bb:cc:dd:ee:ff', hostname='laptop', nickname=None, created_at=_NOW,
    )
    defaults.update(overrides)
    return DigestAlertRow(**defaults)


class TestDeviceLabel:
    def test_prefers_nickname_over_hostname_and_mac(self):
        row = _row(nickname="Dad's Phone", hostname='some-router-name')
        assert device_label(row) == "Dad's Phone"

    def test_falls_back_to_hostname_when_no_nickname(self):
        row = _row(nickname=None, hostname='laptop')
        assert device_label(row) == 'laptop'

    def test_falls_back_to_bare_mac_when_neither_is_set(self):
        row = _row(nickname=None, hostname=None, device_mac='aa:bb:cc:dd:ee:ff')
        assert device_label(row) == 'aa:bb:cc:dd:ee:ff'

    def test_no_device_mac_reads_as_household(self):
        row = _row(device_mac=None, hostname=None, nickname=None)
        assert device_label(row) == 'Household'


class TestRenderDigestText:
    def test_all_clear_when_total_is_zero(self):
        text = render_digest_text([], total=0, severity_counts={}, cutoff=_CUTOFF, truncated=False)
        assert 'all clear' in text
        assert f'{_CUTOFF:%Y-%m-%d %H:%M}' in text

    def test_includes_severity_breakdown_and_each_row(self):
        rows = [_row(severity='CRITICAL', alert_type='ARP_SPOOF'), _row(severity='WARNING', alert_type='HIGH_UPLOAD')]
        text = render_digest_text(
            rows, total=2, severity_counts={'CRITICAL': 1, 'WARNING': 1}, cutoff=_CUTOFF, truncated=False,
        )
        assert '1 CRITICAL' in text
        assert '1 WARNING' in text
        assert '[CRITICAL] laptop — ARP_SPOOF: spoofing suspected' in text
        assert '[WARNING] laptop — HIGH_UPLOAD' in text

    def test_severity_counts_reflect_the_true_total_not_just_shown_rows(self):
        """The whole reason severity_counts is a separate param, not derived
        from `rows` — see the function's own docstring."""
        rows = [_row()]  # only 1 row shown
        text = render_digest_text(
            rows, total=50, severity_counts={'CRITICAL': 30, 'WARNING': 20}, cutoff=_CUTOFF, truncated=True,
        )
        assert '30 CRITICAL' in text
        assert '20 WARNING' in text

    def test_truncated_adds_a_pointer_with_the_remaining_count(self):
        rows = [_row()]
        text = render_digest_text(rows, total=25, severity_counts={'CRITICAL': 25}, cutoff=_CUTOFF, truncated=True)
        assert '...and 24 more. See the Alerts tab in Heimdall for the full list.' in text

    def test_not_truncated_has_no_pointer(self):
        rows = [_row()]
        text = render_digest_text(rows, total=1, severity_counts={'CRITICAL': 1}, cutoff=_CUTOFF, truncated=False)
        assert 'more.' not in text

    def test_falls_back_to_alert_type_when_description_is_blank(self):
        rows = [_row(description=None, alert_type='NEW_DEVICE')]
        text = render_digest_text(rows, total=1, severity_counts={'CRITICAL': 1}, cutoff=_CUTOFF, truncated=False)
        assert 'NEW_DEVICE: NEW_DEVICE' in text


class TestRenderDigestHtml:
    def test_is_well_formed_html_with_doctype(self):
        html = render_digest_html([], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False)
        assert html.strip().startswith('<!DOCTYPE html>')
        assert '</html>' in html

    def test_references_the_embedded_logo_by_cid(self):
        html = render_digest_html([], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False)
        assert 'src="cid:heimdall-logo"' in html

    def test_all_clear_shows_the_all_clear_panel(self):
        html = render_digest_html([], total=0, severity_counts={}, cutoff=_CUTOFF, now=_NOW, truncated=False)
        assert 'ALL CLEAR' in html

    def test_renders_a_row_per_alert_with_escaped_content(self):
        rows = [_row(description='<script>alert(1)</script>', alert_type='ARP_SPOOF')]
        html = render_digest_html(
            rows, total=1, severity_counts={'CRITICAL': 1}, cutoff=_CUTOFF, now=_NOW, truncated=False,
        )
        assert '<script>alert(1)</script>' not in html  # must be HTML-escaped, not injected raw
        assert '&lt;script&gt;' in html
        assert 'ARP_SPOOF' in html

    def test_truncated_adds_a_pointer_row(self):
        rows = [_row()]
        html = render_digest_html(
            rows, total=25, severity_counts={'CRITICAL': 25}, cutoff=_CUTOFF, now=_NOW, truncated=True,
        )
        assert 'and 24 more' in html

    def test_severity_pill_color_differs_by_severity(self):
        rows = [_row(severity='CRITICAL'), _row(severity='INFO')]
        html = render_digest_html(
            rows, total=2, severity_counts={'CRITICAL': 1, 'INFO': 1}, cutoff=_CUTOFF, now=_NOW, truncated=False,
        )
        assert '#ff5a3a' in html  # CRITICAL
        assert '#a3854d' in html  # INFO


def test_max_alert_rows_is_a_sane_positive_bound():
    assert 0 < MAX_ALERT_ROWS <= 50
