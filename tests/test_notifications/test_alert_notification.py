from datetime import datetime, timezone
from types import SimpleNamespace

from sentinel.notifications.alert_notification import render_alert_html, render_alert_text

_NOW = datetime(2026, 9, 11, 8, 12, tzinfo=timezone.utc)


def _alert(**overrides):
    defaults = dict(
        severity='CRITICAL', alert_type='HIGH_RISK_PORT_OPENED',
        description='10.100.102.9 newly exposes MSRPC on port 135 (closed on the previous scan)',
        mitigation=None, created_at=_NOW, device_mac='60:eb:69:7e:18:bd',
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _device(**overrides):
    defaults = dict(
        mac_address='60:eb:69:7e:18:bd', hostname='DESKTOP-JH1JU68', nickname=None,
        ip_address='10.100.102.9', is_trusted=False, vendor_name='Dell Inc.',
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestRenderAlertText:
    def test_includes_severity_type_and_description(self):
        text = render_alert_text(_alert(), _device())
        assert '[CRITICAL] HIGH_RISK_PORT_OPENED' in text
        assert '10.100.102.9 newly exposes MSRPC on port 135' in text

    def test_includes_device_fields_when_a_device_is_given(self):
        text = render_alert_text(_alert(), _device())
        assert 'DEVICE   : DESKTOP-JH1JU68' in text
        assert 'MAC      : 60:eb:69:7e:18:bd' in text
        assert 'IP       : 10.100.102.9' in text
        assert 'VENDOR   : Dell Inc.' in text

    def test_nickname_beats_hostname_for_the_device_line(self):
        text = render_alert_text(_alert(), _device(nickname='Office PC'))
        assert 'DEVICE   : Office PC' in text
        assert 'DESKTOP-JH1JU68' not in text

    def test_untrusted_device_is_tagged(self):
        text = render_alert_text(_alert(), _device(is_trusted=False))
        assert 'TRUST    : UNTRUSTED' in text

    def test_trusted_device_is_tagged(self):
        text = render_alert_text(_alert(), _device(is_trusted=True))
        assert 'TRUST    : TRUSTED' in text

    def test_no_device_falls_back_to_the_bare_mac(self):
        text = render_alert_text(_alert(device_mac='aa:bb:cc:dd:ee:ff'), None)
        assert 'DEVICE   : aa:bb:cc:dd:ee:ff' in text
        assert 'TRUST' not in text  # nothing known to report trust for

    def test_no_device_and_no_mac_reads_as_unknown_device(self):
        text = render_alert_text(_alert(device_mac=None), None)
        assert 'DEVICE   : unknown device' in text

    def test_mitigation_included_when_present(self):
        text = render_alert_text(_alert(mitigation='Block the offending MAC.'), _device())
        assert 'MITIGATION: Block the offending MAC.' in text

    def test_mitigation_omitted_when_absent(self):
        text = render_alert_text(_alert(mitigation=None), _device())
        assert 'MITIGATION' not in text

    def test_falls_back_to_alert_type_when_description_is_blank(self):
        text = render_alert_text(_alert(alert_type='NEW_DEVICE', description=None), _device())
        assert 'NEW_DEVICE' in text.splitlines()[0]
        assert 'NEW_DEVICE' in text.splitlines()[2]  # the description-fallback line too

    def test_ends_with_the_heimdall_signoff(self):
        text = render_alert_text(_alert(), _device())
        assert text.strip().endswith('Heimdall Home Network Sentinel')


class TestRenderAlertHtml:
    def test_is_well_formed_html_with_doctype(self):
        html = render_alert_html(_alert(), _device())
        assert html.strip().startswith('<!DOCTYPE html>')
        assert '</html>' in html

    def test_references_the_embedded_logo_by_cid(self):
        html = render_alert_html(_alert(), _device())
        assert 'src="cid:heimdall-logo"' in html

    def test_escapes_html_in_the_description(self):
        html = render_alert_html(_alert(description='<script>alert(1)</script>'), _device())
        assert '<script>alert(1)</script>' not in html
        assert '&lt;script&gt;' in html

    def test_severity_pill_present(self):
        html = render_alert_html(_alert(severity='CRITICAL'), _device())
        assert '#ff5a3a' in html  # CRITICAL's color

    def test_trust_pill_reflects_untrusted(self):
        html = render_alert_html(_alert(), _device(is_trusted=False))
        assert '>UNTRUSTED<' in html

    def test_trust_pill_reflects_trusted(self):
        html = render_alert_html(_alert(), _device(is_trusted=True))
        assert '>TRUSTED<' in html

    def test_mitigation_section_present_when_given(self):
        html = render_alert_html(_alert(mitigation='Isolate the device.'), _device())
        assert 'MITIGATION' in html
        assert 'Isolate the device.' in html

    def test_mitigation_section_absent_when_not_given(self):
        html = render_alert_html(_alert(mitigation=None), _device())
        assert 'MITIGATION' not in html

    def test_no_device_does_not_crash_and_omits_device_rows(self):
        html = render_alert_html(_alert(device_mac=None), None)
        assert '<!DOCTYPE html>' in html
        assert 'TRUSTED' not in html and 'UNTRUSTED' not in html

    def test_share_block_contains_the_full_plain_text_body(self):
        """Requested directly: a self-contained, copy/shareable block —
        the exact render_alert_text() output, so selecting it (e.g. via a
        phone's native Share action) hands off everything needed for
        context with nothing missing. This fixture's text has no HTML-
        escapable characters, so a plain substring check is valid without
        re-implementing html.escape."""
        alert = _alert()
        device = _device()
        html = render_alert_html(alert, device)
        text = render_alert_text(alert, device)
        assert text in html
