"""Renders a single real-time CRITICAL alert notification — plain-text and
branded-HTML email bodies for NotificationService.notify_new_critical_alert.

Confirmed live 2026-09-11: this notification had never gotten the same
treatment the daily digest has — notify_new_critical_alert only ever passed
`message` to notify(), no `html_message`, so every real-time CRITICAL email
went out as a bare one-line plain-text body (just alert.description, no
device context, no trust status, no mitigation, no branding at all). This
module is the fix: same visual system as digest.py (imports its palette/
pill helpers directly rather than redefining them — the two are
deliberately consistent, just different content shapes: one alert, right
when it fires, vs. the once-daily window of everything). Pure content
generation, no I/O — see NotificationService for how the result actually
gets sent.
"""
from __future__ import annotations

from html import escape

from sentinel.notifications.digest import (
    _ACCENT, _BG, _BORDER, _MONO_STACK, _SURFACE, _SURFACE_ELEVATED, _TEXT_MUTED, _TEXT_PRIMARY,
    _severity_pill, _trust_pill, resolve_device_label,
)


def _device_label(alert, device) -> str:
    if device is not None:
        return resolve_device_label(device.hostname, device.nickname, device.mac_address)
    return alert.device_mac or 'unknown device'


def render_alert_text(alert, device) -> str:
    """Plain text — what ntfy gets verbatim, and the email's plain-text
    alternative. Deliberately self-contained: this whole body is meant to
    be select-all-and-shared as-is (e.g. into a phone's native Share sheet,
    or pasted into an AI app for a second opinion) without needing anything
    else from the app for context.
    """
    lines = [f'[{alert.severity}] {alert.alert_type}', '', alert.description or alert.alert_type, '']
    lines.append(f'DEVICE   : {_device_label(alert, device)}')
    if device is not None:
        lines.append(f'MAC      : {device.mac_address}')
        if device.ip_address:
            lines.append(f'IP       : {device.ip_address}')
        lines.append(f'TRUST    : {"TRUSTED" if device.is_trusted else "UNTRUSTED"}')
        if device.vendor_name:
            lines.append(f'VENDOR   : {device.vendor_name}')
    elif alert.device_mac:
        lines.append(f'MAC      : {alert.device_mac}')
    lines.append(f'DETECTED : {alert.created_at:%Y-%m-%d %H:%M} UTC' if alert.created_at else 'DETECTED : just now')

    if alert.mitigation:
        lines.append('')
        lines.append(f'MITIGATION: {alert.mitigation}')

    lines.append('')
    lines.append('— Heimdall Home Network Sentinel')
    return '\n'.join(lines)


def render_alert_html(alert, device) -> str:
    """Table-based, fully inline-styled HTML — same reasoning as digest.py's
    own render_digest_html (email clients don't run arbitrary CSS/JS)."""
    device_rows_html = ''
    if device is not None:
        fields = [('MAC', device.mac_address)]
        if device.ip_address:
            fields.append(('IP', device.ip_address))
        fields.append(('TRUST', _trust_pill(device.is_trusted)))
        if device.vendor_name:
            fields.append(('VENDOR', escape(device.vendor_name)))
        device_rows_html = ''.join(
            '<tr>'
            f'<td style="padding:3px 10px 3px 0;color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;'
            f'letter-spacing:1.5px;white-space:nowrap;vertical-align:top;">{label}</td>'
            f'<td style="padding:3px 0;color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;">{value}</td>'
            '</tr>'
            for label, value in fields
        )

    mitigation_html = ''
    if alert.mitigation:
        mitigation_html = f"""
<tr><td style="padding:0 24px 20px 24px;">
<div style="border:1px solid {_ACCENT};background-color:rgba(255,176,45,0.08);padding:12px 14px;">
<div style="color:{_ACCENT};font-family:{_MONO_STACK};font-size:10px;letter-spacing:2px;font-weight:600;margin-bottom:6px;">MITIGATION</div>
<div style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;line-height:1.6;">{escape(alert.mitigation)}</div>
</div>
</td></tr>
"""

    detected = f'{alert.created_at:%Y-%m-%d %H:%M} UTC' if alert.created_at else 'just now'
    share_text = render_alert_text(alert, device)

    return f"""\
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background-color:{_BG};">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:{_BG};padding:24px 12px;">
<tr><td align="center">
<table cellpadding="0" cellspacing="0" border="0" width="640" style="max-width:640px;width:100%;background-color:{_SURFACE};border:1px solid {_BORDER};">

<tr><td style="padding:20px 24px;border-bottom:1px solid {_BORDER};">
<table cellpadding="0" cellspacing="0" border="0" width="100%"><tr>
<td width="44" style="padding-right:14px;">
<img src="cid:heimdall-logo" width="40" height="40" alt="Heimdall" style="display:block;border-radius:50%;border:1px solid {_ACCENT};">
</td>
<td valign="middle">
<div style="color:{_ACCENT};font-family:{_MONO_STACK};font-size:15px;letter-spacing:4px;font-weight:700;">HEIMDALL</div>
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:10px;letter-spacing:2px;margin-top:2px;">HOME NETWORK SENTINEL — LIVE ALERT</div>
</td>
</tr></table>
</td></tr>

<tr><td style="padding:20px 24px;border-bottom:1px solid {_BORDER};">
<table cellpadding="0" cellspacing="0" border="0"><tr>
<td style="padding-right:8px;">{_severity_pill(alert.severity)}</td>
<td style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:15px;letter-spacing:0.5px;font-weight:600;">{escape(alert.alert_type)}</td>
</tr></table>
<div style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:13px;line-height:1.6;margin-top:10px;">{escape(alert.description or alert.alert_type)}</div>
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:10px;margin-top:8px;">detected {detected}</div>
</td></tr>

<tr><td style="padding:16px 24px;border-bottom:1px solid {_BORDER};">
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:2px;font-weight:600;margin-bottom:8px;">DEVICE</div>
<div style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:13px;font-weight:600;margin-bottom:6px;">{escape(_device_label(alert, device))}</div>
<table cellpadding="0" cellspacing="0" border="0">
{device_rows_html}
</table>
</td></tr>
{mitigation_html}
<tr><td style="padding:4px 24px 20px 24px;">
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:2px;font-weight:600;margin-bottom:8px;">SHARE THIS ALERT</div>
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:0.5px;margin-bottom:6px;">Tap and hold to select, then share/copy into any other app.</div>
<pre style="margin:0;padding:12px 14px;background-color:{_BG};border:1px solid {_BORDER};color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:11px;line-height:1.6;white-space:pre-wrap;word-break:break-word;">{escape(share_text)}</pre>
</td></tr>

<tr><td style="padding:14px 24px;background-color:{_SURFACE_ELEVATED};">
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:1px;">
Heimdall — self-hosted home network security monitor. Sent immediately for a new CRITICAL alert.
</div>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>
"""
