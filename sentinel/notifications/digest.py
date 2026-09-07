"""Renders the daily security digest's plain-text and HTML bodies — pure
content generation, no I/O. See SentinelScheduler._security_digest_job for
how the underlying alert rows are queried, and NotificationService for how
the result actually gets sent (including embedding the logo referenced by
the `cid:heimdall-logo` src in the HTML below).

Colors are the app's own default "Amber CRT" palette
(frontend/src/index.css :root[data-palette='amber']), hardcoded rather than
referenced — email clients don't run the app's CSS, or any CSS variables at
all reliably, so every color here is a literal matching that palette's
values by hand. If the palette's hex values ever change, these should too.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape

# Mirrors frontend/src/index.css :root[data-palette='amber'] — see module
# docstring for why these are hardcoded rather than shared with the CSS.
_BG = '#12100a'
_SURFACE = '#1a170f'
_SURFACE_ELEVATED = '#221d13'
_BORDER = '#4a3d22'  # rgba(255,176,45,0.3) flattened against _BG — email clients handle alpha inconsistently
_TEXT_PRIMARY = '#e8dcc8'
_TEXT_MUTED = '#a3854d'
_ACCENT = '#ffb02d'

_SEVERITY_COLOR = {'CRITICAL': '#ff5a3a', 'WARNING': '#ffd23a', 'INFO': '#a3854d'}

# A table this long stops being a scannable digest and starts being the
# Alerts page — cap it and point at the real thing for the rest. See
# render_digest_html/_text's `truncated` handling.
MAX_ALERT_ROWS = 20

_MONO_STACK = "'JetBrains Mono','Courier New',Courier,monospace"


@dataclass
class DigestAlertRow:
    severity: str
    alert_type: str
    description: str | None
    device_mac: str | None
    hostname: str | None
    nickname: str | None
    created_at: datetime


def device_label(row: DigestAlertRow) -> str:
    """Mirrors frontend/src/lib/deviceDisplay.js:deviceDisplayName's
    nickname > hostname > bare-MAC precedence. No device_mac at all (e.g.
    WAN_BANDWIDTH_SPIKE, a household-wide finding with no single device to
    attribute it to) reads as 'Household' rather than a blank cell."""
    if not row.device_mac:
        return 'Household'
    return row.nickname or row.hostname or row.device_mac


def render_digest_text(
    rows: list[DigestAlertRow], total: int, severity_counts: dict[str, int], cutoff: datetime, truncated: bool,
) -> str:
    """Plain-text fallback — shown by clients that don't render HTML, and
    always what ntfy pushes (a phone notification has no room for a table).

    severity_counts is the TRUE breakdown across the whole window (from a
    separate aggregate query — see SentinelScheduler._security_digest_job),
    not derived from `rows`: rows is capped at MAX_ALERT_ROWS, so counting
    severities from it alone would silently under-report once a day
    exceeds that cap.
    """
    if total == 0:
        return f'No alerts since {cutoff:%Y-%m-%d %H:%M} UTC — all clear.'

    lines = [f'HEIMDALL SECURITY DIGEST — {total} alert(s) since {cutoff:%Y-%m-%d %H:%M} UTC', '']
    lines.append(', '.join(f'{c} {s}' for s, c in sorted(severity_counts.items(), key=lambda kv: -kv[1])))
    lines.append('')
    for r in rows:
        lines.append(
            f'[{r.severity}] {device_label(r)} — {r.alert_type}: '
            f'{r.description or r.alert_type} ({r.created_at:%Y-%m-%d %H:%M} UTC)'
        )
    if truncated:
        lines.append('')
        lines.append(f'...and {total - len(rows)} more. See the Alerts tab in Heimdall for the full list.')
    return '\n'.join(lines)


def _severity_pill(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, _TEXT_MUTED)
    return (
        f'<span style="display:inline-block;padding:2px 8px;border:1px solid {color};'
        f'border-radius:2px;color:{color};font-family:{_MONO_STACK};font-size:10px;'
        f'letter-spacing:1px;font-weight:600;white-space:nowrap;">{escape(severity)}</span>'
    )


def render_digest_html(
    rows: list[DigestAlertRow], total: int, severity_counts: dict[str, int],
    cutoff: datetime, now: datetime, truncated: bool,
) -> str:
    """Table-based, fully inline-styled HTML — no <style> block, no CSS
    variables, no flex/grid: email clients (Gmail's web/app clients
    especially) strip or ignore all of that unpredictably. References the
    logo as cid:heimdall-logo; NotificationService embeds the actual image
    bytes under that Content-ID when it sends this.

    severity_counts is the TRUE breakdown across the whole window — see
    render_digest_text's docstring for why this isn't derived from `rows`.
    """
    if total > 0:
        badges = ''.join(
            f'<td style="padding-right:8px;">{_severity_pill(sev)} '
            f'<span style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;">{count}</span></td>'
            for sev, count in sorted(severity_counts.items(), key=lambda kv: -kv[1])
        )
        summary_html = f'<table cellpadding="0" cellspacing="0" border="0"><tr>{badges}</tr></table>'
    else:
        summary_html = ''

    if total == 0:
        body_rows = (
            f'<tr><td style="padding:24px 0;text-align:center;color:{_TEXT_MUTED};'
            f'font-family:{_MONO_STACK};font-size:12px;letter-spacing:1px;">'
            f'ALL CLEAR — no alerts since {cutoff:%Y-%m-%d %H:%M} UTC</td></tr>'
        )
        headline = 'ALL CLEAR'
    else:
        row_html = []
        for r in rows:
            color = _SEVERITY_COLOR.get(r.severity, _TEXT_MUTED)
            row_html.append(
                '<tr>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;">{_severity_pill(r.severity)}</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;'
                f'color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;white-space:nowrap;">'
                f'{escape(device_label(r))}</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;'
                f'color:{color};font-family:{_MONO_STACK};font-size:11px;letter-spacing:0.5px;white-space:nowrap;">'
                f'{escape(r.alert_type)}</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;'
                f'color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;line-height:1.5;">'
                f'{escape(r.description or r.alert_type)}</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;'
                f'color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:10px;white-space:nowrap;text-align:right;">'
                f'{r.created_at:%m-%d %H:%M}</td>'
                '</tr>'
            )
        if truncated:
            row_html.append(
                f'<tr><td colspan="5" style="padding:10px;border-top:1px solid {_BORDER};text-align:center;'
                f'color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:11px;">'
                f'...and {total - len(rows)} more — see the Alerts tab in Heimdall for the full list.</td></tr>'
            )
        body_rows = ''.join(row_html)
        headline = f'{total} ALERT{"S" if total != 1 else ""}'

    table_header = ''
    if total > 0:
        table_header = (
            '<tr>'
            + ''.join(
                f'<th style="padding:6px 10px;text-align:left;color:{_TEXT_MUTED};'
                f'font-family:{_MONO_STACK};font-size:9px;letter-spacing:2px;font-weight:600;">{label}</th>'
                for label in ('SEVERITY', 'DEVICE', 'TYPE', 'DESCRIPTION', 'TIME (UTC)')
            )
            + '</tr>'
        )

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
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:10px;letter-spacing:2px;margin-top:2px;">HOME NETWORK SENTINEL — SECURITY DIGEST</div>
</td>
</tr></table>
</td></tr>

<tr><td style="padding:20px 24px;border-bottom:1px solid {_BORDER};">
<div style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:16px;letter-spacing:1px;font-weight:600;margin-bottom:8px;">{headline}</div>
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:11px;margin-bottom:{'10px' if total > 0 else '0'};">since {cutoff:%Y-%m-%d %H:%M} UTC — as of {now:%Y-%m-%d %H:%M} UTC</div>
{summary_html}
</td></tr>

<tr><td style="padding:4px 14px 20px 14px;">
<table cellpadding="0" cellspacing="0" border="0" width="100%">
{table_header}
{body_rows}
</table>
</td></tr>

<tr><td style="padding:14px 24px;background-color:{_SURFACE_ELEVATED};">
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:1px;">
Heimdall — self-hosted home network security monitor. This digest summarizes every alert regardless of severity, once a day.
</div>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>
"""
