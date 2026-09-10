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

# Requested directly: grouped by alert_type rather than one row per raw
# alert — during a genuine burst (a real attack, or a flaky device rapid-
# cycling), a flat per-alert list gets dominated by one repeating type and
# pushes everything else out of the MAX_ALERT_ROWS cap. Grouping guarantees
# *diversity* of information instead: a type that fired 200 times still
# only ever costs one row, so distinct issues stay visible. Ten groups
# (not the old top-5-types line, and not raw MAX_ALERT_ROWS=20 individual
# alerts) — enough to see everything that actually happened on a normal
# day without turning into the Alerts page.
MAX_ALERT_TYPES = 10

_MONO_STACK = "'JetBrains Mono','Courier New',Courier,monospace"

# Public (not a leading-underscore module-private constant): SentinelScheduler
# ._security_digest_job builds its worst-severity-per-type query with the
# same numeric ranks, then maps the result back through this exact dict —
# shared across the module boundary deliberately, not an internal detail.
SEVERITY_RANK_TO_NAME = {3: 'CRITICAL', 2: 'WARNING', 1: 'INFO'}

# Same reasoning as MAX_ALERT_TYPES: a household can easily have 30-50+
# devices ever seen, but only the busiest ones are actually interesting in
# a daily glance. Ranked by total bytes, so the cap always keeps the
# heaviest users, not an arbitrary/alphabetical slice.
MAX_TRAFFIC_DEVICES = 20

# A digest window is usually ~24h (one bar per hour), but last_digest_sent_at
# can be arbitrarily old if a send was ever missed — cap how many hourly
# bars get drawn so that doesn't turn into an unreadably wide chart. Unlike
# MAX_ALERT_TYPES/MAX_TRAFFIC_DEVICES this keeps the MOST RECENT hours (see
# SentinelScheduler._security_digest_job), not the largest — a timeline
# reads chronologically, not ranked.
MAX_BANDWIDTH_HOURS = 48

# 9 levels (index 0 = a blank column for a true zero hour, not just a short
# bar) — used to draw a crude bar chart out of plain text for
# render_digest_text/ntfy, which can't render an actual <table> chart.
_SPARKLINE_BLOCKS = ' ▁▂▃▄▅▆▇█'


@dataclass
class DigestTypeGroup:
    """One alert_type's worth of activity in the digest window.

    severity is the WORST severity seen for this type in the window (not
    just whichever alert happened to be latest) — a type that spiked to
    CRITICAL once and has since calmed to WARNING must still read as
    CRITICAL here, or the one moment that mattered gets buried.
    """
    alert_type: str
    severity: str
    count: int
    device_count: int
    latest_description: str | None
    latest_created_at: datetime


@dataclass
class DigestDeviceTraffic:
    """One device's total upload/download for the digest window. Only ever
    built from TrafficSample rows with granularity == 'per_device' — see
    SentinelScheduler._security_digest_job and CLAUDE.md rule 5: a wired
    device sharing its physical port with another (TrafficGranularity.
    PER_PORT) has no real per-device figure to report at all, only a port
    aggregate, so it's excluded here rather than shown as if measured.

    is_trusted mirrors Device.is_trusted (False for a MAC with traffic but
    no devices row at all — an unknown device is never trusted by
    default). Not used by the email renderers below; carried through for
    the Reports tab's own untrusted-device filter/coloring — see
    sentinel/api/serializers.py:digest_data_to_dict.
    """
    device_label: str
    upload_bytes: int
    download_bytes: int
    # Defaulted (not required) only so existing tests/call sites that don't
    # care about trust status don't need updating — digest_query.py always
    # passes the real value explicitly. False matches Device.is_trusted's
    # own server_default: an unknown device is never trusted by default.
    is_trusted: bool = False


@dataclass
class DigestHourlyBandwidth:
    """Total household WAN bandwidth (upload + download) for one hour
    bucket. Built from WanStats — the router's own WAN-interface counter,
    with no device or port dimension at all — so unlike DigestDeviceTraffic
    this has no CLAUDE.md rule 5 concern to filter for: it's a single
    honest household-wide total, wired and wireless traffic alike, not
    attributed to anything.
    """
    hour: datetime  # bucket start (UTC, on the hour)
    total_bytes: int


def resolve_device_label(hostname: str | None, nickname: str | None, mac: str) -> str:
    """Mirrors frontend/src/lib/deviceDisplay.js:deviceDisplayName's
    nickname > hostname > bare-MAC precedence, for building
    DigestDeviceTraffic.device_label from a query's own hostname/nickname
    columns (see SentinelScheduler._security_digest_job)."""
    return nickname or hostname or mac


def _plural(n: int, word: str) -> str:
    return f'{n} {word}' if n == 1 else f'{n} {word}s'


def _format_mb(n_bytes: int) -> str:
    """Fixed MB unit, not formatBytes.js's tiered KB/MB/GB — requested as
    megabytes specifically, and a fixed unit keeps every row in this
    section directly comparable at a glance. Same 1024-based conversion as
    the frontend's own formatBytes for consistency elsewhere in the app."""
    return f'{n_bytes / 1024 / 1024:.2f} MB'


def _sparkline(values: list[int]) -> str:
    """One block character per value, height-scaled to the largest value in
    `values` — a crude bar chart for plain text (ntfy, and any email client
    that renders text/plain instead of the HTML part). A genuinely-zero
    hour draws as a blank column (index 0), not just the shortest visible
    bar, so a quiet stretch of the night doesn't look like low-but-nonzero
    activity."""
    peak = max(values, default=0)
    if peak == 0:
        return ' ' * len(values)
    levels = len(_SPARKLINE_BLOCKS) - 1
    return ''.join(
        _SPARKLINE_BLOCKS[0] if v == 0 else _SPARKLINE_BLOCKS[max(1, round(v / peak * levels))]
        for v in values
    )


def render_digest_text(
    groups: list[DigestTypeGroup], total: int, severity_counts: dict[str, int],
    cutoff: datetime, truncated: bool, total_types: int,
    traffic: list[DigestDeviceTraffic] | None = None, traffic_truncated: bool = False,
    total_traffic_devices: int = 0,
    hourly_bandwidth: list[DigestHourlyBandwidth] | None = None,
) -> str:
    """Plain-text fallback — shown by clients that don't render HTML, and
    always what ntfy pushes (a phone notification has no room for a table).

    severity_counts is the TRUE breakdown across the whole window (from a
    separate aggregate query — see SentinelScheduler._security_digest_job),
    not derived from `groups`: a group's own .severity is its *worst* alert,
    which would double-count towards the wrong bucket if summed naively.

    The traffic and hourly-bandwidth sections (if given) are appended even
    on an otherwise "all clear" day — no alerts doesn't mean no activity
    worth reporting, and these are independent questions.
    """
    if total == 0:
        lines = [f'No alerts since {cutoff:%Y-%m-%d %H:%M} UTC — all clear.']
    else:
        lines = [f'HEIMDALL SECURITY DIGEST — {total} alert(s) since {cutoff:%Y-%m-%d %H:%M} UTC', '']
        lines.append(', '.join(f'{c} {s}' for s, c in sorted(severity_counts.items(), key=lambda kv: -kv[1])))
        lines.append('')
        for g in groups:
            devices = _plural(g.device_count, 'device')
            lines.append(
                f'[{g.severity}] {g.alert_type} — {_plural(g.count, "occurrence")} across {devices}: '
                f'{g.latest_description or g.alert_type} (latest: {g.latest_created_at:%Y-%m-%d %H:%M} UTC)'
            )
        if truncated:
            lines.append('')
            lines.append(
                f'...and {total_types - len(groups)} more alert type(s). '
                'See the Alerts tab in Heimdall for the full list.'
            )

    if hourly_bandwidth:
        lines.append('')
        peak = max(hourly_bandwidth, key=lambda h: h.total_bytes)
        lines.append(
            f'BANDWIDTH BY HOUR ({hourly_bandwidth[0].hour:%H:%M}'
            f'-{hourly_bandwidth[-1].hour:%H:%M} UTC, peak {peak.hour:%H:%M} — {_format_mb(peak.total_bytes)})'
        )
        lines.append(_sparkline([h.total_bytes for h in hourly_bandwidth]))

    if traffic:
        lines.append('')
        lines.append('DEVICE TRAFFIC (upload / download)')
        for t in traffic:
            lines.append(f'{t.device_label}: {_format_mb(t.upload_bytes)} up / {_format_mb(t.download_bytes)} down')
        if traffic_truncated:
            lines.append(f'...and {total_traffic_devices - len(traffic)} more device(s), smaller usage.')
        lines.append(
            "Wired devices sharing a physical port aren't broken out individually — "
            'only a combined port total is measurable for them.'
        )

    return '\n'.join(lines)


def _severity_pill(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, _TEXT_MUTED)
    return (
        f'<span style="display:inline-block;padding:2px 8px;border:1px solid {color};'
        f'border-radius:2px;color:{color};font-family:{_MONO_STACK};font-size:10px;'
        f'letter-spacing:1px;font-weight:600;white-space:nowrap;">{escape(severity)}</span>'
    )


def render_digest_html(
    groups: list[DigestTypeGroup], total: int, severity_counts: dict[str, int],
    cutoff: datetime, now: datetime, truncated: bool, total_types: int,
    traffic: list[DigestDeviceTraffic] | None = None, traffic_truncated: bool = False,
    total_traffic_devices: int = 0,
    hourly_bandwidth: list[DigestHourlyBandwidth] | None = None,
) -> str:
    """Table-based, fully inline-styled HTML — no <style> block, no CSS
    variables, no flex/grid: email clients (Gmail's web/app clients
    especially) strip or ignore all of that unpredictably. References the
    logo as cid:heimdall-logo; NotificationService embeds the actual image
    bytes under that Content-ID when it sends this.

    severity_counts is the TRUE breakdown across the whole window — see
    render_digest_text's docstring for why this isn't derived from `groups`.

    The traffic and hourly-bandwidth sections (if given) each render as
    their own card section below the alerts table, even on an otherwise
    "all clear" day — see render_digest_text's docstring for why those are
    independent. The bar chart itself is a plain <table> with per-hour
    <td height="..."> cells (both the HTML height attribute and an inline
    CSS height, for maximum client compatibility) rather than an actual
    <img>/SVG/canvas chart — email clients don't render any of those
    reliably, but a table of colored cells is about as compatible as HTML
    email gets.
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
        for g in groups:
            color = _SEVERITY_COLOR.get(g.severity, _TEXT_MUTED)
            row_html.append(
                '<tr>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;">{_severity_pill(g.severity)}</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;'
                f'color:{color};font-family:{_MONO_STACK};font-size:11px;letter-spacing:0.5px;white-space:nowrap;">'
                f'{escape(g.alert_type)}</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;white-space:nowrap;">'
                f'<div style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:13px;font-weight:600;">{g.count}</div>'
                f'<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;">{escape(_plural(g.device_count, "device"))}</div>'
                '</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;'
                f'color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;line-height:1.5;">'
                f'{escape(g.latest_description or g.alert_type)}</td>'
                f'<td style="padding:8px 10px;border-top:1px solid {_BORDER};vertical-align:top;'
                f'color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:10px;white-space:nowrap;text-align:right;">'
                f'{g.latest_created_at:%m-%d %H:%M}</td>'
                '</tr>'
            )
        if truncated:
            row_html.append(
                f'<tr><td colspan="5" style="padding:10px;border-top:1px solid {_BORDER};text-align:center;'
                f'color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:11px;">'
                f'...and {total_types - len(groups)} more alert type(s) — see the Alerts tab in Heimdall for the full list.'
                '</td></tr>'
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
                for label in ('SEVERITY', 'TYPE', 'COUNT', 'LATEST DESCRIPTION', 'LATEST (UTC)')
            )
            + '</tr>'
        )

    bandwidth_section = ''
    if hourly_bandwidth:
        # Peak bar fixed at MAX_BAR_PX, every other bar scaled relative to
        # it — a real zero hour still gets MIN_BAR_PX so it reads as "zero",
        # not "missing column".
        MAX_BAR_PX, MIN_BAR_PX = 60, 2
        peak_bytes = max(h.total_bytes for h in hourly_bandwidth)
        peak_hour = max(hourly_bandwidth, key=lambda h: h.total_bytes)
        # >24 bars (a missed-digest window spanning more than a day) would
        # crowd an "every hour" label axis — thin it to every other hour.
        label_every = 1 if len(hourly_bandwidth) <= 24 else 2
        bar_cells = []
        for i, h in enumerate(hourly_bandwidth):
            bar_px = (
                MIN_BAR_PX if peak_bytes == 0
                else max(MIN_BAR_PX, round(h.total_bytes / peak_bytes * MAX_BAR_PX))
            )
            # The peak hour's bar gets the full accent color; every other
            # bar is the dimmer muted tone — draws the eye to the peak the
            # way a real chart's tooltip/highlight would.
            color = _ACCENT if peak_bytes > 0 and h.total_bytes == peak_bytes else _TEXT_MUTED
            label = f'{h.hour:%H}' if i % label_every == 0 else '&nbsp;'
            bar_cells.append(
                '<td align="center" valign="bottom" style="padding:0 1px;">'
                '<table cellpadding="0" cellspacing="0" border="0"><tr>'
                f'<td width="10" height="{bar_px}" bgcolor="{color}" '
                f'style="width:10px;height:{bar_px}px;background-color:{color};font-size:0;line-height:0;">&nbsp;</td>'
                '</tr></table>'
                f'<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:8px;margin-top:3px;">{label}</div>'
                '</td>'
            )
        bandwidth_footnote = (
            f'{hourly_bandwidth[0].hour:%Y-%m-%d %H:%M}–{hourly_bandwidth[-1].hour:%H:%M} UTC — '
            f'peak {peak_hour.hour:%H:%M}: {_format_mb(peak_bytes)}'
        )
        bandwidth_section = f"""
<tr><td style="padding:4px 24px 20px 24px;border-top:1px solid {_BORDER};">
<div style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:13px;letter-spacing:1px;font-weight:600;margin:16px 0 10px 0;">BANDWIDTH BY HOUR</div>
<table cellpadding="0" cellspacing="0" border="0"><tr>
{''.join(bar_cells)}
</tr></table>
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:0.5px;margin-top:10px;">{escape(bandwidth_footnote)}</div>
</td></tr>
"""

    traffic_section = ''
    if traffic:
        traffic_header = (
            '<tr>'
            + ''.join(
                f'<th style="padding:6px 10px;text-align:{"right" if label != "DEVICE" else "left"};'
                f'color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:2px;font-weight:600;">{label}</th>'
                for label in ('DEVICE', 'UPLOAD', 'DOWNLOAD')
            )
            + '</tr>'
        )
        traffic_rows_html = ''.join(
            '<tr>'
            f'<td style="padding:6px 10px;border-top:1px solid {_BORDER};'
            f'color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;white-space:nowrap;">{escape(t.device_label)}</td>'
            f'<td style="padding:6px 10px;border-top:1px solid {_BORDER};text-align:right;'
            f'color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;white-space:nowrap;">{_format_mb(t.upload_bytes)}</td>'
            f'<td style="padding:6px 10px;border-top:1px solid {_BORDER};text-align:right;'
            f'color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:12px;white-space:nowrap;">{_format_mb(t.download_bytes)}</td>'
            '</tr>'
            for t in traffic
        )
        traffic_footnote = "Wired devices sharing a physical port aren't broken out individually — only a combined port total is measurable for them."
        if traffic_truncated:
            traffic_footnote = (
                f'...and {total_traffic_devices - len(traffic)} more device(s), smaller usage. ' + traffic_footnote
            )
        traffic_section = f"""
<tr><td style="padding:4px 24px 20px 24px;border-top:1px solid {_BORDER};">
<div style="color:{_TEXT_PRIMARY};font-family:{_MONO_STACK};font-size:13px;letter-spacing:1px;font-weight:600;margin:16px 0 10px 0;">DEVICE TRAFFIC</div>
<table cellpadding="0" cellspacing="0" border="0" width="100%">
{traffic_header}
{traffic_rows_html}
</table>
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:0.5px;margin-top:10px;line-height:1.5;">{escape(traffic_footnote)}</div>
</td></tr>
"""

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
{bandwidth_section}
{traffic_section}
<tr><td style="padding:14px 24px;background-color:{_SURFACE_ELEVATED};">
<div style="color:{_TEXT_MUTED};font-family:{_MONO_STACK};font-size:9px;letter-spacing:1px;">
Heimdall — self-hosted home network security monitor. This digest summarizes every alert regardless of severity, once a day, grouped by type.
</div>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>
"""
