"""Human-readable mitigation guidance attached to threat alerts, so a finding
on the Alerts page tells a home user what to actually DO about it, not just
what was detected.

Built once per alert in SentinelScheduler._raise_threat_alert (see
sentinel/db/models.py:Alert.mitigation), so every attack-signal source that
already routes through that choke point (ArpWatcher, DhcpWatcher,
PassiveFingerprinter, NetworkScanner, Zeek, Suricata, OpenCanary) gets
consistent guidance for free — no per-caller wiring needed.

Deliberately NOT wired into RuleEngine (user-authored rules have no fixed
alert_type to key off) or the ML/statistical detector pipeline
(sentinel/detection/pipeline.py — anomalous-volume, signal-anomaly,
vendor-mismatch, new-device, etc.). Those are heuristic/probabilistic
signals worth a human's judgment, not a confirmed attack, so canned
"how to fix a real attack" copy would overstate their certainty.
"""
from __future__ import annotations

from typing import Callable, Optional

# Per-port advice for sentinel.security.scanner.HIGH_RISK_PORTS. Kept as its
# own dict rather than folded into HIGH_RISK_PORTS itself, so that dict can
# stay a simple port->name lookup without dragging remediation copy along
# wherever else it's used.
_HIGH_RISK_PORT_ADVICE: dict[int, str] = {
    21: 'FTP sends credentials in plaintext. Disable it in the device\'s admin settings, or '
        'switch to SFTP/FTPS if remote file transfer is actually needed.',
    23: 'Telnet sends credentials in plaintext and is a top target for IoT botnets. Log into '
        'the device and disable Telnet/remote CLI access; use SSH instead if you need remote access.',
    135: 'MSRPC has no business being reachable from the rest of the LAN. Check this device\'s '
         'firewall and confirm file/printer sharing isn\'t unintentionally exposed to the network.',
    139: 'NetBIOS file sharing is exposed. Disable "NetBIOS over TCP/IP" in the device\'s network '
         'adapter settings unless you specifically rely on legacy Windows file sharing.',
    445: 'SMB has been the entry point for major worms (WannaCry, EternalBlue). Make sure the '
         'device is fully patched and that SMBv1 is disabled.',
    512: 'rexec is an unauthenticated remote-execution protocol from the 1980s. Disable it — '
         'there is no legitimate reason to run this on a home network.',
    513: 'rlogin is an unauthenticated remote-login protocol from the 1980s. Disable it — use '
         'SSH instead if remote login is actually needed.',
    514: 'rsh is an unauthenticated remote-shell protocol from the 1980s. Disable it — there is '
         'no legitimate reason to run this on a home network.',
    1433: 'MSSQL is exposed to the LAN. Confirm it\'s configured to only accept local '
          'connections, and that it\'s fully patched.',
    3389: 'RDP is a leading ransomware entry point. Disable it if you don\'t use remote '
          'desktop, or restrict access to a VPN — never forward RDP to the internet.',
    5900: 'VNC often ships with a weak or no password. Set a strong VNC password immediately, '
          'or disable it if you don\'t use remote screen sharing.',
    4444: 'Port 4444 is Metasploit\'s default handler port — this usually means active '
          'exploitation, not a misconfigured service. Disconnect this device and investigate '
          'before reconnecting it.',
    31337: 'Port 31337 ("elite") is a classic backdoor signature (Back Orifice and similar). '
           'Treat this device as already compromised: isolate it and reinstall its OS from a '
           'known-clean source.',
}

_GENERIC_HIGH_RISK_PORT_ADVICE = (
    'This service has no business being reachable on an ordinary home LAN. Log into the '
    'device and disable it if unused, or restrict who can reach it if it\'s actually needed.'
)


def _high_risk_port_opened(raw_data: dict) -> str:
    advice = _HIGH_RISK_PORT_ADVICE.get(raw_data.get('port'), _GENERIC_HIGH_RISK_PORT_ADVICE)
    return f'{advice} Never forward this port from your router to the internet.'


def _vulnerability_detected(raw_data: dict) -> str:
    names = ', '.join((raw_data.get('findings') or {}).keys()) or 'The flagged script'
    return (
        f'"{names}" is a known-vulnerability signature, not something Heimdall can patch '
        f'remotely. Check the device manufacturer\'s support page for a firmware/software '
        f'update — most findings like this are fixed at the firmware level. If none exists '
        f'(e.g. end-of-life hardware), reduce exposure by quarantining the device or moving it '
        f'to a separate/guest network instead of the main LAN.'
    )


def _credential_exposure_detected(raw_data: dict) -> str:
    names = ', '.join((raw_data.get('findings') or {}).keys()) or 'A service on this device'
    return (
        f'"{names}" found a default or blank password still active. Log into the device\'s own '
        f'admin interface now and set a strong, unique password — unlike a vulnerability '
        f'finding, this is something you can fix yourself immediately. Until you do, treat the '
        f'device as already accessible to anyone on your LAN.'
    )


def _fingerprint_conflict(raw_data: dict, previous_key: str, active_key: str) -> str:
    previous = raw_data.get(previous_key, 'its previous signature')
    current = raw_data.get(active_key, 'a different signature')
    return (
        f'This MAC address looked like "{previous}" before and now looks like "{current}" — '
        f'usually a harmless OS/firmware update, but also how MAC-address spoofing shows up. '
        f'Physically confirm what\'s actually connected under this device\'s name; if you can\'t '
        f'account for it, block it from the Devices page.'
    )


def _arp_spoof(raw_data: dict) -> str:
    ip = raw_data.get('ip', 'This IP')
    old_mac = raw_data.get('old_mac', 'a known device')
    new_mac = raw_data.get('new_mac', 'an unrecognized device')
    return (
        f'{new_mac} just claimed {ip}, previously used by {old_mac} — a classic precursor to a '
        f'man-in-the-middle attack. If this device was auto-blocked, physically find and remove '
        f'it from the network. A frequent false positive: a second router/access point or VPN '
        f'client sharing the same interface — if that\'s the cause, no attack is happening, but '
        f'you should still resolve the address conflict.'
    )


def _rogue_dhcp(raw_data: dict) -> str:
    ip = raw_data.get('ip', 'An unknown device')
    return (
        f'{ip} just tried to hand out its own DHCP leases instead of your router — this lets it '
        f'silently reroute your traffic through itself. Physically locate and disconnect it now. '
        f'Common false positive: a second Wi-Fi router or travel router plugged in with its own '
        f'DHCP server still enabled — if that\'s the cause, disable DHCP on it.'
    )


def _dns_malicious_query(raw_data: dict) -> str:
    query = raw_data.get('query', 'a domain')
    return (
        f'This device queried "{query}", which is on a known malicious-domain blocklist — often '
        f'a sign of malware already running, a phishing page, or an ad/tracker network. Run a '
        f'malware scan on this device and check what app made the request.'
    )


def _c2_beaconing(raw_data: dict) -> str:
    dst = raw_data.get('dst', 'a remote host')
    return (
        f'This device is making unusually regular, clockwork connections to {dst} — a classic '
        f'sign of malware "phoning home" to a command-and-control server. Check what\'s running '
        f'on it (installed apps, background processes) and consider isolating it until you\'re '
        f'sure it\'s clean.'
    )


def _malware_detected(raw_data: dict) -> str:
    source = raw_data.get('source_ip', 'this device')
    return (
        f'ClamAV found malware in a file downloaded by {source}. The file itself was deleted '
        f'from Heimdall\'s scan queue automatically, but the device that fetched it likely still '
        f'has its own copy — run a full antivirus scan on it.'
    )


def _ids_signature_match(raw_data: dict) -> str:
    category = raw_data.get('category', 'a known attack pattern')
    return (
        f'Suricata matched traffic from this device against "{category}" — a known intrusion '
        f'signature. CRITICAL severity here usually means active exploitation: isolate the '
        f'device now. WARNING/INFO can include false positives from legitimate scanning tools '
        f'(including Heimdall\'s own nmap scans) — check the signature details before acting.'
    )


def _malicious_traffic_destination(raw_data: dict) -> str:
    ip = raw_data.get('remote_ip', 'a remote host')
    trigger_type = (raw_data.get('trigger_alert_type') or 'a traffic-volume alert').replace('_', ' ').lower()
    return (
        f'This device\'s traffic (flagged first by a {trigger_type}) was headed to {ip}, which threat '
        f'intelligence independently confirms is malicious — not a guess. If this device was auto-blocked, '
        f'leave it isolated and run a full malware scan before reconnecting it. Check what app or process on '
        f'the device initiated the connection.'
    )


def _honeypot_access(raw_data: dict) -> str:
    service = (raw_data.get('logdata') or {}).get('SERVICE', 'a decoy service')
    return (
        f'Something on your LAN just connected to Heimdall\'s "{service}" honeypot — nothing '
        f'legitimate should ever do this, since it\'s not a real service anyone should know '
        f'about. This is one of the strongest signals of an actively scanning or compromised '
        f'device on your network. Identify and isolate the source immediately.'
    )


_BUILDERS: dict[str, Callable[[dict], str]] = {
    'HIGH_RISK_PORT_OPENED': _high_risk_port_opened,
    'VULNERABILITY_DETECTED': _vulnerability_detected,
    'CREDENTIAL_EXPOSURE_DETECTED': _credential_exposure_detected,
    'OS_FINGERPRINT_CONFLICT': lambda raw: _fingerprint_conflict(raw, 'passive_os', 'active_os'),
    'FINGERPRINT_MISMATCH': lambda raw: _fingerprint_conflict(raw, 'previous_os', 'new_os'),
    'ARP_SPOOF': _arp_spoof,
    'ROGUE_DHCP_SERVER': _rogue_dhcp,
    'DNS_MALICIOUS_QUERY': _dns_malicious_query,
    'C2_BEACONING': _c2_beaconing,
    'MALWARE_DETECTED': _malware_detected,
    'IDS_SIGNATURE_MATCH': _ids_signature_match,
    'HONEYPOT_ACCESS': _honeypot_access,
    'MALICIOUS_TRAFFIC_DESTINATION': _malicious_traffic_destination,
}


def build_mitigation(alert_type: str, raw_data: Optional[dict]) -> Optional[str]:
    """Returns actionable "what to do about this" guidance for a threat
    alert, or None for alert types with no canned guidance (e.g. IP_CONFLICT,
    or anything from the ML/detector pipeline — see module docstring).

    Never raises: an unexpected raw_data shape (a field missing or the wrong
    type) falls back to None rather than crashing the caller — same
    defensive posture as sentinel/security/*_parser.py's parse_event().
    """
    builder = _BUILDERS.get(alert_type)
    if builder is None:
        return None
    try:
        return builder(raw_data or {})
    except Exception:
        return None
