"""Threat intelligence routes: feed status, IP lookup, DNS stats.

Deliberately left as a stub: every endpoint here needs sentinel/security/
(ThreatIntelService — OTX + feed downloads, DNS query source) per
docs/architecture/06-security-services.md, which hasn't been built yet.
"""
from flask import Blueprint

bp = Blueprint('threats', __name__)
