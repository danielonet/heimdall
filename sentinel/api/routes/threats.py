"""Threat intelligence routes: feed status, IP lookup, DNS stats (stub — Phase 2)."""
from flask import Blueprint

bp = Blueprint('threats', __name__)
