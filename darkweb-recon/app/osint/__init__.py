"""OSINT enrichment connectors.

Pivot the threat-actor selectors extracted from dark-web posts (usernames,
emails, IPs/domains) against public OSINT sources to build a fuller actor
profile. Each connector degrades gracefully when its dependency or API key is
absent. These query CLEARNET public sources — not Tor.

For authorized investigative use only; results are leads, not confirmations.
"""
from __future__ import annotations

from .base import EnrichmentResult
from .sherlock import enrich_username
from .shodan import enrich_host

__all__ = ["EnrichmentResult", "enrich_username", "enrich_host"]
