"""VirusTotal enrichment.

Looks up a domain, IP, or file hash on VirusTotal (API v3) and returns its
reputation + antivirus detection stats. Useful for scoring the infrastructure
and indicators that surface in dark-web posts.

Requires a free VirusTotal API key in the VIRUSTOTAL_API_KEY environment
variable; degrades gracefully (skipped) when absent. Free keys are rate-limited
(~4 lookups/min), so this is used sparingly.
"""
from __future__ import annotations

import os
import re

import httpx

from .base import EnrichmentResult

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_API = "https://www.virustotal.com/api/v3"


def _api_key() -> str | None:
    return os.environ.get("VIRUSTOTAL_API_KEY")


def _endpoint(value: str) -> tuple[str, str]:
    """Return (endpoint_path, selector_type) for the indicator."""
    if _IP_RE.match(value):
        return f"/ip_addresses/{value}", "ip"
    if _HASH_RE.match(value):
        return f"/files/{value}", "hash"
    return f"/domains/{value}", "domain"


async def enrich_virustotal(value: str) -> EnrichmentResult:
    """Look up a domain / IP / file hash on VirusTotal."""
    value = value.strip()
    path, sel_type = _endpoint(value)

    key = _api_key()
    if not key:
        return EnrichmentResult("virustotal", sel_type, value, ok=False,
                                note="VIRUSTOTAL_API_KEY not set — skipped")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{_API}{path}",
                                 headers={"x-apikey": key})
            if r.status_code == 404:
                return EnrichmentResult("virustotal", sel_type, value, ok=True,
                                        findings=[], note="not found on VirusTotal")
            if r.status_code == 401:
                return EnrichmentResult("virustotal", sel_type, value, ok=False,
                                        note="invalid API key (401)")
            if r.status_code == 429:
                return EnrichmentResult("virustotal", sel_type, value, ok=False,
                                        note="rate limited (429) — try again later")
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
    except Exception as exc:  # noqa: BLE001
        return EnrichmentResult("virustotal", sel_type, value, ok=False,
                                note=f"error: {exc}")

    stats = attrs.get("last_analysis_stats", {}) or {}
    finding = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
    }
    if sel_type == "domain" and attrs.get("categories"):
        finding["categories"] = list(attrs["categories"].values())[:5]
    if sel_type == "hash":
        finding["name"] = attrs.get("meaningful_name") or attrs.get("type_description")
    flagged = finding["malicious"] + finding["suspicious"]
    return EnrichmentResult(
        "virustotal", sel_type, value, ok=True, findings=[finding],
        note=f"{flagged} engines flagged it" if flagged else "clean",
    )
