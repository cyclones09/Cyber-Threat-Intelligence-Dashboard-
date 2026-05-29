"""Shodan infrastructure enrichment.

Given an IP or domain extracted from a post (or an actor's infrastructure),
query the Shodan REST API for open ports, services, and host metadata. Requires
a free Shodan API key in the SHODAN_API_KEY environment variable; degrades
gracefully when absent.
"""
from __future__ import annotations

import os
import re

import httpx

from .base import EnrichmentResult

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_API = "https://api.shodan.io"


def _api_key() -> str | None:
    return os.environ.get("SHODAN_API_KEY")


async def _resolve(client: httpx.AsyncClient, domain: str, key: str) -> str | None:
    r = await client.get(f"{_API}/dns/resolve",
                         params={"hostnames": domain, "key": key})
    if r.status_code == 200:
        return r.json().get(domain)
    return None


async def enrich_host(value: str) -> EnrichmentResult:
    """Look up an IP or domain on Shodan."""
    value = value.strip()
    is_ip = bool(_IP_RE.match(value))
    sel_type = "ip" if is_ip else "domain"

    key = _api_key()
    if not key:
        return EnrichmentResult("shodan", sel_type, value, ok=False,
                                note="SHODAN_API_KEY not set — skipped")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            ip = value if is_ip else await _resolve(client, value, key)
            if not ip:
                return EnrichmentResult("shodan", sel_type, value, ok=False,
                                        note="could not resolve to an IP")
            r = await client.get(f"{_API}/shodan/host/{ip}", params={"key": key})
            if r.status_code == 404:
                return EnrichmentResult("shodan", sel_type, value, ok=True,
                                        findings=[], note="no Shodan records")
            r.raise_for_status()
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        return EnrichmentResult("shodan", sel_type, value, ok=False,
                                note=f"error: {exc}")

    findings = [{
        "ip": data.get("ip_str"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "country": data.get("country_name"),
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
    }]
    return EnrichmentResult("shodan", sel_type, value, ok=True,
                            findings=findings,
                            note=f"{len(data.get('ports', []))} open ports")
