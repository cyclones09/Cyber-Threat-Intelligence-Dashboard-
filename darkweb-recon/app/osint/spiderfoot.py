"""SpiderFoot OSINT-automation enrichment.

SpiderFoot runs as its own service (its web UI exposes an HTTP API). This
connector talks to a running instance: it starts a scan against a target
(domain, IP, email, username, or name — SpiderFoot auto-detects the type),
polls until the scan finishes, then pulls the collected events back as findings.

Point it at your instance with the SPIDERFOOT_URL environment variable
(e.g. http://127.0.0.1:5001). Start one with:  python3 sf.py -l 127.0.0.1:5001
Degrades gracefully (skipped) when SPIDERFOOT_URL is unset or unreachable.

SpiderFoot scans are slow (minutes) and noisy, so this is opt-in — it is not
run on every actor automatically.
"""
from __future__ import annotations

import asyncio
import os
import re

import httpx

from .base import EnrichmentResult

# Scan lifecycle states SpiderFoot reports; the first set is terminal.
_TERMINAL = {"FINISHED", "ABORTED", "ERROR-FAILED", "ABORT-REQUESTED"}
_KNOWN_STATUSES = _TERMINAL | {"RUNNING", "STARTING", "INITIALIZING", "CREATED"}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _base_url() -> str | None:
    url = os.environ.get("SPIDERFOOT_URL")
    return url.rstrip("/") if url else None


def _guess_type(target: str) -> str:
    if _IP_RE.match(target):
        return "ip"
    if _EMAIL_RE.match(target):
        return "email"
    if "." in target and " " not in target:
        return "domain"
    return "username/name"


def _scan_id_from_start(resp: httpx.Response) -> str | None:
    """SpiderFoot's /startscan returns ["SUCCESS", "", "<scan_id>"] with cli=1."""
    try:
        data = resp.json()
        if isinstance(data, list) and len(data) >= 3 and data[0] == "SUCCESS":
            return data[2]
    except Exception:  # noqa: BLE001
        pass
    # Fallback: a redirect to /scaninfo?id=<scan_id>
    loc = resp.headers.get("location", "")
    m = re.search(r"id=([A-F0-9]+)", loc, re.IGNORECASE)
    return m.group(1) if m else None


def _row_status(row: list) -> str | None:
    for cell in row:
        if isinstance(cell, str) and cell.upper() in _KNOWN_STATUSES:
            return cell.upper()
    return None


async def _poll_until_done(client: httpx.AsyncClient, base: str, scan_id: str,
                           timeout: int, interval: float) -> str:
    waited = 0.0
    while waited < timeout:
        try:
            r = await client.get(f"{base}/scanlist")
            rows = r.json()
        except Exception:  # noqa: BLE001
            rows = []
        for row in rows:
            if isinstance(row, list) and row and row[0] == scan_id:
                status = _row_status(row)
                if status in _TERMINAL:
                    return status
        await asyncio.sleep(interval)
        waited += interval
    return "TIMEOUT"


def _parse_events(rows: list) -> list[dict]:
    """Compact SpiderFoot event rows into {type, data, module}.

    Row layout (defensive): [generated, data, source_data, module, type, ...,
    event_descr(~10), event_type(~11), ...]. Indices vary by version, so we
    guard every access.
    """
    findings: list[dict] = []
    for row in rows:
        if not isinstance(row, list):
            continue
        data = row[1] if len(row) > 1 else ""
        module = row[3] if len(row) > 3 else ""
        etype = row[10] if len(row) > 10 else (row[4] if len(row) > 4 else "")
        if data:
            findings.append({"type": etype, "data": str(data)[:300],
                             "module": module})
    return findings


async def enrich_spiderfoot(target: str, usecase: str = "Investigate",
                            timeout: int | None = None,
                            poll_interval: float = 5.0,
                            max_findings: int = 200) -> EnrichmentResult:
    """Run a SpiderFoot scan against `target` and return its events.

    usecase: one of "all" | "Footprint" | "Investigate" | "Passive".
    """
    target = target.strip()
    sel_type = _guess_type(target)
    base = _base_url()
    if not base:
        return EnrichmentResult("spiderfoot", sel_type, target, ok=False,
                                note="SPIDERFOOT_URL not set — skipped")
    timeout = timeout or int(os.environ.get("SPIDERFOOT_TIMEOUT", "300"))

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            start = await client.post(f"{base}/startscan", data={
                "scanname": f"obsidian-{target}",
                "scantarget": target,
                "usecase": usecase,
                "modulelist": "",
                "typelist": "",
                "cli": "1",
            })
            scan_id = _scan_id_from_start(start)
            if not scan_id:
                return EnrichmentResult("spiderfoot", sel_type, target, ok=False,
                                        note="could not start scan (bad response)")

            status = await _poll_until_done(client, base, scan_id,
                                            timeout, poll_interval)
            if status == "TIMEOUT":
                return EnrichmentResult("spiderfoot", sel_type, target, ok=False,
                                        note=f"scan {scan_id} still running after "
                                             f"{timeout}s")

            res = await client.get(f"{base}/scaneventresults", params={
                "id": scan_id, "eventType": "ALL", "filterfp": "true",
            })
            rows = res.json() if res.status_code == 200 else []
    except Exception as exc:  # noqa: BLE001
        return EnrichmentResult("spiderfoot", sel_type, target, ok=False,
                                note=f"error: {exc}")

    findings = _parse_events(rows)[:max_findings]
    return EnrichmentResult(
        "spiderfoot", sel_type, target, ok=True, findings=findings,
        note=f"scan {scan_id} {status}, {len(findings)} events",
    )
