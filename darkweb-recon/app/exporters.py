"""Export findings to JSON and defanged CSV for SIEM/case management."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone


def _defang(value: str) -> str:
    """Neutralise URLs/onions so they can't be accidentally clicked."""
    if "://" not in value:
        return value
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


def findings_to_json(findings: list[dict]) -> str:
    payload = {
        "tool": "OBSIDIAN",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def findings_to_csv(findings: list[dict], defang: bool = True) -> str:
    buf = io.StringIO()
    cols = ["fetched_at", "source", "author", "score", "confidence",
            "categories", "watchlist_hits", "url", "title", "selectors"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for f in findings:
        row = dict(f)
        row["categories"] = ",".join(f.get("categories", []))
        row["watchlist_hits"] = ",".join(f.get("watchlist_hits", []))
        row["selectors"] = json.dumps(f.get("selectors", {}), ensure_ascii=False)
        if defang:
            row["url"] = _defang(row.get("url", ""))
        w.writerow(row)
    return buf.getvalue()
