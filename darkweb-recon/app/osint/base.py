"""Shared types for OSINT enrichment connectors."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EnrichmentResult:
    """One connector's output for one selector value."""

    connector: str          # "sherlock" | "shodan" | ...
    selector_type: str      # "username" | "ip" | "domain" | "email"
    selector_value: str
    ok: bool
    findings: list[dict] = field(default_factory=list)
    note: str = ""          # e.g. why it was skipped

    def to_dict(self) -> dict:
        return {
            "connector": self.connector,
            "selector_type": self.selector_type,
            "selector_value": self.selector_value,
            "ok": self.ok,
            "findings": self.findings,
            "note": self.note,
        }
