"""Forum source adapters.

Each adapter yields ``RawPost`` objects from one forum/market. ``build_source``
maps a registry entry (from ``sources.yaml``) to a concrete adapter instance.
"""
from __future__ import annotations

from typing import Any

from .base import BaseSource
from .generic_html import GenericHtmlSource


def build_source(spec: dict[str, Any]) -> BaseSource:
    stype = spec.get("type", "generic_html")
    if stype == "generic_html":
        return GenericHtmlSource(spec)
    raise ValueError(f"unknown source type: {stype}")


__all__ = ["BaseSource", "GenericHtmlSource", "build_source"]
