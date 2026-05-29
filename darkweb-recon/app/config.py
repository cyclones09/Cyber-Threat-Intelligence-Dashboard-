"""Configuration loading.

Settings come from ``config.yaml`` and may be overridden by ``OBSIDIAN_*``
environment variables. Keyword taxonomy and source registry live in their own
YAML files so analysts can iterate on detection content without touching code.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _env_override(key: str, current: Any) -> Any:
    """Return OBSIDIAN_<KEY> from the environment, coerced to type(current)."""
    raw = os.environ.get(f"OBSIDIAN_{key.upper()}")
    if raw is None:
        return current
    if isinstance(current, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    return raw


@dataclass
class Settings:
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    request_timeout: int = 60
    request_delay: float = 4.0
    max_pages_per_source: int = 25
    circuit_rotation_every: int = 0
    tor_control_port: int = 9051
    tor_control_password: str = ""
    demo_mode: bool = True
    database: str = "obsidian.db"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"

    @property
    def db_path(self) -> Path:
        p = Path(self.database)
        return p if p.is_absolute() else ROOT / p

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        data = _load_yaml(path or ROOT / "config.yaml")
        inst = cls()
        for f in inst.__dataclass_fields__:  # type: ignore[attr-defined]
            if f in data:
                setattr(inst, f, data[f])
            setattr(inst, f, _env_override(f, getattr(inst, f)))
        return inst


@dataclass
class KeywordCategory:
    name: str
    weight: int
    description: str
    patterns: list[re.Pattern]


@dataclass
class Taxonomy:
    categories: list[KeywordCategory] = field(default_factory=list)
    watchlist: list[re.Pattern] = field(default_factory=list)
    watchlist_terms: list[str] = field(default_factory=list)
    watchlist_weight: int = 12

    @staticmethod
    def _compile(term: str) -> re.Pattern:
        """Compile a pattern. Regex if it carries metacharacters, else a
        case-insensitive whole-word substring match."""
        if re.search(r"[\\^$.*+?()\[\]{}|]", term):
            return re.compile(term, re.IGNORECASE)
        return re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)

    @classmethod
    def load(cls, path: Path | None = None) -> "Taxonomy":
        data = _load_yaml(path or ROOT / "keywords.yaml")
        cats: list[KeywordCategory] = []
        for name, spec in (data.get("categories") or {}).items():
            cats.append(
                KeywordCategory(
                    name=name,
                    weight=int(spec.get("weight", 1)),
                    description=spec.get("description", ""),
                    patterns=[cls._compile(p) for p in spec.get("patterns", [])],
                )
            )
        terms = data.get("watchlist") or []
        return cls(
            categories=cats,
            watchlist=[cls._compile(t) for t in terms],
            watchlist_terms=list(terms),
            watchlist_weight=int(data.get("watchlist_weight", 12)),
        )


def load_sources(path: Path | None = None) -> list[dict[str, Any]]:
    data = _load_yaml(path or ROOT / "sources.yaml")
    return data.get("sources") or []
