"""Domain models passed between the scraper, matcher, and storage layers."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class RawPost:
    """A single forum post as pulled from a source, before analysis."""

    source: str
    url: str
    author: str
    title: str
    body: str
    fetched_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def fingerprint(self) -> str:
        """Stable hash used for dedup across runs (source + url + body)."""
        h = hashlib.sha256()
        h.update(self.source.encode())
        h.update(self.url.encode())
        h.update(self.body.encode())
        return h.hexdigest()


@dataclass
class KeywordHit:
    category: str
    term: str
    weight: int


@dataclass
class AnalyzedPost:
    """A RawPost enriched with matches, extracted selectors, and a score."""

    post: RawPost
    score: int = 0
    confidence: str = "low"
    hits: list[KeywordHit] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    watchlist_hits: list[str] = field(default_factory=list)
    selectors: dict[str, list[str]] = field(default_factory=dict)

    def to_row(self) -> dict:
        return {
            "fingerprint": self.post.fingerprint,
            "source": self.post.source,
            "url": self.post.url,
            "author": self.post.author,
            "title": self.post.title,
            "body": self.post.body,
            "fetched_at": self.post.fetched_at,
            "score": self.score,
            "confidence": self.confidence,
            "categories": ",".join(self.categories),
            "watchlist_hits": ",".join(self.watchlist_hits),
            "hits": ";".join(f"{h.category}:{h.term}" for h in self.hits),
            "selectors": _selectors_to_str(self.selectors),
        }


def _selectors_to_str(selectors: dict[str, list[str]]) -> str:
    import json

    return json.dumps(selectors, ensure_ascii=False)
