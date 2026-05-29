"""Keyword matching, threat scoring, and confidence rating.

A post's score is the sum of the weights of every keyword category it hits
(counted once per category), plus the watchlist weight for any watchlist match.
Confidence reflects corroboration: how many independent signals (distinct
categories + watchlist + extracted selectors) point at the same post.
"""
from __future__ import annotations

from .config import Taxonomy
from .extractors import extract
from .models import AnalyzedPost, KeywordHit, RawPost


def _confidence(num_signals: int, has_watchlist: bool) -> str:
    if has_watchlist and num_signals >= 2:
        return "high"
    if num_signals >= 3:
        return "high"
    if num_signals == 2:
        return "medium"
    return "low"


def analyze(post: RawPost, taxonomy: Taxonomy) -> AnalyzedPost:
    """Score and enrich a single post against the taxonomy."""
    haystack = f"{post.title}\n{post.body}"
    result = AnalyzedPost(post=post)

    matched_categories: set[str] = set()
    for cat in taxonomy.categories:
        for pat in cat.patterns:
            m = pat.search(haystack)
            if m:
                result.hits.append(
                    KeywordHit(category=cat.name, term=m.group(0), weight=cat.weight)
                )
        if any(h.category == cat.name for h in result.hits):
            matched_categories.add(cat.name)
            result.score += cat.weight

    result.categories = sorted(matched_categories)

    for pat, term in zip(taxonomy.watchlist, taxonomy.watchlist_terms):
        if pat.search(haystack):
            result.watchlist_hits.append(term)
    if result.watchlist_hits:
        result.score += taxonomy.watchlist_weight

    result.selectors = extract(haystack)

    # Signals = distinct keyword categories + watchlist presence + selector types.
    signals = len(matched_categories) + len(result.selectors)
    if result.watchlist_hits:
        signals += 1
    result.confidence = _confidence(signals, bool(result.watchlist_hits))
    return result


def analyze_many(posts: list[RawPost], taxonomy: Taxonomy) -> list[AnalyzedPost]:
    analyzed = [analyze(p, taxonomy) for p in posts]
    # Only surface posts that actually matched something.
    return [a for a in analyzed if a.score > 0]
