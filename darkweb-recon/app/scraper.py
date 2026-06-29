"""Scan orchestration.

Ties the pieces together: pick sources (live or demo), pull posts over Tor,
analyze them against the taxonomy, persist findings, and log the run.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .config import Settings, Taxonomy, load_sources
from .db import Database
from .matcher import analyze_many
from .models import RawPost
from .sources import build_source
from .sources.demo import DemoSource
from .tor import TorClient


async def collect_posts(settings: Settings) -> tuple[list[RawPost], list[str]]:
    """Pull raw posts from all enabled sources (or the demo source)."""
    posts: list[RawPost] = []
    used: list[str] = []

    if settings.demo_mode:
        # Offline path: no Tor, no SOCKS dependency — read bundled fixtures.
        src = DemoSource({"name": "demo_forum"})
        used.append(src.name)
        async for p in src.fetch(None, settings.max_pages_per_source):
            posts.append(p)
        return posts, used

    specs = [s for s in load_sources() if s.get("enabled", True)]
    async with TorClient(settings) as client:
        chk = await client.check()
        if not chk.get("ok"):
            raise RuntimeError(
                f"Tor egress check failed: {chk.get('reason', 'not routing via Tor')}"
            )
        for spec in specs:
            src = build_source(spec)
            used.append(src.name)
            async for p in src.fetch(client, settings.max_pages_per_source):
                posts.append(p)
    return posts, used


async def run_scan(settings: Settings | None = None,
                   taxonomy: Taxonomy | None = None,
                   db: Database | None = None) -> dict:
    """Execute one full scan cycle and return a summary."""
    settings = settings or Settings.load()
    taxonomy = taxonomy or Taxonomy.load()
    db = db or Database(settings.db_path)

    started = datetime.now(timezone.utc).isoformat()
    posts, used = await collect_posts(settings)
    analyzed = analyze_many(posts, taxonomy)

    new = 0
    for a in analyzed:
        if db.upsert_finding(a):
            new += 1

    mode = "demo" if settings.demo_mode else "live"
    db.log_run(mode, used, started, len(posts), len(analyzed))

    return {
        "mode": mode,
        "sources": used,
        "posts_seen": len(posts),
        "matched": len(analyzed),
        "new_findings": new,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
