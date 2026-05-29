"""Parallel onion page scraping.

Fetches discovered `.onion` URLs over Tor and extracts readable text into
`RawPost` objects for the analysis pipeline. Unlike the structured forum
adapter (`sources/generic_html.py`), this handles arbitrary pages — it pulls
the title and the main text body and treats the page as a single document.

In demo mode it returns the bundled fixtures so the pipeline runs offline.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .config import Settings
from .discovery import DiscoveredUrl
from .models import RawPost
from .sources.demo import _FIXTURES
from .tor import TorClient


def _readable_text(html: str) -> tuple[str, str]:
    """Return (title, body_text) from raw HTML, stripping script/style."""
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    title = soup.title.get_text(strip=True) if soup.title else ""
    body = soup.get_text(" ", strip=True)
    return title, body


async def _scrape_one(client: TorClient, d: DiscoveredUrl) -> RawPost | None:
    try:
        resp = await client.get(d.url)
    except Exception:  # noqa: BLE001 - skip dead onions
        return None
    if resp.status_code != 200 or not resp.text:
        return None
    title, body = _readable_text(resp.text)
    if not body:
        return None
    host = urlparse(d.url).netloc
    return RawPost(
        source=d.engine or host,
        url=d.url,
        author=host,  # author unknown for arbitrary pages; host is the pivot
        title=title or d.title,
        body=body[:20000],  # cap to keep matching/LLM token bounds sane
    )


async def scrape_multiple(settings: Settings,
                          discovered: list[DiscoveredUrl]) -> list[RawPost]:
    """Scrape all discovered URLs (sequential with politeness delay over Tor)."""
    if settings.demo_mode:
        return _demo_scrape(discovered)

    posts: list[RawPost] = []
    async with TorClient(settings) as client:
        for d in discovered:
            post = await _scrape_one(client, d)
            if post:
                posts.append(post)
            await asyncio.sleep(settings.request_delay)
    return posts


def _demo_scrape(discovered: list[DiscoveredUrl]) -> list[RawPost]:
    """Map fabricated discovery results to the demo fixtures."""
    posts: list[RawPost] = []
    for i, d in enumerate(discovered):
        f = _FIXTURES[i % len(_FIXTURES)]
        posts.append(RawPost(
            source="demo_search", url=d.url, author=f["author"],
            title=f["title"], body=f["body"],
        ))
    return posts
