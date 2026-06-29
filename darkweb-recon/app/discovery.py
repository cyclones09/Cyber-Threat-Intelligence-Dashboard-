"""Dark-web search-engine discovery (Robin-style).

Given a query (a name, brand, keyword), fan out across dark-web search engines
to discover candidate `.onion` URLs — no hand-curated forum list required.
Engines are queried over Tor; results are deduped and returned for scraping.

Ahmia has a clearnet gateway (ahmia.fi) so it works without Tor; the rest are
hidden services reached through the SOCKS proxy. In demo mode, a bundled set of
fabricated results is returned so the pipeline runs offline.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import quote, urljoin

from bs4 import BeautifulSoup

from .config import Settings
from .tor import TorClient


@dataclass
class SearchEngine:
    name: str
    # {query} is substituted with the URL-encoded query.
    search_url: str
    # CSS selector for result anchor tags pointing at .onion links.
    result_selector: str
    # If True, reachable on clearnet (no Tor needed).
    clearnet: bool = False


# Registry of dark-web search engines (subset of the well-known set).
ENGINES: list[SearchEngine] = [
    SearchEngine(
        name="ahmia",
        search_url="https://ahmia.fi/search/?q={query}",
        result_selector="li.result h4 a, a.result-link, .result a",
        clearnet=True,
    ),
    SearchEngine(
        name="ahmia_onion",
        search_url="http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
        result_selector="li.result h4 a, .result a",
    ),
    # Additional engines (Torch, OnionLand, etc.) can be added here with their
    # own onion search URL + result selector.
]


@dataclass
class DiscoveredUrl:
    url: str
    title: str
    engine: str


def _extract_onion(href: str) -> str | None:
    """Pull a clean .onion URL out of a (possibly redirect-wrapped) href."""
    if not href:
        return None
    # Ahmia wraps results as /search/redirect?redirect_url=<onion>
    if "redirect_url=" in href:
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(href).query)
        href = (qs.get("redirect_url") or [href])[0]
    if ".onion" in href:
        return href if href.startswith("http") else f"http://{href.lstrip('/')}"
    return None


async def _query_engine(client: TorClient, engine: SearchEngine,
                        query: str, limit: int) -> list[DiscoveredUrl]:
    url = engine.search_url.format(query=quote(query))
    try:
        resp = await client.get(url)
    except Exception:  # noqa: BLE001 - one dead engine shouldn't kill discovery
        return []
    if resp.status_code != 200:
        return []
    soup = BeautifulSoup(resp.text, "lxml")
    out: list[DiscoveredUrl] = []
    seen: set[str] = set()
    for a in soup.select(engine.result_selector):
        onion = _extract_onion(a.get("href", ""))
        if onion and onion not in seen:
            seen.add(onion)
            out.append(DiscoveredUrl(
                url=onion, title=a.get_text(strip=True), engine=engine.name))
        if len(out) >= limit:
            break
    return out


async def discover(settings: Settings, queries: list[str],
                   per_engine: int = 25) -> list[DiscoveredUrl]:
    """Run all queries across all engines, returning deduped onion URLs."""
    if settings.demo_mode:
        return _demo_discover(queries)

    results: dict[str, DiscoveredUrl] = {}
    async with TorClient(settings) as client:
        for q in queries:
            tasks = [_query_engine(client, e, q, per_engine) for e in ENGINES]
            for batch in await asyncio.gather(*tasks):
                for d in batch:
                    results.setdefault(d.url, d)
                await asyncio.sleep(settings.request_delay)
    return list(results.values())


# --- offline demo discovery -------------------------------------------------
def _demo_discover(queries: list[str]) -> list[DiscoveredUrl]:
    """Return fabricated 'discovered' onion URLs for demo mode.

    These map to the demo scrape fixtures so the full investigate pipeline runs
    offline. All addresses are placeholders.
    """
    base = "http://demoforumplaceholder0000000000000000000000000000.onion/thread"
    return [
        DiscoveredUrl(f"{base}/{i}", title=f"demo result {i}", engine="demo")
        for i in range(8)
    ]
