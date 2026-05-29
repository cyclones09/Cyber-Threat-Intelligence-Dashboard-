"""Generic HTML forum adapter.

Scrapes any forum board given CSS selectors for thread links, post bodies, and
authors. This covers the majority of SMF/phpBB/XenForo-style boards common on
dark-web forums without writing a bespoke adapter per site.

Flow: for each configured board page, find thread links -> visit each thread,
extract every post body + author -> yield one RawPost per post.
"""
from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..models import RawPost
from ..tor import TorClient
from .base import BaseSource


class GenericHtmlSource(BaseSource):
    def __init__(self, spec: dict[str, Any]):
        super().__init__(spec)
        self.board_paths: list[str] = spec.get("board_paths", [])
        self.selectors: dict[str, str] = spec.get("selectors", {})
        self.cookie: str = spec.get("cookie", "")
        self.delay: float = float(spec.get("request_delay", 4.0))

    def _sel(self, key: str, default: str = "") -> str:
        return self.selectors.get(key, default)

    async def _soup(self, client: TorClient, url: str) -> BeautifulSoup | None:
        try:
            resp = await client.get(url, cookie=self.cookie)
        except Exception:  # noqa: BLE001 - skip unreachable pages, keep crawling
            return None
        if resp.status_code != 200:
            return None
        return BeautifulSoup(resp.text, "lxml")

    async def fetch(self, client: TorClient, max_pages: int) -> AsyncIterator[RawPost]:
        thread_urls: list[str] = []
        for path in self.board_paths:
            board_url = urljoin(self.base_url, path)
            soup = await self._soup(client, board_url)
            await asyncio.sleep(self.delay)
            if not soup:
                continue
            for a in soup.select(self._sel("thread_link", "a")):
                href = a.get("href")
                if href:
                    thread_urls.append(urljoin(self.base_url, href))
                if len(thread_urls) >= max_pages:
                    break
            if len(thread_urls) >= max_pages:
                break

        seen: set[str] = set()
        for turl in thread_urls[:max_pages]:
            if turl in seen:
                continue
            seen.add(turl)
            soup = await self._soup(client, turl)
            await asyncio.sleep(self.delay)
            if not soup:
                continue

            title_el = soup.select_one(self._sel("thread_title", "title"))
            title = title_el.get_text(strip=True) if title_el else ""

            bodies = soup.select(self._sel("post_body", "body"))
            authors = soup.select(self._sel("post_author", ""))
            for i, body_el in enumerate(bodies):
                body = body_el.get_text(" ", strip=True)
                if not body:
                    continue
                author = (
                    authors[i].get_text(strip=True)
                    if i < len(authors) else "unknown"
                )
                yield RawPost(
                    source=self.name, url=turl, author=author or "unknown",
                    title=title, body=body,
                )
