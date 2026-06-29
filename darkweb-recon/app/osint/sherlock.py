"""Sherlock-style username enumeration.

Given an actor handle, check which sites have an account under that name. Two
backends:

1. If the `sherlock` CLI is installed, shell out to it (full 400+ site coverage).
2. Otherwise, use a built-in lightweight checker against a curated site list —
   no install required, works out of the box.

Runs over CLEARNET. For authorized investigative pivoting only.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile

import httpx

from .base import EnrichmentResult

# Built-in site list: name -> (profile URL template, absence marker).
# A 200 response without the marker implies the username exists.
_SITES = {
    "GitHub": ("https://github.com/{}", None),
    "GitLab": ("https://gitlab.com/{}", None),
    "Reddit": ("https://www.reddit.com/user/{}", None),
    "Telegram": ("https://t.me/{}", None),
    "Keybase": ("https://keybase.io/{}", None),
    "Twitter/X": ("https://twitter.com/{}", None),
    "Instagram": ("https://www.instagram.com/{}/", None),
    "Pastebin": ("https://pastebin.com/u/{}", None),
    "TikTok": ("https://www.tiktok.com/@{}", None),
    "HackerNews": ("https://news.ycombinator.com/user?id={}", "No such user."),
}

_UA = "Mozilla/5.0 (compatible; OBSIDIAN-CTI/0.1; +osint-pivot)"


def _sherlock_cli_path() -> str | None:
    return shutil.which("sherlock")


async def _check_site(client: httpx.AsyncClient, name: str, template: str,
                      marker: str | None, username: str) -> dict | None:
    url = template.format(username)
    try:
        r = await client.get(url, headers={"User-Agent": _UA})
    except Exception:  # noqa: BLE001
        return None
    if r.status_code == 200 and (marker is None or marker not in r.text):
        return {"site": name, "url": url}
    return None


async def _builtin(username: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        tasks = [
            _check_site(client, name, tpl, marker, username)
            for name, (tpl, marker) in _SITES.items()
        ]
        results = await asyncio.gather(*tasks)
    return [r for r in results if r]


async def _via_cli(username: str) -> list[dict]:
    """Run the sherlock CLI and parse its JSON output."""
    with tempfile.TemporaryDirectory() as tmp:
        proc = await asyncio.create_subprocess_exec(
            "sherlock", username, "--timeout", "10", "--print-found",
            "--folderoutput", tmp, "--no-color",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
    findings: list[dict] = []
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("[+]") and "http" in line:
            # Format: "[+] SiteName: https://..."
            rest = line[3:].strip()
            site, _, url = rest.partition(":")
            findings.append({"site": site.strip(), "url": url.strip()})
    return findings


async def enrich_username(username: str, prefer_cli: bool = True) -> EnrichmentResult:
    """Find accounts matching `username` across public sites."""
    username = username.strip().lstrip("@")
    if not username or len(username) < 3:
        return EnrichmentResult("sherlock", "username", username, ok=False,
                                note="username too short to pivot")
    try:
        if prefer_cli and _sherlock_cli_path():
            findings = await _via_cli(username)
            backend = "sherlock-cli"
        else:
            findings = await _builtin(username)
            backend = "builtin"
    except Exception as exc:  # noqa: BLE001
        return EnrichmentResult("sherlock", "username", username, ok=False,
                                note=f"error: {exc}")
    return EnrichmentResult(
        "sherlock", "username", username, ok=True, findings=findings,
        note=f"backend={backend}, {len(findings)} hits",
    )
