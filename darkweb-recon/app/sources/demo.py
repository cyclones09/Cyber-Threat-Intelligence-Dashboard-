"""Offline demo fixtures.

Synthetic forum posts used by ``demo_mode`` so the full pipeline (matching,
scoring, selector extraction, scoring, dashboard) can be exercised without Tor
or a live source. All handles, wallets, and keys below are FABRICATED and
format-valid only — they do not correspond to real actors or addresses.
"""
from __future__ import annotations

from typing import AsyncIterator

from ..models import RawPost
from ..tor import TorClient
from .base import BaseSource

# Fabricated posts spanning several actors and threat categories.
_FIXTURES = [
    {
        "author": "nullroute",
        "title": "[SELLING] Corporate access — manufacturing, US",
        "body": (
            "Selling access to a US manufacturing company, ~$400M revenue. "
            "Domain admin, Fortinet VPN foothold confirmed. RDP access stable. "
            "Price negotiable, escrow only. Contact jabber: nullroute@exploit.im "
            "or Tox: 5F3A1C9D2B4E6A8C0F1D3B5E7A9C2D4F6B8E0A1C3D5F7B9E1A3C5D7F9B1E3A5C7D9F1B3E5A7C9D "
            "BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ),
    },
    {
        "author": "nullroute",
        "title": "Re: access prices",
        "body": (
            "Restock: shell access + webshell on a Citrix box, healthcare sector. "
            "Initial access broker, been doing this 3 years. XMR preferred: "
            "48jewgBkRdAuFc3foHU2WryJW5Bb2RNQ7nWh9k7e2k7e2k7e2k7e2k7e2k7e2k7e2k7e2k7e2k7e2k7e2k7e2k7e2kQ"
        ),
    },
    {
        "author": "locksmith_raas",
        "title": "[RECRUITING] Affiliate program — experienced pentesters",
        "body": (
            "Our ransomware affiliate program is now hiring. RaaS, 80/20 split. "
            "We provide the encryptor and negotiation support. Looking for partner "
            "with network access. Telegram: @locksmith_ops  PGP: 0xA1B2C3D4E5F60718"
        ),
    },
    {
        "author": "dumpstar",
        "title": "Fresh base — credit card fullz",
        "body": (
            "Selling fresh base, fullz with SSN and CVV. Database leak from a retail "
            "breach, 2M records. Combolist also available. Sample on request. "
            "ICQ: 728193044  email: dumpstar@onionmail.org"
        ),
    },
    {
        "author": "logmonger",
        "title": "Stealer logs — daily ULP cloud",
        "body": (
            "RedLine + Lumma stealer logs, daily upload. ULP format, cookies for "
            "sale with valid session tokens. Credential dump bundles too. "
            "Session: 05a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90 "
            "ETH: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        ),
    },
    {
        "author": "0daybroker",
        "title": "[SELLING] 0day loader + crypter FUD",
        "body": (
            "Fresh 0day, unpatched. Comes with a loader and FUD crypter, C2 panel "
            "included. command and control over HTTPS. Serious buyers only. "
            "jabber: 0daybroker@xmpp.jp"
        ),
    },
    {
        "author": "ghostwriter",
        "title": "General chat — weekend plans",
        "body": (
            "Just saying hi to everyone, hope you all have a good weekend. No "
            "business talk here, just hanging out. Anyone watching the football?"
        ),
    },
    {
        "author": "leverage_x",
        "title": "Anyone have data on acme-corp.com?",
        "body": (
            "Looking for initial access or any leaked db related to acme-corp.com. "
            "Will pay well. Also interested in Contoso credentials if anyone has "
            "stealer logs. Telegram: @leverage_x"
        ),
    },
]


class DemoSource(BaseSource):
    def __init__(self, spec: dict | None = None):
        super().__init__(spec or {"name": "demo_forum", "enabled": True})
        self.name = (spec or {}).get("name", "demo_forum")

    async def fetch(self, client: TorClient, max_pages: int) -> AsyncIterator[RawPost]:
        base = "http://demoforumplaceholder0000000000000000000000000000.onion/thread"
        for i, f in enumerate(_FIXTURES[:max_pages] if max_pages else _FIXTURES):
            yield RawPost(
                source=self.name,
                url=f"{base}/{i}",
                author=f["author"],
                title=f["title"],
                body=f["body"],
            )
