"""Threat-actor selector extraction.

Pulls the artefacts that let an analyst pivot on, attribute, or report an actor:
contact handles (Jabber/XMPP, Tox, Telegram, Session, ICQ, email), PGP key
fingerprints, and cryptocurrency wallet addresses. These are the strings you
hand to law enforcement or feed into a graph for actor clustering.
"""
from __future__ import annotations

import re

# --- contact selectors -----------------------------------------------------
_JABBER = re.compile(
    r"(?:jabber|xmpp)\s*[:=]?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})",
    re.IGNORECASE,
)
_TELEGRAM = re.compile(
    r"(?:telegram|tg|t\.me/)\s*[:=@/]?\s*(@?[a-z0-9_]{4,32})", re.IGNORECASE
)
# Tox IDs are exactly 76 uppercase hex characters.
_TOX = re.compile(r"\b([0-9A-F]{76})\b")
# Session IDs are 66 hex chars starting with 05.
_SESSION = re.compile(r"\b(05[0-9a-f]{64})\b", re.IGNORECASE)
_ICQ = re.compile(r"\bICQ\s*[:#]?\s*(\d{6,12})\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b", re.IGNORECASE)

# --- PGP --------------------------------------------------------------------
# 40-hex-char fingerprint, or "0x" + 8/16 hex key id.
_PGP_FPR = re.compile(r"\b([0-9A-F]{40})\b")
_PGP_KEYID = re.compile(r"\b0x([0-9A-F]{8,16})\b", re.IGNORECASE)
_PGP_BLOCK = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----")

# --- cryptocurrency wallets -------------------------------------------------
# BTC: legacy/P2SH (1/3...) and bech32 (bc1...).
_BTC = re.compile(r"\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
# ETH: 0x + 40 hex.
_ETH = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
# Monero: 4/8 + 94 base58 chars.
_XMR = re.compile(r"\b([48][0-9AB][0-9a-zA-Z]{93})\b")
# Litecoin.
_LTC = re.compile(r"\b([LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{25,90})\b")


def _findall(pattern: re.Pattern, text: str) -> list[str]:
    return list(dict.fromkeys(pattern.findall(text)))  # dedup, keep order


def extract(text: str) -> dict[str, list[str]]:
    """Return a dict of selector-type -> unique values found in ``text``.

    Empty categories are omitted so downstream consumers only see real hits.
    """
    out: dict[str, list[str]] = {}

    def put(key: str, values: list[str]) -> None:
        values = [v for v in values if v]
        if values:
            out[key] = values

    put("jabber", _findall(_JABBER, text))
    put("telegram", [t.lstrip("@") for t in _findall(_TELEGRAM, text)])
    put("tox", _findall(_TOX, text))
    put("session", _findall(_SESSION, text))
    put("icq", _findall(_ICQ, text))

    # PGP: fingerprints first, then 0x key ids that are not already a 40-char fpr.
    fprs = _findall(_PGP_FPR, text)
    keyids = _findall(_PGP_KEYID, text)
    pgp = fprs + [k for k in keyids if k.upper() not in {f[-len(k):].upper() for f in fprs}]
    if _PGP_BLOCK.search(text):
        pgp.append("PGP_PUBLIC_KEY_BLOCK")
    put("pgp", pgp)

    # Wallets. Exclude ETH-looking strings from the PGP fingerprint set.
    put("btc", _findall(_BTC, text))
    put("eth", _findall(_ETH, text))
    put("xmr", _findall(_XMR, text))
    put("ltc", _findall(_LTC, text))

    # Emails that aren't already captured as jabber handles.
    jabber = set(out.get("jabber", []))
    put("email", [e for e in _findall(_EMAIL, text) if e not in jabber])

    return out
