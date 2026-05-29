"""OBSIDIAN — dark web forum reconnaissance & threat-actor discovery engine.

A self-hosted CTI tool that crawls authorized dark-web forums over Tor, matches
posts against a weighted keyword taxonomy, extracts threat-actor selectors
(handles, Jabber/Tox/Telegram/Session IDs, PGP fingerprints, crypto wallets),
scores each post, and surfaces the results through a FastAPI dashboard + REST
API. Runs fully offline in demo mode against bundled fixtures.

For authorized defensive threat-intelligence use only. See README.
"""

__version__ = "0.1.0"
