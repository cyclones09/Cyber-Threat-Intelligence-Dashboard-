"""SQLite persistence (stdlib only — no ORM, no extra deps).

Stores analyzed posts (deduped by fingerprint) and a log of scan runs. The
``findings`` table is the analyst's queue; ``runs`` is the audit trail.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .models import AnalyzedPost

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint    TEXT PRIMARY KEY,
    source         TEXT NOT NULL,
    url            TEXT,
    author         TEXT,
    title          TEXT,
    body           TEXT,
    fetched_at     TEXT,
    first_seen     TEXT,
    last_seen      TEXT,
    score          INTEGER,
    confidence     TEXT,
    categories     TEXT,
    watchlist_hits TEXT,
    hits           TEXT,
    selectors      TEXT,
    reviewed       INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_author ON findings(author);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT,
    finished_at TEXT,
    mode        TEXT,
    sources     TEXT,
    posts_seen  INTEGER,
    findings    INTEGER,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS investigations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT,
    objective       TEXT,
    refined_queries TEXT,
    sources_count   INTEGER,
    findings_count  INTEGER,
    summary         TEXT,
    source_links    TEXT
);

CREATE TABLE IF NOT EXISTS osint (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT,
    connector      TEXT,
    selector_type  TEXT,
    selector_value TEXT,
    ok             INTEGER,
    findings       TEXT,
    note           TEXT
);
"""


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._init()

    def _init(self) -> None:
        with self.connect() as con:
            con.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    # --- writes ------------------------------------------------------------
    def upsert_finding(self, a: AnalyzedPost) -> bool:
        """Insert a finding or refresh last_seen if already known.

        Returns True if this was a new finding.
        """
        row = a.to_row()
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as con:
            existing = con.execute(
                "SELECT fingerprint FROM findings WHERE fingerprint=?",
                (row["fingerprint"],),
            ).fetchone()
            if existing:
                con.execute(
                    "UPDATE findings SET last_seen=?, score=?, confidence=? "
                    "WHERE fingerprint=?",
                    (now, row["score"], row["confidence"], row["fingerprint"]),
                )
                return False
            con.execute(
                """INSERT INTO findings
                   (fingerprint, source, url, author, title, body, fetched_at,
                    first_seen, last_seen, score, confidence, categories,
                    watchlist_hits, hits, selectors)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["fingerprint"], row["source"], row["url"], row["author"],
                    row["title"], row["body"], row["fetched_at"], now, now,
                    row["score"], row["confidence"], row["categories"],
                    row["watchlist_hits"], row["hits"], row["selectors"],
                ),
            )
            return True

    def log_run(self, mode: str, sources: list[str], started: str,
                posts_seen: int, findings: int, notes: str = "") -> None:
        with self.connect() as con:
            con.execute(
                """INSERT INTO runs
                   (started_at, finished_at, mode, sources, posts_seen, findings, notes)
                   VALUES (?,?,?,?,?,?,?)""",
                (started, datetime.now(timezone.utc).isoformat(), mode,
                 ",".join(sources), posts_seen, findings, notes),
            )

    def log_investigation(self, objective: str, refined: list[str],
                          sources_count: int, findings_count: int,
                          summary: str, source_links: list[str]) -> int:
        with self.connect() as con:
            cur = con.execute(
                """INSERT INTO investigations
                   (created_at, objective, refined_queries, sources_count,
                    findings_count, summary, source_links)
                   VALUES (?,?,?,?,?,?,?)""",
                (datetime.now(timezone.utc).isoformat(), objective,
                 json.dumps(refined), sources_count, findings_count, summary,
                 json.dumps(source_links)),
            )
            return cur.lastrowid

    def save_osint(self, result: dict) -> None:
        with self.connect() as con:
            con.execute(
                """INSERT INTO osint
                   (created_at, connector, selector_type, selector_value, ok,
                    findings, note)
                   VALUES (?,?,?,?,?,?,?)""",
                (datetime.now(timezone.utc).isoformat(), result["connector"],
                 result["selector_type"], result["selector_value"],
                 1 if result["ok"] else 0, json.dumps(result["findings"]),
                 result.get("note", "")),
            )

    def investigations(self, limit: int = 50) -> list[dict]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM investigations ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["refined_queries"] = json.loads(d.get("refined_queries") or "[]")
            d["source_links"] = json.loads(d.get("source_links") or "[]")
            out.append(d)
        return out

    def osint_results(self, limit: int = 500) -> list[dict]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM osint ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["ok"] = bool(d["ok"])
            d["findings"] = json.loads(d.get("findings") or "[]")
            out.append(d)
        return out

    def set_reviewed(self, fingerprint: str, reviewed: bool = True) -> None:
        with self.connect() as con:
            con.execute(
                "UPDATE findings SET reviewed=? WHERE fingerprint=?",
                (1 if reviewed else 0, fingerprint),
            )

    # --- reads -------------------------------------------------------------
    def findings(self, limit: int = 200, min_score: int = 0,
                 source: str | None = None, author: str | None = None,
                 confidence: str | None = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE score >= ?"
        params: list = [min_score]
        if source:
            q += " AND source = ?"; params.append(source)
        if author:
            q += " AND author = ?"; params.append(author)
        if confidence:
            q += " AND confidence = ?"; params.append(confidence)
        q += " ORDER BY score DESC, last_seen DESC LIMIT ?"
        params.append(limit)
        with self.connect() as con:
            return [_decode(dict(r)) for r in con.execute(q, params).fetchall()]

    def actors(self, limit: int = 100) -> list[dict]:
        """Aggregate findings by author into a threat-actor leaderboard."""
        with self.connect() as con:
            rows = con.execute("SELECT * FROM findings").fetchall()
        by_author: dict[str, dict] = {}
        for r in rows:
            d = _decode(dict(r))
            a = d["author"] or "unknown"
            entry = by_author.setdefault(a, {
                "author": a, "posts": 0, "max_score": 0, "total_score": 0,
                "sources": set(), "categories": Counter(), "selectors": {},
            })
            entry["posts"] += 1
            entry["max_score"] = max(entry["max_score"], d["score"])
            entry["total_score"] += d["score"]
            entry["sources"].add(d["source"])
            for c in d["categories"]:
                entry["categories"][c] += 1
            for k, vals in d["selectors"].items():
                entry["selectors"].setdefault(k, set()).update(vals)
        out = []
        for e in by_author.values():
            e["sources"] = sorted(e["sources"])
            e["categories"] = dict(e["categories"])
            e["selectors"] = {k: sorted(v) for k, v in e["selectors"].items()}
            out.append(e)
        out.sort(key=lambda x: (x["max_score"], x["total_score"]), reverse=True)
        return out[:limit]

    def stats(self) -> dict:
        with self.connect() as con:
            total = con.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
            high = con.execute(
                "SELECT COUNT(*) c FROM findings WHERE confidence='high'"
            ).fetchone()["c"]
            watch = con.execute(
                "SELECT COUNT(*) c FROM findings WHERE watchlist_hits != ''"
            ).fetchone()["c"]
            authors = con.execute(
                "SELECT COUNT(DISTINCT author) c FROM findings"
            ).fetchone()["c"]
            runs = con.execute("SELECT COUNT(*) c FROM runs").fetchone()["c"]
            invs = con.execute(
                "SELECT COUNT(*) c FROM investigations").fetchone()["c"]
        return {
            "findings": total, "high_confidence": high,
            "watchlist_hits": watch, "actors": authors, "runs": runs,
            "investigations": invs,
        }


def _decode(row: dict) -> dict:
    row["categories"] = [c for c in (row.get("categories") or "").split(",") if c]
    row["watchlist_hits"] = [
        c for c in (row.get("watchlist_hits") or "").split(",") if c
    ]
    try:
        row["selectors"] = json.loads(row.get("selectors") or "{}")
    except json.JSONDecodeError:
        row["selectors"] = {}
    return row
