#!/usr/bin/env python3
"""OBSIDIAN command-line interface.

Examples:
  python cli.py scan                 # run one scan cycle (honours config.yaml)
  python cli.py scan --live          # force live Tor mode for this run
  python cli.py findings --min 15    # list findings with score >= 15
  python cli.py actors               # threat-actor leaderboard
  python cli.py tor-check            # verify Tor egress
  python cli.py export json -o out.json
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import Settings, Taxonomy
from app.db import Database
from app.exporters import findings_to_csv, findings_to_json
from app.scraper import run_scan
from app.tor import TorClient


def _ctx(args) -> tuple[Settings, Taxonomy, Database]:
    settings = Settings.load()
    if getattr(args, "live", False):
        settings.demo_mode = False
    if getattr(args, "demo", False):
        settings.demo_mode = True
    return settings, Taxonomy.load(), Database(settings.db_path)


def cmd_scan(args) -> int:
    settings, taxonomy, db = _ctx(args)
    print(f"[*] scan starting (mode={'demo' if settings.demo_mode else 'live'})")
    summary = asyncio.run(run_scan(settings, taxonomy, db))
    print(f"[+] sources : {', '.join(summary['sources'])}")
    print(f"[+] posts   : {summary['posts_seen']} seen, {summary['matched']} matched")
    print(f"[+] findings: {summary['new_findings']} new")
    return 0


def cmd_findings(args) -> int:
    _, _, db = _ctx(args)
    rows = db.findings(limit=args.limit, min_score=args.min, confidence=args.confidence)
    if not rows:
        print("no findings (run `scan` first)"); return 0
    for r in rows:
        print(f"[{r['score']:>3}] {r['confidence']:<6} {r['source']}/{r['author']:<16} "
              f"{r['title'][:60]}")
        if r["categories"]:
            print(f"      cats: {', '.join(r['categories'])}")
        if r["watchlist_hits"]:
            print(f"      WATCHLIST: {', '.join(r['watchlist_hits'])}")
        for k, v in r["selectors"].items():
            print(f"      {k}: {', '.join(v)}")
    return 0


def cmd_actors(args) -> int:
    _, _, db = _ctx(args)
    for a in db.actors(limit=args.limit):
        print(f"{a['author']:<20} posts={a['posts']:<3} max_score={a['max_score']:<3} "
              f"sources={','.join(a['sources'])}")
        if a["selectors"]:
            for k, v in a["selectors"].items():
                print(f"    {k}: {', '.join(v)}")
    return 0


def cmd_tor_check(args) -> int:
    settings, _, _ = _ctx(args)
    if settings.demo_mode:
        print("demo mode is ON — Tor is not used. Run with --live to test Tor.")
        return 0
    result = asyncio.run(_tor_check(settings))
    print(result)
    return 0 if result.get("ok") else 1


async def _tor_check(settings: Settings) -> dict:
    async with TorClient(settings) as client:
        return await client.check()


def cmd_export(args) -> int:
    _, _, db = _ctx(args)
    rows = db.findings(limit=10000)
    out = findings_to_json(rows) if args.format == "json" else findings_to_csv(rows)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote {len(rows)} findings -> {args.output}")
    else:
        print(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="obsidian", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--live", action="store_true", help="force live Tor mode")
    p.add_argument("--demo", action="store_true", help="force offline demo mode")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="run one scan cycle").set_defaults(func=cmd_scan)

    f = sub.add_parser("findings", help="list findings")
    f.add_argument("--min", type=int, default=0)
    f.add_argument("--limit", type=int, default=100)
    f.add_argument("--confidence", choices=["high", "medium", "low"])
    f.set_defaults(func=cmd_findings)

    a = sub.add_parser("actors", help="threat-actor leaderboard")
    a.add_argument("--limit", type=int, default=50)
    a.set_defaults(func=cmd_actors)

    sub.add_parser("tor-check", help="verify Tor egress").set_defaults(func=cmd_tor_check)

    e = sub.add_parser("export", help="export findings")
    e.add_argument("format", choices=["json", "csv"])
    e.add_argument("-o", "--output")
    e.set_defaults(func=cmd_export)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
