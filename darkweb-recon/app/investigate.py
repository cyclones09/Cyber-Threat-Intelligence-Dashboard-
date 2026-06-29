"""Investigation orchestrator (Robin-style, search-by-name pipeline).

Given an analyst objective (e.g. a CEO's name, a brand, a domain), run:

  1. refine    — Claude expands the objective into dark-web search queries
  2. discover  — query dark-web search engines for candidate .onion URLs
  3. scrape    — pull those pages over Tor
  4. analyze   — keyword match + threat scoring + selector extraction
  5. filter    — Claude prunes irrelevant noise (keeps real leads)
  6. store     — persist findings (deduped)
  7. enrich    — pivot top actors' selectors via OSINT (Sherlock/Shodan)
  8. summary   — Claude writes the investigation summary
  9. persist   — log the investigation + OSINT results

Every LLM step degrades gracefully when no API key is set, so the pipeline
still produces deterministic results offline / in demo mode.
"""
from __future__ import annotations

from . import llm
from .config import Settings, Taxonomy
from .db import Database
from .discovery import discover
from .matcher import analyze_many
from .osint import (enrich_host, enrich_spiderfoot, enrich_username,
                    enrich_virustotal)
from .scrape import scrape_multiple


async def investigate(objective: str, settings: Settings | None = None,
                      taxonomy: Taxonomy | None = None,
                      db: Database | None = None,
                      enrich: bool = True,
                      spiderfoot: bool = False,
                      max_enrich_actors: int = 5) -> dict:
    """Run the full investigation pipeline for `objective`."""
    settings = settings or Settings.load()
    taxonomy = taxonomy or Taxonomy.load()
    db = db or Database(settings.db_path)

    # 1. refine
    refined = llm.refine_query(objective)

    # 2. discover
    discovered = await discover(settings, refined.queries,
                                per_engine=settings.max_pages_per_source)

    # 3. scrape
    posts = await scrape_multiple(settings, discovered)

    # 4. analyze
    analyzed = analyze_many(posts, taxonomy)

    # 5. filter (LLM relevance pass)
    candidates = [{"title": a.post.title, "snippet": a.post.body[:300],
                   "score": a.score} for a in analyzed]
    keep_idx = set(llm.filter_results(objective, candidates))
    analyzed = [a for i, a in enumerate(analyzed) if i in keep_idx]

    # 6. store findings
    new = 0
    for a in analyzed:
        if db.upsert_finding(a):
            new += 1

    # 7. enrich top actors via OSINT
    osint_results: list[dict] = []
    if enrich:
        actors = db.actors(limit=max_enrich_actors)
        for actor in actors:
            sels = actor.get("selectors", {})
            # usernames: the handle itself + telegram/icq handles
            handles = {actor["author"], *sels.get("telegram", []),
                       *sels.get("icq", [])}
            for h in list(handles)[:3]:
                res = await enrich_username(h)
                osint_results.append(res.to_dict())
                db.save_osint(res.to_dict())
            # infra: any domains/IPs seen as selectors (rare in handles, but
            # emails carry domains we can pivot)
            for email in sels.get("email", [])[:2]:
                domain = email.split("@", 1)[-1]
                for fn in (enrich_host, enrich_virustotal):
                    res = await fn(domain)
                    osint_results.append(res.to_dict())
                    db.save_osint(res.to_dict())

    # 7b. SpiderFoot (opt-in, slow): one automated OSINT scan on the objective.
    if spiderfoot:
        res = await enrich_spiderfoot(objective)
        osint_results.append(res.to_dict())
        db.save_osint(res.to_dict())

    # 8. summary
    findings = db.findings(limit=50)
    actors = db.actors(limit=20)
    summary = llm.generate_summary(objective, findings, actors)

    # 9. persist investigation
    source_links = [d.url for d in discovered]
    inv_id = db.log_investigation(
        objective=objective, refined=refined.queries,
        sources_count=len(discovered), findings_count=len(analyzed),
        summary=summary, source_links=source_links,
    )

    return {
        "investigation_id": inv_id,
        "objective": objective,
        "llm_enabled": llm.available(),
        "refined_queries": refined.queries,
        "refine_rationale": refined.rationale,
        "discovered": len(discovered),
        "scraped": len(posts),
        "matched": len(analyzed),
        "new_findings": new,
        "osint_results": osint_results,
        "summary": summary,
        "source_links": source_links,
    }
