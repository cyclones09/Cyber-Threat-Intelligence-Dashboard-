"""FastAPI application: dashboard UI + REST API.

Run with:  uvicorn app.main:app --reload   (from the project root)
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Body, FastAPI, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from . import __version__, llm, maltego
from .config import Settings, Taxonomy
from .db import Database
from .exporters import findings_to_csv, findings_to_json
from .investigate import investigate
from .scraper import run_scan
from .tor import TorClient

settings = Settings.load()
taxonomy = Taxonomy.load()
db = Database(settings.db_path)

app = FastAPI(title="OBSIDIAN", version=__version__)

_TEMPLATE = (Path(__file__).parent / "templates" / "dashboard.html").read_text(
    encoding="utf-8"
)


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return _TEMPLATE


@app.get("/api/stats")
async def api_stats() -> dict:
    return db.stats()


@app.get("/api/tor")
async def api_tor() -> dict:
    if settings.demo_mode:
        return {"demo": True, "ok": False}
    async with TorClient(settings) as client:
        result = await client.check()
    result["demo"] = False
    return result


@app.get("/api/findings")
async def api_findings(
    min_score: int = 0,
    limit: int = Query(200, le=1000),
    source: str | None = None,
    author: str | None = None,
    confidence: str | None = None,
) -> dict:
    rows = db.findings(
        limit=limit, min_score=min_score, source=source,
        author=author, confidence=confidence,
    )
    return {"count": len(rows), "findings": rows}


@app.get("/api/actors")
async def api_actors(limit: int = Query(100, le=500)) -> dict:
    rows = db.actors(limit=limit)
    return {"count": len(rows), "actors": rows}


@app.post("/api/scan")
async def api_scan() -> dict:
    return await run_scan(settings, taxonomy, db)


@app.post("/api/investigate")
async def api_investigate(payload: dict = Body(...)) -> dict:
    objective = (payload or {}).get("objective", "").strip()
    if not objective:
        return {"error": "objective is required"}
    enrich = bool((payload or {}).get("enrich", True))
    return await investigate(objective, settings, taxonomy, db, enrich=enrich)


@app.get("/api/investigations")
async def api_investigations(limit: int = Query(50, le=200)) -> dict:
    rows = db.investigations(limit=limit)
    return {"count": len(rows), "investigations": rows}


@app.get("/api/osint")
async def api_osint(limit: int = Query(200, le=1000)) -> dict:
    rows = db.osint_results(limit=limit)
    return {"count": len(rows), "results": rows}


@app.get("/api/llm")
async def api_llm() -> dict:
    return {"available": llm.available(), "model": llm.MODEL}


@app.get("/api/export/json")
async def export_json() -> Response:
    rows = db.findings(limit=10000)
    return Response(
        content=findings_to_json(rows),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=obsidian_findings.json"},
    )


@app.get("/api/export/csv")
async def export_csv(defang: bool = True) -> PlainTextResponse:
    rows = db.findings(limit=10000)
    return PlainTextResponse(
        content=findings_to_csv(rows, defang=defang),
        headers={"Content-Disposition": "attachment; filename=obsidian_iocs.csv"},
    )


@app.get("/api/export/maltego")
async def export_maltego() -> PlainTextResponse:
    return PlainTextResponse(
        content=maltego.to_csv(db.actors(limit=500)),
        headers={"Content-Disposition": "attachment; filename=obsidian_maltego.csv"},
    )


@app.get("/api/export/graph")
async def export_graph() -> Response:
    return Response(
        content=maltego.to_graph_json(db.actors(limit=500)),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=obsidian_graph.json"},
    )
