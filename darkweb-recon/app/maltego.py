"""Maltego-compatible graph export.

Maltego can't be driven directly, but it imports CSV link tables. This builds a
node + edge model from findings and OSINT enrichment, then emits:

  * a Maltego "Import Connectivity Table" CSV (Source,SourceType,Target,
    TargetType,Edge) — paste into Maltego's CSV import to materialise the graph
  * a generic graph JSON (nodes/edges) for any other graph tool

Entity types use Maltego's standard names (maltego.Person, maltego.Alias,
maltego.PhoneNumber, maltego.IPv4Address, etc.) where they map cleanly.
"""
from __future__ import annotations

import csv
import io
import json

# Map our selector types to Maltego entity type names.
_SELECTOR_ENTITY = {
    "jabber": "maltego.Alias",
    "telegram": "maltego.Alias",
    "tox": "maltego.Hash",
    "session": "maltego.Hash",
    "icq": "maltego.Alias",
    "email": "maltego.EmailAddress",
    "pgp": "maltego.Hash",
    "btc": "maltego.Hash",
    "eth": "maltego.Hash",
    "xmr": "maltego.Hash",
    "ltc": "maltego.Hash",
}


def _build_graph(actors: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (nodes, edges) from the actor leaderboard."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, label: str, etype: str) -> None:
        nodes.setdefault(node_id, {"id": node_id, "label": label, "type": etype})

    for a in actors:
        actor_id = f"actor:{a['author']}"
        add_node(actor_id, a["author"], "maltego.Alias")
        for src in a.get("sources", []):
            sid = f"source:{src}"
            add_node(sid, src, "maltego.Website")
            edges.append({"source": actor_id, "target": sid, "label": "posted_on"})
        for sel_type, values in a.get("selectors", {}).items():
            etype = _SELECTOR_ENTITY.get(sel_type, "maltego.Phrase")
            for v in values:
                nid = f"{sel_type}:{v}"
                add_node(nid, v, etype)
                edges.append({"source": actor_id, "target": nid,
                              "label": f"uses_{sel_type}"})
    return list(nodes.values()), edges


def to_csv(actors: list[dict]) -> str:
    """Maltego import-connectivity-table CSV."""
    nodes, edges = _build_graph(actors)
    by_id = {n["id"]: n for n in nodes}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Source", "SourceType", "Target", "TargetType", "Edge"])
    for e in edges:
        s, t = by_id[e["source"]], by_id[e["target"]]
        w.writerow([s["label"], s["type"], t["label"], t["type"], e["label"]])
    return buf.getvalue()


def to_graph_json(actors: list[dict]) -> str:
    nodes, edges = _build_graph(actors)
    return json.dumps({"nodes": nodes, "edges": edges}, indent=2,
                      ensure_ascii=False)
