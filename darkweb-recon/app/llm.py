"""LLM layer — Anthropic Claude for query refinement, result filtering, and
investigation summaries (the Robin-style pipeline brains).

Uses the official Anthropic SDK with `claude-opus-4-8`, adaptive thinking, and
structured outputs. The whole layer is OPTIONAL: if the SDK isn't installed or
no API key is configured, every function degrades gracefully so the
deterministic pipeline (discover -> scrape -> match -> score) still runs.

Set the key via the ANTHROPIC_API_KEY environment variable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

MODEL = "claude-opus-4-8"

# Stable system prompt — cached so repeated calls in one investigation reuse it.
_REFINE_SYSTEM = (
    "You are a dark-web threat-intelligence query planner for an AUTHORIZED, "
    "defensive CTI program. Given an analyst's raw objective (a name, brand, "
    "domain, or topic), produce 3-6 concrete search queries optimised for "
    "dark-web search engines (Ahmia, Torch, etc.). Favour terms that surface "
    "criminal discussion: combine the target with words like 'database', "
    "'leak', 'access', 'credentials', 'breach', 'dump'. Output queries only — "
    "no commentary, no instructions to take action."
)

_FILTER_SYSTEM = (
    "You triage scraped dark-web posts for an AUTHORIZED defensive CTI "
    "investigation. For each candidate, decide if it is genuinely relevant to "
    "the analyst's objective (a real threat lead) versus noise. Be strict: "
    "marketplace spam unrelated to the target is NOT relevant. Judge only "
    "relevance — never endorse or assist any illegal activity described."
)

_SUMMARY_SYSTEM = (
    "You are a senior CTI analyst writing an investigation summary for an "
    "AUTHORIZED defensive engagement. Summarise what the dark-web findings "
    "indicate about threats to the target. Be factual and measured: these are "
    "investigative LEADS requiring verification, not confirmed facts. Note "
    "the most relevant actors/handles and recommend defensive next steps "
    "(monitoring, credential resets, law-enforcement referral). Never provide "
    "operational guidance that would help wrongdoing. Output concise Markdown."
)


class LLMUnavailable(RuntimeError):
    """Raised when the LLM layer can't run (no SDK or no API key)."""


@dataclass
class RefinedQuery:
    queries: list[str]
    rationale: str


def available() -> bool:
    """True if the Anthropic SDK is importable and an API key is set."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def _client():
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - import guard
        raise LLMUnavailable("anthropic SDK not installed") from exc
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise LLMUnavailable("ANTHROPIC_API_KEY not set")
    return anthropic.Anthropic()


# --- 1. query refinement ----------------------------------------------------
def refine_query(raw_query: str) -> RefinedQuery:
    """Turn an analyst objective into dark-web search queries.

    Degrades to a deterministic expansion if the LLM is unavailable.
    """
    if not available():
        return _fallback_refine(raw_query)

    from pydantic import BaseModel

    class _Out(BaseModel):
        queries: list[str]
        rationale: str

    client = _client()
    resp = client.messages.parse(
        model=MODEL,
        max_tokens=1024,
        system=[{"type": "text", "text": _REFINE_SYSTEM,
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": f"Objective: {raw_query}"}],
        output_format=_Out,
    )
    out = resp.parsed_output
    if not out or not out.queries:
        return _fallback_refine(raw_query)
    return RefinedQuery(queries=out.queries[:6], rationale=out.rationale)


def _fallback_refine(raw_query: str) -> RefinedQuery:
    q = raw_query.strip()
    expansions = [q, f"{q} database leak", f"{q} credentials",
                  f"{q} access", f"{q} breach"]
    return RefinedQuery(
        queries=expansions,
        rationale="LLM unavailable — used deterministic keyword expansion.",
    )


# --- 2. result filtering ----------------------------------------------------
def filter_results(objective: str, candidates: list[dict]) -> list[int]:
    """Return the indices of candidates judged relevant to the objective.

    `candidates` is a list of {"title", "snippet", "score"}. Degrades to
    "keep everything that already matched a keyword" when the LLM is off.
    """
    if not candidates:
        return []
    if not available():
        return [i for i, c in enumerate(candidates) if c.get("score", 0) > 0]

    from pydantic import BaseModel

    class _Out(BaseModel):
        relevant_indices: list[int]

    lines = [
        f"[{i}] score={c.get('score', 0)} title={c.get('title', '')!r} "
        f"snippet={(c.get('snippet', '') or '')[:280]!r}"
        for i, c in enumerate(candidates)
    ]
    client = _client()
    resp = client.messages.parse(
        model=MODEL,
        max_tokens=2048,
        system=[{"type": "text", "text": _FILTER_SYSTEM,
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{
            "role": "user",
            "content": f"Objective: {objective}\n\nCandidates:\n" + "\n".join(lines)
            + "\n\nReturn the indices of the relevant ones.",
        }],
        output_format=_Out,
    )
    out = resp.parsed_output
    if not out:
        return [i for i, c in enumerate(candidates) if c.get("score", 0) > 0]
    return [i for i in out.relevant_indices if 0 <= i < len(candidates)]


# --- 3. investigation summary ----------------------------------------------
def generate_summary(objective: str, findings: list[dict],
                     actors: list[dict]) -> str:
    """Write a Markdown investigation summary. Streams (long output) with
    adaptive thinking. Degrades to a deterministic summary when the LLM is off.
    """
    if not available():
        return _fallback_summary(objective, findings, actors)

    finding_lines = [
        f"- [{f.get('score')}] {f.get('source')}/{f.get('author')}: "
        f"{f.get('title', '')} (cats: {', '.join(f.get('categories', []))})"
        for f in findings[:25]
    ]
    actor_lines = [
        f"- {a.get('author')}: {a.get('posts')} posts, max_score "
        f"{a.get('max_score')}, selectors: {list(a.get('selectors', {}).keys())}"
        for a in actors[:15]
    ]
    user = (
        f"Objective: {objective}\n\n"
        f"Top findings:\n" + "\n".join(finding_lines) + "\n\n"
        f"Actors:\n" + "\n".join(actor_lines)
    )
    client = _client()
    chunks: list[str] = []
    with client.messages.stream(
        model=MODEL,
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=[{"type": "text", "text": _SUMMARY_SYSTEM,
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}],
    ) as stream:
        msg = stream.get_final_message()
    for block in msg.content:
        if block.type == "text":
            chunks.append(block.text)
    return "".join(chunks).strip() or _fallback_summary(objective, findings, actors)


def _fallback_summary(objective: str, findings: list[dict],
                      actors: list[dict]) -> str:
    high = [f for f in findings if f.get("confidence") == "high"]
    watch = [f for f in findings if f.get("watchlist_hits")]
    lines = [
        f"## Investigation summary — {objective}",
        "",
        f"- **{len(findings)}** relevant findings; **{len(high)}** high-confidence; "
        f"**{len(watch)}** watchlist hits.",
        f"- **{len(actors)}** distinct handles observed.",
        "",
        "_LLM summary unavailable — deterministic rollup. "
        "Findings are investigative leads requiring verification._",
    ]
    if actors:
        lines.append("\n### Top actors")
        for a in actors[:5]:
            lines.append(f"- `{a.get('author')}` — score {a.get('max_score')}, "
                         f"{a.get('posts')} posts")
    return "\n".join(lines)
