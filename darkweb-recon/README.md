# ◆ OBSIDIAN — Dark Web OSINT & Threat-Actor Discovery

A self-hosted CTI tool that **searches the dark web by name/brand/domain**,
discovers `.onion` sources over Tor, matches content against a weighted keyword
taxonomy, extracts threat-actor selectors (handles, Jabber/Tox/Telegram/Session
IDs, PGP fingerprints, crypto wallets), **pivots those selectors through OSINT
tools (Sherlock, Shodan, VirusTotal, SpiderFoot, Maltego export)**, and writes an
investigation summary with an **optional Claude LLM layer**.

Stack: **Python · FastAPI · httpx · SQLite · zero JS build step.** Runs **fully
offline in demo mode** so you can trial the entire workflow with zero
infrastructure (no Tor, no API keys).

> ⚠️ **For authorized defensive threat-intelligence use only.** Read the
> [Legal & OPSEC](#legal--opsec) section before pointing this at anything live.

---

## Two workflows

### A. Investigate — search by name (the primary, "Robin-style" flow)

```
objective ─┐  e.g. "Jane Doe, CEO of Acme" / "acme-corp.com"
           ▼
 [1] REFINE     Claude expands the objective into dark-web search queries
 [2] DISCOVER   query dark-web search engines (Ahmia, Torch…) → .onion URLs
 [3] SCRAPE     pull those pages over Tor
 [4] ANALYZE    weighted keyword match + threat scoring + selector extraction
 [5] FILTER     Claude prunes noise, keeps real leads
 [6] STORE      SQLite, deduped by content fingerprint
 [7] ENRICH     pivot actors' selectors via OSINT (Sherlock, Shodan, SpiderFoot)
 [8] SUMMARY    Claude writes the investigation summary
```

You don't curate forum URLs — you type a name and the engine finds the sources.
Every LLM step (1, 5, 8) **degrades to deterministic logic** when no API key is
set, so the pipeline still runs and produces findings + a rollup summary.

### B. Scan — monitor specific forums you already track

```
sources.yaml → COLLECT (Tor) → MATCH → EXTRACT → SCORE → STORE → SURFACE
```

Both workflows feed the same SQLite store, **threat-actor leaderboard**, and
dashboard. A post only becomes a **finding** if it matches at least one
category, so the queue stays signal-heavy.

---

## Quick start (demo mode — no Tor needed)

```bash
cd darkweb-recon
python3 -m pip install -r requirements.txt

# Search the dark web by name (the headline feature)
python3 cli.py investigate "Jane Doe, CEO of Acme Corp acme-corp.com"

# Or monitor specific forums
python3 cli.py scan

# Inspect results
python3 cli.py findings --min 15
python3 cli.py actors

# Or use the dashboard (has the investigate box)
uvicorn app.main:app --reload      # http://127.0.0.1:8000
```

`demo_mode: true` in `config.yaml` keeps everything offline. The fixtures in
`app/sources/demo.py` are fabricated, format-valid samples — no real actors,
handles, or wallets.

### Enabling the LLM + OSINT pivots

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # enables query refine / filter / summary (Claude)
export SHODAN_API_KEY=...             # enables Shodan infra pivots (free key works)
export VIRUSTOTAL_API_KEY=...         # enables VirusTotal reputation lookups (free key works)
export SPIDERFOOT_URL=http://127.0.0.1:5001   # a running SpiderFoot instance
# Sherlock username pivots work out of the box (built-in checker); if the
# `sherlock` CLI is installed it's used automatically for fuller coverage.
```

Start SpiderFoot with `python3 sf.py -l 127.0.0.1:5001`, then add `--spiderfoot`
to an investigation (CLI) or tick the SpiderFoot box (dashboard). It runs one
automated OSINT scan on the objective — slow (minutes) and opt-in.

All of these are optional — without them the pipeline still runs deterministically.

---

## Going live (Tor + real sources)

1. **Install & run Tor** (daemon on `9050`, or Tor Browser on `9150`):
   ```bash
   sudo apt install tor && sudo systemctl start tor
   ```
2. **Point the proxy** in `config.yaml` (`tor_proxy: socks5h://127.0.0.1:9050`)
   and set `demo_mode: false`.
3. **Verify egress:**
   ```bash
   python3 cli.py --live tor-check
   # -> {'ok': True, 'exit_ip': '...'}
   ```
4. **Register sources** in `sources.yaml`. The `generic_html` adapter scrapes
   any SMF/phpBB/XenForo-style board given CSS selectors — no code needed:
   ```yaml
   sources:
     - name: "myforum"
       type: "generic_html"
       enabled: true
       base_url: "http://<authorized-service>.onion"
       board_paths: ["/index.php?board=marketplace"]
       selectors:
         thread_link: "a.topic_link"
         post_body:   "div.post"
         post_author: ".username"
       cookie: ""        # paste a session Cookie header if the board needs auth
   ```
5. **Scan:** `python3 cli.py --live scan`

> The `.onion` addresses shipped in `sources.yaml` are **placeholders**. You
> supply the sources you are authorized to monitor.

---

## Tuning detection (`keywords.yaml`)

The taxonomy is the heart of the engine. Each category has a `weight` and a
list of `patterns` (plain terms = whole-word match; regex if metacharacters are
present). Categories shipped: `initial_access`, `ransomware`, `data_sale`,
`credentials`, `malware_dev`, `recruitment`.

The **watchlist** is your highest-value signal — your own brands, domains, and
sectors. A watchlist hit means *your* estate is being discussed and adds
`watchlist_weight` (default 12) to the score:

```yaml
watchlist_weight: 12
watchlist:
  - "your-company.com"
  - "yourbrand"
```

---

## CLI reference

| Command | Description |
|---|---|
| `python3 cli.py investigate "<name/brand/domain>"` | Search-by-name pipeline |
| `python3 cli.py investigate "<obj>" --no-enrich` | …without OSINT pivots |
| `python3 cli.py investigate "<obj>" --spiderfoot` | …also run a SpiderFoot scan |
| `python3 cli.py scan` | Run one forum scan cycle (mode from `config.yaml`) |
| `python3 cli.py --live scan` | Force live Tor mode for this run |
| `python3 cli.py findings --min 15 --confidence high` | List findings |
| `python3 cli.py actors` | Threat-actor leaderboard |
| `python3 cli.py tor-check` | Verify Tor egress |
| `python3 cli.py export json -o out.json` | Export findings (json/csv) |
| `python3 cli.py export maltego -o graph.csv` | Export Maltego graph (maltego/graph) |

`--live` / `--demo` override `config.yaml` for a single invocation.

---

## REST API

| Method | Path | Description |
|---|---|---|
| `GET`  | `/` | Dashboard UI (with the investigate box) |
| `POST` | `/api/investigate` | Run the search-by-name pipeline (`{"objective": "...", "enrich": true}`) |
| `GET`  | `/api/investigations?limit=` | Past investigations + summaries |
| `GET`  | `/api/osint?limit=` | OSINT pivot results |
| `GET`  | `/api/llm` | LLM availability + model |
| `GET`  | `/api/stats` | KPI counters |
| `GET`  | `/api/tor` | Tor egress status |
| `GET`  | `/api/findings?min_score=&confidence=&source=&author=&limit=` | Findings |
| `GET`  | `/api/actors?limit=` | Actor leaderboard |
| `POST` | `/api/scan` | Trigger a forum scan cycle |
| `GET`  | `/api/export/json` · `/api/export/csv?defang=true` | Findings export |
| `GET`  | `/api/export/maltego` · `/api/export/graph` | Actor graph export |

Schedule investigations/scans with cron/systemd-timer hitting the `POST`
endpoints, or run `cli.py` on an interval. (Dark-web monitoring is *polling*,
not real-time — expect minutes-to-hours per cycle.)

---

## Architecture

```
darkweb-recon/
├── config.yaml          # runtime settings (Tor, timeouts, demo mode)
├── keywords.yaml        # weighted detection taxonomy + watchlist
├── sources.yaml         # forum registry (placeholders — you fill in)
├── cli.py               # command-line runner
├── requirements.txt
└── app/
    ├── config.py        # settings + taxonomy loaders (env overridable)
    ├── models.py        # RawPost / AnalyzedPost / KeywordHit
    ├── tor.py           # httpx-over-SOCKS client + egress check + NEWNYM
    ├── discovery.py     # dark-web search-engine aggregator (Ahmia, …)
    ├── scrape.py        # parallel onion page scraping → RawPost
    ├── matcher.py       # keyword matching, scoring, confidence
    ├── extractors.py    # selector extraction (handles/PGP/wallets)
    ├── llm.py           # Claude: refine / filter / summary (optional)
    ├── investigate.py   # search-by-name orchestrator (the Robin pipeline)
    ├── scraper.py       # forum-scan orchestrator (collect → analyze → store)
    ├── osint/           # pivot connectors: sherlock, shodan, spiderfoot (+ base)
    ├── maltego.py       # Maltego CSV + graph JSON export
    ├── db.py            # SQLite persistence (findings/runs/investigations/osint)
    ├── exporters.py     # JSON / defanged CSV
    ├── main.py          # FastAPI app + dashboard
    ├── sources/         # pluggable forum adapters (base, generic_html, demo)
    └── templates/       # single-file dashboard (no JS build)
```

Extend it by: subclassing `BaseSource` (new forum type) in
`app/sources/__init__.py::build_source`; adding a `SearchEngine` to
`discovery.ENGINES`; or adding an OSINT connector under `app/osint/`.

---

## Deploy

**This is a run-it-locally tool.** It needs Tor, a persistent process, and a
writable database, and it handles sensitive investigation data — so it does
**not** belong on serverless/static hosts like Vercel, Netlify, or Lambda
(no Tor, no long-running process, ephemeral filesystem), and it should never be
exposed on a public URL. Run it on a machine you control.

### Option 1 — local (fastest)
```bash
cd darkweb-recon
pip install -r requirements.txt
uvicorn app.main:app          # http://127.0.0.1:8000  (demo mode, no Tor needed)
```

### Option 2 — Docker (Tor bundled, one command)
```bash
cd darkweb-recon
docker compose up --build      # http://127.0.0.1:8000
```
The image bundles Tor. It starts in demo mode; flip `OBSIDIAN_DEMO_MODE` to
`"false"` in `docker-compose.yml` to start Tor and scan real sources from
`sources.yaml`. The dashboard is published to **localhost only** by default
(`127.0.0.1:8000`) — keep it that way (or behind a VPN/SSH tunnel); there is no
built-in authentication.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Covers selector extraction, scoring/watchlist logic, the benign-post filter,
end-to-end demo scan + investigate pipeline, dedup-on-rescan, LLM graceful
degradation, search-engine result parsing, and Maltego export.

---

## Legal & OPSEC

This tool is for **authorized defensive threat intelligence** — protecting an
organization you are entitled to protect.

- **Authorization:** Accessing some hidden services, or even possessing certain
  leaked data, can be unlawful depending on jurisdiction and content. Operate
  under documented authorization (your employer's CTI program, a signed
  engagement, or law-enforcement direction). Consult counsel.
- **Do not engage:** OBSIDIAN only *reads*. Never purchase, solicit, or
  negotiate for illegal goods/services, and never download leaked datasets you
  aren't authorized to handle.
- **OPSEC:** Always route via Tor (`tor-check` before live runs). Run from an
  isolated VM. The generic User-Agent and request delay reduce your footprint;
  enable circuit rotation for longer crawls. Never reuse personal accounts or
  identifiers.
- **Findings are leads, not facts.** Selectors and scores are investigative
  starting points requiring human verification before any action or report.

The bundled fixtures and all sample handles/wallets/keys are fabricated.
