# ◆ OBSIDIAN — Dark Web Forum Recon & Threat-Actor Discovery

A self-hosted CTI tool that crawls **authorized** dark-web forums over Tor,
matches posts against a weighted keyword taxonomy, extracts threat-actor
selectors (handles, Jabber/Tox/Telegram/Session IDs, PGP fingerprints, crypto
wallets), scores each post, and surfaces the results through a FastAPI
dashboard + REST API.

Built in the same spirit as a "no-npm, no-API-keys, runs-locally, your data
never leaves your machine" pipeline: **Python · FastAPI · httpx · SQLite ·
zero JS build step.** Runs **fully offline in demo mode** so you can trial the
entire workflow with zero infrastructure.

> ⚠️ **For authorized defensive threat-intelligence use only.** Read the
> [Legal & OPSEC](#legal--opsec) section before pointing this at anything live.

---

## What it does (the pipeline)

```
sources.yaml ─┐
              ▼
   [1] COLLECT   pull forum posts over Tor (socks5h) — or offline fixtures
   [2] MATCH     weighted keyword taxonomy + your target watchlist
   [3] EXTRACT   actor selectors: jabber/tox/telegram/session/icq/pgp/btc/eth/xmr
   [4] SCORE     sum category weights + watchlist; rate confidence by corroboration
   [5] STORE     SQLite, deduped by content fingerprint, with first/last seen
   [6] SURFACE   dashboard + REST API + JSON/defanged-CSV export
```

A post only becomes a **finding** if it matches at least one category, so the
queue stays signal-heavy. Findings aggregate by author into a **threat-actor
leaderboard** that rolls up every selector and category seen per handle — the
starting point for attribution and law-enforcement referrals.

---

## Quick start (demo mode — no Tor needed)

```bash
cd darkweb-recon
python3 -m pip install -r requirements.txt

# Run one scan against the bundled fixtures
python3 cli.py scan

# Inspect results
python3 cli.py findings --min 15
python3 cli.py actors

# Or use the dashboard
uvicorn app.main:app --reload      # http://127.0.0.1:8000
```

`demo_mode: true` in `config.yaml` keeps everything offline. The fixtures in
`app/sources/demo.py` are fabricated, format-valid samples — no real actors,
handles, or wallets.

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
| `python3 cli.py scan` | Run one scan cycle (mode from `config.yaml`) |
| `python3 cli.py --live scan` | Force live Tor mode for this run |
| `python3 cli.py findings --min 15 --confidence high` | List findings |
| `python3 cli.py actors` | Threat-actor leaderboard |
| `python3 cli.py tor-check` | Verify Tor egress |
| `python3 cli.py export json -o out.json` | Export findings |

`--live` / `--demo` override `config.yaml` for a single invocation.

---

## REST API

| Method | Path | Description |
|---|---|---|
| `GET`  | `/` | Dashboard UI |
| `GET`  | `/api/stats` | KPI counters |
| `GET`  | `/api/tor` | Tor egress status |
| `GET`  | `/api/findings?min_score=&confidence=&source=&author=&limit=` | Findings |
| `GET`  | `/api/actors?limit=` | Actor leaderboard |
| `POST` | `/api/scan` | Trigger a scan cycle |
| `GET`  | `/api/export/json` | Export all findings (JSON) |
| `GET`  | `/api/export/csv?defang=true` | Export findings (defanged IOC CSV) |

Schedule scans with cron/systemd-timer hitting `POST /api/scan`, or run
`cli.py scan` on an interval.

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
    ├── matcher.py       # keyword matching, scoring, confidence
    ├── extractors.py    # selector extraction (handles/PGP/wallets)
    ├── db.py            # SQLite persistence + actor aggregation
    ├── scraper.py       # orchestration (collect → analyze → store)
    ├── exporters.py     # JSON / defanged CSV
    ├── main.py          # FastAPI app + dashboard
    ├── sources/         # pluggable forum adapters (base, generic_html, demo)
    └── templates/       # single-file dashboard (no JS build)
```

Add a new forum type by subclassing `BaseSource` and registering it in
`app/sources/__init__.py::build_source`.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Covers selector extraction, scoring/watchlist logic, the benign-post filter,
end-to-end demo scan, and dedup-on-rescan.

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
