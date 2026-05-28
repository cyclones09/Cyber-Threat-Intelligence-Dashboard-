# SOC Defenders — Cyber Threat Intelligence (CTI) Dashboard

> A fully interactive, single-file CTI dashboard built for Security Operations Center analysts. Deployable in seconds. Zero backend required.

**[Live Demo →](https://your-project.vercel.app)**

---

## Overview

This project is a production-grade Cyber Threat Intelligence dashboard that replicates the core workflow of platforms like **Recorded Future**, **Mandiant Advantage**, and **SOC Defenders**. It consolidates IOC tracking, CVE monitoring, daily threat briefings, and analyst action checklists into a single, fast, deployable interface.

Built as a deep-dive into the CTI domain — combining frontend engineering with genuine cybersecurity operational design based on real analyst workflows.

---

## Features

### Threat Intelligence
- **Daily Briefing Panel** — structured threat briefing with executive summary, top 5 threats of the day, and keyword-first SEO slug format (`/briefings/fortios-zero-day-lockbit-energy-2026-05-27`)
- **Prioritized Action Checklist** — URGENT / HIGH / NORMAL tasks with interactive checkboxes and completion tracking
- **CVE Tracker** — 6 active CVEs with CVSS scores, vendor/product affected, exploitation status, and patch versions
- **IOC Data Table** — 25 indicators of compromise with full metadata: date, indicator, type, severity, threat category, industry, source, and confidence score

### Schema-Driven Taxonomy
Filters and data are driven by a structured taxonomy matching industry standards:
- **16 Threat Types**: Ransomware, Zero-Day, Phishing, APT, Supply Chain, Data Breach, Malware, Vulnerability Exploit, Credential Theft, DDoS, BEC, Insider Threat, IoT/OT, Mobile Malware, Cryptojacking, Compliance
- **13 Industries**: Healthcare, Finance, Government, Technology, Energy, Education, Manufacturing, Retail, Legal, Telecom, Transportation, Media, Defense
- **4 Severity Levels**: Critical, High, Medium, Low

### Visualizations
- **Line Chart** — Threat types over 7 days (Ransomware, Phishing, Vuln Exploit, APT, Supply Chain)
- **Donut Chart** — Attack vectors by global region
- **Horizontal Bar Chart** — Top 10 malicious IPs and domains by hit count
- **Histogram** — IOC confidence score distribution across all indicators

### UX & Interactivity
- **Global filter bar** — filter by severity, threat type, and industry simultaneously; sidebar category pills sync with table filters
- **Detail drawer** — click any IOC row, CVE card, feed item, or top-5 threat to open a contextual panel showing CVEs, malware families, recommended mitigations, and briefing slug
- **IOC by Industry Sector** — 13 sector cards showing tier classification, IOC counts, and 24h delta
- **Live UTC clock** and threat level badge (Guarded / Elevated / Critical)
- **Automation pipeline panel** — visualises the defend.network Make.com → Claude Haiku → GitHub → Netlify architecture
- **SOC maturity level reference** and live KPI metrics panel

---

## Tech Stack

| Layer | Technology |
|---|---|
| Structure | Semantic HTML5 |
| Styling | Custom CSS (variables, grid, animations) |
| Charts | [Chart.js 4.4.1](https://www.chartjs.org/) via CDN |
| Fonts | Google Fonts — Share Tech Mono + Rajdhani |
| Hosting | Vercel (static) |
| Build | None — zero build step, zero dependencies |

**Bundle size: ~86KB.** No React. No Node. No bundler. No database.

---

## Architecture

```
cti-dashboard/
├── index.html        # Entire application — styles, markup, data, logic
├── vercel.json       # Deployment config (security headers, routing)
├── .gitignore
└── README.md
```

The dashboard is intentionally a **single HTML file**. This is a deliberate architectural choice that demonstrates:
- Ability to build complex UIs without framework overhead
- Understanding of vanilla JS DOM patterns (filtering, sorting, pagination, drawer state)
- Performance-first thinking — sub-100KB, zero network requests beyond fonts and Chart.js CDN

Inspired by the [defend.network architecture](https://dev.to/) — a fully automated CTI platform running for ~$2/month using Make.com, Netlify serverless functions, Claude Haiku API, and GitHub static hosting.

---


---

## Connecting Real Data

The dashboard currently uses realistic static sample data. To connect live feeds:

### RSS / OSINT Feeds
Replace `const FEED = [...]` and `const IOC = [...]` with data fetched from:
- **CISA KEV**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **AlienVault OTX**: `https://otx.alienvault.com/api/v1/pulses/subscribed`
- **Abuse.ch**: `https://feodotracker.abuse.ch/downloads/ipblocklist.json`
- **The Hacker News RSS**: `https://feeds.feedburner.com/TheHackersNews`

### Automated Pipeline (defend.network architecture)
To make this fully autonomous for ~$2/month:
1. **Make.com** (free) — daily 6AM UTC trigger → webhook
2. **Netlify Function** — fetch RSS, call Claude Haiku API, rebuild HTML, push to GitHub
3. **Claude Haiku API** — structured JSON analysis (~$0.03-0.05/briefing)
4. **GitHub Contents API** — push new `index.html` on each run
5. **Vercel** — auto-deploys on every GitHub push

---

## Cybersecurity Domain Coverage

This project demonstrates working knowledge of:

- **IOC types**: IP, domain, URL, hash (SHA-256), email
- **Threat classification frameworks**: aligned with MITRE ATT&CK TTP categories
- **CTI data standards**: STIX/TAXII indicator schema, CVSS scoring
- **SOC operational metrics**: MTTD, MTTR, True/False positive rates, IOC hit rate
- **Threat intel types**: Strategic, Tactical, Operational, Technical intelligence
- **SOC maturity model**: Levels 1 (Reactive) → 4 (Adaptive/ML-driven)
- **KEV catalog workflow**: CISA Known Exploited Vulnerabilities prioritisation
- **Industry sector tiering**: Critical infrastructure (Tier 1) through lower-priority sectors

---

## Screenshots

> *(Add screenshots here after first deploy)*

| Section | Description |
|---|---|
| Daily Briefing | Executive summary + top 5 threats + action checklist |
| IOC Table | Filterable, sortable, paginated indicator feed |
| CVE Tracker | Active exploited vulnerabilities with CVSS scores |
| Charts | Line, donut, bar, histogram visualisations |
| Detail Drawer | Full context panel per IOC, CVE, or feed item |

---

## License

MIT — use freely for portfolios, job applications, or as a foundation for a real CTI platform.

---

*Built with Chart.js · Deployed on Vercel · Data modelled on socdefenders.ai + defend.network + isMalicious.com*
