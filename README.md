# Website Auditor

A Python CLI tool that crawls a website and runs an automated audit across SEO, accessibility, performance, security, forms/compliance, and content/link health — producing scored HTML and PDF reports.

## Overview
Point the tool at one or more URLs and it will:
1. Crawl the site with a real browser (Playwright), collecting pages, network traffic, console output, and screenshots.
2. Run a battery of audit checks against the collected data.
3. Score the results.
4. Generate an HTML report (opened automatically in your browser) and a PDF report, plus a raw JSON/log output.

## Features
- **SEO** — titles, meta descriptions, canonicals, viewport/favicon, robots.txt, sitemap.xml, structured data, Open Graph/Twitter cards, headings, alt text, lazy loading, broken internal/external links, redirect chains, duplicate titles/descriptions, soft-404 detection.
- **Accessibility** — automated accessibility checks against page markup.
- **Performance** — Core Web Vitals-style metrics (LCP, CLS, FCP, TTFB), blocking time, DOM size, page weight, compression/caching, render-blocking JS, image weight/format/lazy-loading.
- **Security** — HTTP security headers, cookies, CORS, directory listing, exposed files (`.git`, `.env`, backups, dumps, phpinfo, etc.), SPF/DMARC, SSL, technology fingerprinting, and (in `--aggressive` mode) active checks such as XSS, SQLi, CSRF, IDOR, JWT, authentication, business-logic, and form-fuzzing probes.
- **Forms & compliance** — field labels/types, spam protection, GDPR consent, cookie consent, privacy/legal links, contact info discovery.
- **Visual review** — contrast, typography, palette, line length, broken/blurry/stretched images, above-the-fold composition, overlay/overlap/scroll issues, blank first-screen detection, and an optional AI-assisted design critique.
- **Responsive / mobile** — DOM inspection and responsive layout checks across viewports.
- **Console & network** — console errors/warnings, failed requests, HTTP error responses, request/response logging.
- **Reporting** — scored HTML report (auto-opens), PDF report, JSON export, and an issue log.

## Architecture
- `browser/` — Playwright-based crawler (`crawler.py`) and page "reveal" helpers that drive the browser and collect raw page/network/console data.
- `audit/` — the check engine. `engine.py` orchestrates individual audit modules (`seo.py`, `accessibility/`, `performance.py`, `security/`, `forms.py`, `images.py`, `links.py`, `network.py`, `contact.py`, `responsive/`, `visual/`, `lighthouse/`, etc.), each contributing `Issue` objects.
- `audit/scoring/` — turns collected issues into a weighted score (`engine.py`, `weights.py`).
- `audit/visual/ai_review.py` — optional design critique via the Anthropic API, gated behind `--ai-review` and the `ANTHROPIC_API_KEY` env var.
- `reports/` — HTML, PDF, and JSON report builders that render the final audit output.
- `utils/` — logging, console summary printing, and issue-log persistence.
- `main.py` — CLI entry point that wires the crawler, audit engine, scoring engine, and report builders together, reading target URLs from `url.md` (or prompting interactively if that file is absent).
- `Phase.md` — a running phase-by-phase progress tracker for the project (foundation, SEO, network/browser, reporting, crawler, AI assistant, visual/performance/site-wide/hardening phases).
- `tests/` — unit tests (see Testing below).

## Tech Stack
- Python 3
- Playwright (headless/headed browser automation)
- BeautifulSoup4 / lxml (HTML parsing)
- Rich (console output)
- Pillow (image analysis)
- dnspython (DNS/SPF/DMARC checks)
- Optional: Anthropic API for the AI design review feature

## Getting Started

### Install dependencies
```bash
pip install -r requirements.txt
```

### Install Playwright's browser binaries
```bash
playwright install
```

## Configuration
No configuration file is required for basic use. One optional environment variable enables the AI design-review feature:

- `ANTHROPIC_API_KEY` — required only if you pass `--ai-review`; without it, the AI review step is skipped with a warning.
- `AUDITOR_AI_MODEL` — optional, overrides the default model used for the AI design review.

Do not commit real API keys. Set them as environment variables in your shell or a local (gitignored) `.env`-style setup of your own choosing.

## Usage
List target URLs in `url.md` (one per line, `#` for comments), or omit it to be prompted interactively. Then run:

```bash
python main.py
```

Useful flags:
```bash
python main.py --headless          # run the browser headless
python main.py --no-open           # don't auto-open the HTML report
python main.py --pages 50          # sample up to 50 internal pages for site-wide SEO checks (default 25)
python main.py --ai-review         # add an AI design critique (needs ANTHROPIC_API_KEY)
python main.py --aggressive        # enable active security testing (XSS/SQLi/CSRF/IDOR probes, etc.)
```

> **Caution:** `--aggressive` performs active security probing (injection attempts, fuzzing, etc.) — only run it against sites you own or are explicitly authorized to test.

## Testing
Tests are written with `unittest` and live under `tests/`. Run the full suite with:

```bash
python -m unittest discover -s tests
```

## Project Status
Active. See `Phase.md` for the detailed, phase-by-phase feature history and `PLAN.md` for the current improvement roadmap.
