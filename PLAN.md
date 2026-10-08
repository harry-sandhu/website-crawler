# Project Improvement Plan

## Current State
Python CLI website-auditing tool: Playwright-based crawl engine feeding a multi-category audit engine (SEO, accessibility, performance, security, forms/compliance, visual, responsive, network/console), a scoring engine, and HTML/PDF/JSON report generation. 10 commits on `main`, private repo. Has a `tests/` suite (unittest) and a detailed `Phase.md` progress tracker spanning multiple completed phases plus a backlog of future ideas.

## What Is Already Good
- Clear separation of concerns: `browser/` (crawl), `audit/` (checks), `audit/scoring/` (scoring), `reports/` (output generation), `utils/` (logging/support).
- Broad, genuinely useful check coverage (SEO, a11y, performance, security, forms/compliance, visual, responsive) with an opt-in aggressive mode for active security probing.
- Optional AI-assisted design review is cleanly gated behind a flag and an env var (`ANTHROPIC_API_KEY`), with a graceful skip-and-warn when the key is absent.
- `Phase.md` gives an unusually thorough, honest record of what's done vs. planned — valuable project history.
- Has an actual test suite (`tests/`, unittest-based) covering normalization and security detections.

## Issues Found
- README was minimal (~12 lines: a one-line description and a bullet feature list) — no install steps, no usage example, no mention of Playwright browser install, no config/env var documentation, no testing instructions. This has been fixed in this pass (see README section below).
- Working tree currently has many pre-existing modified/untracked files (audit modules, crawler, main.py, requirements.txt, tests, Phase.md, url.md, plus new untracked files like `audit/security/exposure.py`, `audit/security/hardening.py`, `audit/visual/`, `browser/reveal.py`, `doneurl.txt`, `tests/test_new_audits.py`) representing active work-in-progress — left untouched by this documentation pass.
- No `requirements.txt` entry for `anthropic` despite `audit/visual/ai_review.py` depending on the Anthropic API — likely an installation gap for anyone enabling `--ai-review`.
- No pytest/unittest config or `pyproject.toml`/`setup.py` — tests are run via `python -m unittest discover`, which works but isn't declared anywhere until now (added to README).

## Documentation
README was previously minimal (12 lines, description + feature bullets only) and has been expanded into a full Overview / Features / Architecture / Tech Stack / Getting Started / Configuration / Usage / Testing / Project Status document reflecting the actual codebase structure and CLI flags.

## Code Quality
Not reviewed in depth as part of this documentation-only pass; no code changes made.

## Testing
Test suite exists (`tests/test_normalization.py`, `tests/test_security_detections.py`, and an in-progress `tests/test_new_audits.py`), using `unittest`. No CI workflow currently runs these automatically.

## Security
- This is a private repo and a legitimate security-auditing tool; the `--aggressive` flag enables active probing (XSS/SQLi/CSRF/IDOR/form-fuzzing) which is appropriate functionality for an authorized auditing tool, but the README now explicitly flags it should only be used against sites you own or are authorized to test.
- No secrets, keys, or credentials were found in README, requirements.txt, main.py, or the commit log reviewed.
- `ANTHROPIC_API_KEY` is read from the environment, not hardcoded — good practice already in place.

## Architecture
Crawl (Playwright) → Audit engine (per-category checks producing `Issue` objects) → Scoring engine (weighted score) → Report builders (HTML/PDF/JSON). Clean, modular, and consistent with how the codebase is laid out on disk.

## UX / UI
N/A — CLI tool, not reviewed for UX in this pass.

## Performance
N/A — not assessed in this pass.

## DevOps / Deployment
No CI/CD currently configured. Given there's already a test suite, a simple CI workflow (lint + unittest run) would be a reasonable low-effort addition.

## GitHub / Open Source Presentation
Private repo — not public-facing, so presentation polish is lower priority than for a public portfolio repo, but the README gap was still worth closing for the repo owner's and any collaborators' benefit.

## Screenshots / Visual Assets
N/A — not assessed in this pass.

## README
Expanded from ~12 lines (title + feature bullets) to a full README covering overview, features, architecture, tech stack, setup (including `playwright install`), configuration/env vars, usage examples with CLI flags, testing instructions, and project status.

## Priority Roadmap

### P0 — Critical
- N/A — no critical/blocking issues identified in this documentation pass.

### P1 — Important
- Add `anthropic` to `requirements.txt` (or document it as a separate optional extra) since `--ai-review` depends on it but it's currently absent from the dependency list.
- Add a minimal CI workflow to run the existing `tests/` suite automatically on push/PR.

### P2 — Nice to Have
- Add a `pyproject.toml` or `pytest.ini` to standardize test running/config.
- Consider documenting the `url.md` file format and `doneurl.txt` workflow (once the in-progress work stabilizes) for multi-URL batch runs.
- Expand `Phase.md`'s "Coming Soon"/"Future Ideas" items into tracked issues if the project moves toward collaboration.

## Recommended Next Steps
1. Add `anthropic` to `requirements.txt` to fix the install gap for `--ai-review`.
2. Set up a basic CI workflow (run `python -m unittest discover -s tests` on push/PR).
3. Once current in-progress work (visible in the working tree) is committed, review it against `Phase.md`'s "Coming Soon" items to keep the tracker accurate.
