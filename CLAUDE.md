# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GhostCVEs ("Ghost Hunter") identifies "Ghost CVEs" — vulnerability identifiers that appear in public sources (GitHub advisories, RSS feeds, vendor pages) but remain RESERVED or NOT_FOUND in official CVE registries (CVE.org, NVD). It runs a 6-stage detection pipeline every 6 hours via GitHub Actions.

## Commands

```bash
# Run the full 6-stage hunt pipeline
python main.py --hunt

# Hunt + check for resolved ghosts (RESERVED → PUBLISHED)
python main.py --hunt --check-resolutions

# Generate reports (JSON, CSV, Markdown)
python main.py --report --format all --output-dir reports

# Terminal dashboard
python main.py --dashboard

# Source reliability audit
python main.py --audit

# Run all tests with coverage
pytest

# Run specific test directory
pytest tests/pipeline/
pytest tests/discovery/
pytest tests/integration/

# Linting and formatting
ruff check src/ tests/
ruff check --fix src/ tests/
black src/ tests/
mypy src/
```

pytest is configured in `pyproject.toml` with `addopts = "-v --cov=src --cov-report=term-missing"`.

## Architecture

### 6-Stage Pipeline (`src/pipeline/orchestrator.py`)

1. **Discovery** (`src/discovery/`): Collects CVE mentions from 23 sources — 15 RSS feeds (`rss_discovery.py`), GitHub Security Advisories API, ExploitDB scraper, CVE.org monitor, and 5 vendor scrapers (`vendors/`). All inherit from `BaseDiscovery`.

2. **Disclosure Classification** (`src/pipeline/disclosure_classifier.py`): Determines if a CVE is publicly disclosed (PUBLIC), merely mentioned (MENTIONED_ONLY), or uncertain. Adjusts confidence by source reliability.

3. **Multi-Source Validation** (`src/registry/multi_source_validator.py`): Checks CVE status via 3-tier fallback: CVE.org API → Local CVElist V5 → Local NVD JSON. Results cached for 1 hour.

4. **Ghost Analysis** (`src/pipeline/ghost_analyzer.py`): A CVE is a ghost if: disclosure=PUBLIC + validation=RESERVED/NOT_FOUND + age > 6hr grace period + avg confidence ≥ 0.60.

5. **Root Cause Detection** (`src/pipeline/root_cause_detector.py`): Attributes cause: FAKE_CVE, EMBARGO, VENDOR_FAILURE, CNA_DELAY, SYSTEM_LAG, or UNKNOWN.

6. **Continuous Learning** (`src/pipeline/learning_system.py`): Tracks resolutions and updates source reliability scores for future weighting.

### Key Modules

- **Entry point**: `main.py` — CLI with argparse, orchestrates pipeline/reports/dashboard
- **Configuration**: `src/config.py` — all source definitions, CVE patterns, confidence thresholds
- **Data models**: `src/models/enums.py` (status enums), `src/models/dataclasses.py` (pipeline data structures)
- **Database**: `src/storage/database.py` (SQLAlchemy ORM), `src/storage/models.py` (table models), `src/storage/schema_v2.py` (current schema)
- **API client**: `src/api/cve_org_client.py` — rate-limited to 30 req/min
- **UI**: `src/ui/dashboard.py` (Rich terminal), `src/ui/reporter.py` (file reports)

### Database

SQLite (`ghost_log.db`). Key tables: `ghost_cves`, `discovery_sources`, `source_reliability`, `resolution_history`, `validation_cache`, `hunt_runs`. Schema defined in `src/storage/schema_v2.py`.

### CI/CD

- `.github/workflows/hunt.yml`: Runs every 6 hours. Caches CVE data files and database. Includes git push retry logic with exponential backoff, weekly VACUUM, monthly archiving, and critical ghost alerting.
- `.github/workflows/pages.yml`: Generates GitHub Pages dashboard after each hunt.
- Dashboard data written to `docs/_data/` and served from `docs/index.html`.

## Environment Variables

- `GITHUB_TOKEN` — GitHub API access (optional, increases rate limits)
- `NVD_API_KEY` — NVD API key (optional)

## Key Design Decisions

- GitHub code search discovery is disabled (too much noise from fake repos)
- 24 RSS feeds are commented out in config due to 404/403/parse errors
- Grace period of 6 hours prevents false positives from normal CVE publication lag
- The project targets <10% false positive rate through multi-source validation and confidence scoring
- Large data files (`data/cvelistV5/`, `data/nvd.json`) are gitignored and cached in CI

## Code Style

Configured in `pyproject.toml`: Black (line-length 88), Ruff (E/W/F/I/B/C4/UP/ARG/SIM rules), mypy strict mode. Python 3.11+.
