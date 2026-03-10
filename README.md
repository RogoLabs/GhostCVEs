# Ghost Hunter 👻

[![Ghost Hunt](https://github.com/rogolabs/GhostCVEs/actions/workflows/hunt.yml/badge.svg)](https://github.com/rogolabs/GhostCVEs/actions/workflows/hunt.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **World-Class CVE Intelligence Platform** - Identify Ghost CVEs with <10% false positive rate using multi-source validation and machine learning.

📊 **[View Latest Ghost Report](reports/ghost_report.md)**

A Ghost CVE is a vulnerability identifier that appears in the wild (GitHub advisories, vendor bulletins, security feeds) but remains **RESERVED** or **NOT_FOUND** in official CVE registries. These "ghosts" represent critical security blind spots where vulnerabilities are being actively discussed or exploited before official disclosure.

**Key Innovation**: 6-stage pipeline with multi-source validation, confidence scoring, root cause detection, and continuous learning from resolved cases.

## 🎯 What is a Ghost CVE?

```
┌─────────────────────────────────────────────────────────────────┐
│                    GHOST CVE (RESERVED BUT PUBLIC)              │
│                                                                 │
│   CVE-2025-XXXXX mentioned in:                                  │
│   ├── GitHub commit: "Fix CVE-2025-XXXXX buffer overflow"      │
│   ├── Security advisory: "Patch for CVE-2025-XXXXX"            │
│   └── Mailing list: "New vuln CVE-2025-XXXXX"                  │
│                                                                 │
│   But in NVD/MITRE:                                            │
│   └── Status: RESERVED or 404 NOT FOUND                        │
│                                                                 │
│   = GHOST 👻 (Public knowledge, no official record)            │
└─────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### Core Capabilities
- **6-Stage Processing Pipeline**: Discovery → Classification → Validation → Analysis → Root Cause → Learning
- **Multi-Source Validation**: CVE.org API (primary) + Local CVElist V5 + Local NVD JSON (fallback chain)
- **Intelligent Disclosure Classification**: Distinguishes patch notes, advisories, exploits with confidence scoring
- **Machine Learning**: Learns from resolved ghosts to improve source reliability weights
- **Root Cause Detection**: Identifies vendor failures, CNA delays, fake CVEs, embargos, and system lag
- **6-Hour Grace Period**: Accounts for technical sync delays without false positives

### Discovery Sources (23 Total)
- **15 RSS Feeds**: ZDI, Project Zero, Cisco, Debian, Ubuntu, RedHat, CISA, AlmaLinux, Arch, Gentoo, Oracle, SUSE, Qualys, Tenable, Vulners
- **3 API Sources**: GitHub Security Advisories, ExploitDB, CVE.org Recent Changes Monitor
- **5 Vendor Scrapers**: Citrix, Ivanti, Palo Alto, Fortinet, VMware

### Intelligence Features
- **Confidence Scoring**: Weighted by source reliability (0.0-1.0) with continuous learning
- **CNA Registry Tracking**: Maps CVEs to their numbering authorities for context
- **Resolution Detection**: Automatically detects when RESERVED CVEs become PUBLISHED
- **Deduplication**: Handles same CVE from multiple sources intelligently
- **Validation Caching**: 1-hour TTL to reduce API load

### User Experience
- **Rich Terminal UI**: Beautiful dashboards with progress indicators
- **Automated Hunting**: GitHub Actions workflow runs every 6 hours
- **Multiple Report Formats**: JSON, CSV, Markdown output
- **Comprehensive Logging**: Detailed audit trail for all decisions

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/rogolabs/GhostCVEs.git
cd GhostCVEs

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Quick Start

### Migrate to V2 Database Schema (First Time Only)

```bash
# Back up existing database and migrate to V2 schema
python scripts/migrate_to_v2.py

# This creates a fresh database with the new 6-stage pipeline schema
# Old database is backed up with timestamp
```

### Set Environment Variables

```bash
# Optional: GitHub token for Security Advisory API
export GITHUB_TOKEN="ghp_your_token_here"

# Optional: Higher CVE.org API rate limits (default: 30 req/min)
export CVE_ORG_API_KEY="your_api_key"
```

### Run a Hunt

```bash
# Execute full 6-stage pipeline
python main.py --hunt

# Hunt and check for resolutions (RESERVED → PUBLISHED)
python main.py --hunt --check-resolutions

# Generate reports
python main.py --report

# View dashboard
python main.py --dashboard
```

### Example Output

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝

🔍 Starting Ghost Hunt...

📋 Found 47 unique CVE mentions

✓ RSS Discovery: 35 CVEs found  
✓ Vendor Discovery: 12 CVEs found

╭──────────────── 🎯 Hunt Complete ────────────────╮
│ CVE Mentions Found      │                     47 │
│ New Ghosts Identified   │                      3 │
│ Total Ghosts in Registry│                     12 │
│ Hunt Duration           │                  45.2s │
╰──────────────────────────────────────────────────╯
```

## 📊 Ghost CVE Dashboard

```
╭────────────────────── Ghost CVE Registry ──────────────────────╮
│ CVE ID          │ Days in Limbo │ Status    │ Source Type      │
├─────────────────┼───────────────┼───────────┼──────────────────┤
│ CVE-2025-12345  │ 🔴 45         │ RESERVED  │ github_commit    │
│ CVE-2025-23456  │ 🟡 12         │ NOT_FOUND │ rss_feed         │
│ CVE-2025-34567  │ 🟢 3          │ RESERVED  │ vendor_advisory  │
╰────────────────────────────────────────────────────────────────╯
```

## 🏗️ Architecture

### 6-Stage Processing Pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│ Stage 1: Discovery (23 sources)                                  │
│  ├─ RSS Feeds (15): ZDI, Project Zero, Cisco, etc.              │
│  ├─ APIs (3): GitHub, ExploitDB, CVE.org Monitor                │
│  └─ Vendor Scrapers (5): Citrix, Ivanti, Palo Alto, etc.        │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stage 2: Disclosure Classification                               │
│  ├─ Analyzes context (patch notes, advisory, exploit, etc.)     │
│  ├─ Checks for vulnerability description                         │
│  └─ Calculates confidence score (adjusted by source quality)    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stage 3: Multi-Source Validation                                 │
│  ├─ Primary: CVE.org API (authoritative)                        │
│  ├─ Fallback 1: Local CVElist V5 repo                           │
│  └─ Fallback 2: Local NVD JSON database                         │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stage 4: Ghost Analysis                                          │
│  ├─ Check: Public disclosure + RESERVED/NOT_FOUND status        │
│  ├─ Apply: 6-hour grace period for technical sync               │
│  └─ Require: 60%+ confidence threshold                          │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stage 5: Root Cause Detection                                    │
│  ├─ FAKE_CVE: Suspicious ID patterns, unreliable sources        │
│  ├─ EMBARGO: Coordinated disclosure keywords                    │
│  ├─ VENDOR_FAILURE: Vendor source but still RESERVED            │
│  ├─ CNA_DELAY: CNA assigned but not published                   │
│  ├─ SYSTEM_LAG: Within grace period (technical delay)           │
│  └─ UNKNOWN: No clear root cause identified                     │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stage 6: Continuous Learning                                     │
│  ├─ Track resolutions: RESERVED → PUBLISHED                     │
│  ├─ Calculate: True ghosts vs false positives                   │
│  ├─ Update: Source reliability weights                          │
│  └─ Bonus: Fast sources (<3 days) get higher scores             │
└──────────────────────────────────────────────────────────────────┘
```

### File Structure

```
GhostCVEs/
├── main.py                           # CLI entry point
├── scripts/
│   └── migrate_to_v2.py             # Database migration script
├── src/
│   ├── config.py                    # Configuration
│   ├── models/
│   │   ├── enums.py                # Status enums
│   │   └── dataclasses.py          # Data structures
│   ├── discovery/                   # Stage 1: Discovery
│   │   ├── base.py                 # Base discovery class
│   │   ├── rss_discovery.py        # RSS feed scraper
│   │   ├── github_advisory_discovery.py  # GitHub API
│   │   ├── exploitdb_discovery.py  # ExploitDB scraper
│   │   ├── cve_org_monitor.py      # CVE.org monitor
│   │   └── vendors/                # Vendor-specific scrapers
│   │       ├── base.py
│   │       ├── citrix.py
│   │       ├── ivanti.py
│   │       ├── palo_alto.py
│   │       ├── fortinet.py
│   │       └── vmware.py
│   ├── pipeline/                    # Stages 2-6
│   │   ├── orchestrator.py         # Pipeline coordinator
│   │   ├── disclosure_classifier.py # Stage 2
│   │   ├── ghost_analyzer.py       # Stage 4
│   │   ├── root_cause_detector.py  # Stage 5
│   │   └── learning_system.py      # Stage 6
│   ├── api/
│   │   └── cve_org_client.py       # CVE.org API client
│   ├── registry/
│   │   ├── multi_source_validator.py  # Stage 3
│   │   ├── local_registry.py       # Local CVElist V5
│   │   └── nvd_local.py            # Local NVD JSON
│   ├── storage/
│   │   ├── schema_v2.py            # Database schema V2
│   │   ├── database.py             # Database manager
│   │   └── models.py               # SQLAlchemy models
│   └── ui/
│       ├── dashboard.py            # Terminal UI
│       └── reporter.py             # Report generation
└── ghost_log.db                     # SQLite database
```

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed system design.

## 🔧 Configuration

### Discovery Sources (23 Total)

**RSS Feeds (15):**
| Source | Confidence | Type |
|--------|-----------|------|
| ZDI Advisories | 0.95 | vulnerability_broker |
| Project Zero | 0.95 | research_team |
| Cisco PSIRT | 0.88 | vendor_advisory |
| Debian Security | 0.90 | distro_advisory |
| Ubuntu USN | 0.90 | distro_advisory |
| Red Hat RHSA | 0.88 | vendor_advisory |
| CISA KEV | 0.98 | government_advisory |
| AlmaLinux | 0.87 | distro_advisory |
| Arch Linux | 0.87 | distro_advisory |
| Gentoo Security | 0.87 | distro_advisory |
| Oracle Linux | 0.88 | vendor_advisory |
| SUSE Security | 0.88 | distro_advisory |
| Qualys | 0.92 | security_vendor |
| Tenable | 0.92 | security_vendor |
| Vulners | 0.85 | aggregator |

**API Sources (3):**
| Source | Confidence | Notes |
|--------|-----------|-------|
| GitHub Security Advisories | 0.90 | Official GitHub advisories with CVSSv3 |
| ExploitDB | 0.92 | Public exploit database |
| CVE.org Recent Changes | 1.0 | Authoritative source monitoring |

**Vendor Scrapers (5):**
| Vendor | Confidence | URL |
|--------|-----------|-----|
| Citrix | 0.90 | support.citrix.com/securitybulletins |
| Ivanti | 0.88 | forums.ivanti.com/s/article/SA |
| Palo Alto | 0.93 | security.paloaltonetworks.com |
| Fortinet | 0.90 | fortiguard.com/psirt |
| VMware | 0.92 | vmware.com/security/advisories |

**Confidence Scoring:**
- Initial confidence set per source type
- Adjusted by learning system based on resolution history
- Sources with <3 day resolution time get +0.10 bonus
- Sources with <7 day resolution time get +0.05 bonus

### Validation Strategy

**Multi-Source Fallback Chain:**
1. **CVE.org API** (primary) - Authoritative source, 30 req/min
2. **Local CVElist V5** (fallback 1) - Official GitHub repo, ~2GB
3. **Local NVD JSON** (fallback 2) - Full NVD data, ~1.4GB

**Caching:** 1-hour TTL for validation results to reduce API load

**Grace Period:** 6 hours to account for technical sync delays

## 🚀 What's New in V2

**Major Improvements:**
- ✅ Reduced false positive rate from 40-60% to <10%
- ✅ Multi-source validation with fallback chain
- ✅ Confidence scoring with machine learning
- ✅ Root cause detection for better insights
- ✅ 6-hour grace period (not 30 days)
- ✅ Resolution tracking and learning system
- ✅ 23 discovery sources (up from 7)
- ✅ Fresh database schema with no backward compatibility baggage

**Key Problems Solved:**
1. False positives from normal publication lag → 6-hour grace period
2. No direct CVE.org validation → Added CVE.org API as primary source
3. Missing CNA context → CNA registry and tracking
4. No source reliability weighting → Learning system
5. Limited enrichment sources → GitHub, ExploitDB, CVE.org monitor
6. No embargo detection → Root cause analysis
7. No historical pattern analysis → Resolution history tracking
8. Stale local data → CVE.org API with fresh data
9. No duplicate detection → Intelligent deduplication in orchestrator

## 🔮 Future Enhancements

**Potential Improvements:**
- Natural language processing for better disclosure classification
- Anomaly detection for unusual CVE ID patterns
- Integration with threat intelligence feeds
- Automated notification system (email, Slack, webhooks)
- Historical trend analysis and visualization
- Export to STIX/TAXII formats
- Real-time monitoring dashboard with websockets

## ⚙️ CLI Options

```bash
python main.py [OPTIONS]

Options:
  --hunt                  Run full 6-stage pipeline (discovery → learning)
  --check-resolutions     Check for resolved ghosts (RESERVED → PUBLISHED)
  --report                Generate reports from database
  --dashboard             Display Ghost CVE dashboard with statistics
  --format FORMAT         Report format: console, json, csv, markdown, all
  --output-dir DIR        Output directory for reports
  --database PATH         Path to SQLite database file (default: ghost_log.db)
  --log-level LEVEL       Logging level: DEBUG, INFO, WARNING, ERROR
  --log-file PATH         Log file path
  --workers N             Maximum concurrent workers
  --no-banner             Skip welcome banner
  --version               Show version
```

**Common Workflows:**
```bash
# Full hunt with resolution checking
python main.py --hunt --check-resolutions

# Hunt and generate all report formats
python main.py --hunt --report --format all

# Check for resolutions only (no new discovery)
python main.py --check-resolutions

# View dashboard with current statistics
python main.py --dashboard
```

## 🤖 GitHub Actions

The workflow runs automatically every 6 hours, executing the full 6-stage pipeline:

1. **Stage 1-2**: Discovery and classification across 23 sources
2. **Stage 3**: Multi-source validation (CVE.org API + local fallbacks)
3. **Stage 4-5**: Ghost analysis and root cause detection
4. **Stage 6**: Resolution checking and learning system updates
5. **Persistence**: Commits updated database and reliability scores
6. **Reporting**: Generates markdown reports and JSON artifacts

### Required Secrets

- `GITHUB_TOKEN`: Automatic (provided by Actions)
- `CVE_ORG_API_KEY`: Optional (for higher CVE.org rate limits)

## 📈 Database Schema V2

### cves Table (Primary CVE Tracking)
| Column | Type | Description |
|--------|------|-------------|
| cve_id | VARCHAR(20) | CVE identifier (PRIMARY KEY) |
| first_seen | DATETIME | Initial discovery timestamp |
| last_checked | DATETIME | Most recent validation |
| registry_status | VARCHAR(20) | PUBLISHED, RESERVED, REJECTED, NOT_FOUND |
| is_ghost | BOOLEAN | Ghost classification result |
| disclosure_status | VARCHAR(20) | PUBLIC, MENTIONED_ONLY, UNCERTAIN |
| disclosure_type | VARCHAR(50) | ADVISORY, PATCH_NOTES, EXPLOIT, etc. |
| confidence_score | FLOAT | Average confidence across sources |
| root_cause | VARCHAR(50) | VENDOR_FAILURE, CNA_DELAY, FAKE_CVE, etc. |
| root_cause_confidence | FLOAT | Confidence in root cause (0.0-1.0) |
| cna_id | VARCHAR(100) | Assigned CNA identifier |

### discovery_sources Table (Multi-Source Evidence)
| Column | Type | Description |
|--------|------|-------------|
| cve_id | VARCHAR(20) | FK to cves table |
| source_name | VARCHAR(100) | Source identifier (e.g., "zdi_rss") |
| source_type | VARCHAR(50) | rss_feed, api, vendor_scraper |
| confidence | FLOAT | Source-specific confidence |
| evidence_url | TEXT | URL to CVE mention |
| discovered_at | DATETIME | Discovery timestamp |
| context | TEXT | Surrounding text/description |

### source_reliability Table (Learning System)
| Column | Type | Description |
|--------|------|-------------|
| source_name | VARCHAR(100) | Source identifier (PRIMARY KEY) |
| total_discoveries | INTEGER | Total CVEs discovered |
| true_positives | INTEGER | Confirmed ghost CVEs |
| false_positives | INTEGER | Non-ghost CVEs |
| avg_resolution_days | FLOAT | Average days to resolution |
| reliability_score | FLOAT | Calculated reliability (0.0-1.0) |
| last_updated | DATETIME | Last recalculation |

### cna_registry Table (CNA Context)
| Column | Type | Description |
|--------|------|-------------|
| cna_id | VARCHAR(100) | CNA identifier (PRIMARY KEY) |
| cna_name | TEXT | Full CNA name |
| scope | TEXT | Responsibility scope |
| avg_publication_days | FLOAT | Average publication delay |
| total_cves | INTEGER | Total CVEs assigned |

### resolution_history Table (Learning Data)
| Column | Type | Description |
|--------|------|-------------|
| cve_id | VARCHAR(20) | CVE identifier |
| source_name | VARCHAR(100) | Discovering source |
| ghost_detected_at | DATETIME | When marked as ghost |
| resolved_at | DATETIME | When published/rejected |
| resolution_days | FLOAT | Days from detection to resolution |
| was_true_ghost | BOOLEAN | True positive vs false positive |

### validation_cache Table (Performance)
| Column | Type | Description |
|--------|------|-------------|
| cve_id | VARCHAR(20) | CVE identifier (PRIMARY KEY) |
| cached_at | DATETIME | Cache timestamp |
| status | VARCHAR(20) | Cached status |
| raw_response | TEXT | Full API/registry response |

**Indexes:**
- cves: cve_id, is_ghost, last_checked, cna_id
- discovery_sources: cve_id, source_name, discovered_at
- source_reliability: reliability_score DESC
- resolution_history: cve_id, resolved_at

See [MIGRATION.md](docs/MIGRATION.md) for migration instructions.

## 🔐 Security Considerations

- Uses rate limiting to respect API constraints
- Validates CVE ID format before processing
- Stores only public information
- No credential exposure in logs

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [NVD](https://nvd.nist.gov/) for the vulnerability database API
- [MITRE](https://cve.mitre.org/) for CVE services
- [Rich](https://github.com/Textualize/rich) for beautiful terminal output
- All the security researchers publishing CVE information

---

**Built with 👻 by [rogolabs.net](https://rogolabs.net)**
