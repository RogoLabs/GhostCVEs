# Ghost Hunter 👻

[![Ghost Hunt](https://github.com/rogolabs/GhostCVEs/actions/workflows/hunt.yml/badge.svg)](https://github.com/rogolabs/GhostCVEs/actions/workflows/hunt.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **CVE Intelligence Platform** - Identify Ghost CVEs mentioned in public sources but missing from official registries.

📊 **[View Latest Ghost Report](reports/ghost_report.md)**

A Ghost CVE is a vulnerability identifier that appears in the wild (GitHub commits, security advisories, RSS feeds) but remains **RESERVED** or **NOT_FOUND** in official CVE registries like NVD and MITRE. These "ghosts" represent potential security blind spots where vulnerabilities are being discussed publicly before official disclosure.

## 🎯 What is a Ghost CVE?

```
┌─────────────────────────────────────────────────────────────────┐
│                         GHOST CVE                               │
│                                                                 │
│   CVE-2025-XXXXX mentioned in:                                  │
│   ├── GitHub commit: "Fix CVE-2025-XXXXX buffer overflow"      │
│   ├── Security advisory: "Patch for CVE-2025-XXXXX"            │
│   └── Mailing list: "New vuln CVE-2025-XXXXX"                  │
│                                                                 │
│   But in NVD/MITRE:                                            │
│   └── Status: RESERVED or 404 NOT FOUND                        │
│                                                                 │
│   = GHOST 👻                                                    │
└─────────────────────────────────────────────────────────────────┘
```

## ✨ Features

- **Multi-Source Discovery**: Monitors GitHub (code + commits), RSS feeds, vendor advisories
- **Registry Validation**: Validates CVEs against NVD API 2.0 and MITRE CVE Services
- **Intelligent Tracking**: Preserves first-seen dates while updating status
- **Rich Terminal UI**: Beautiful dashboards and progress indicators
- **Automated Hunting**: GitHub Actions workflow runs every 6 hours
- **Multiple Report Formats**: JSON, CSV, Markdown output
- **Serverless Data History**: SQLite database committed back to repo

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

### Set Environment Variables

```bash
# Required for GitHub discovery
export GITHUB_TOKEN="ghp_your_token_here"

# Optional: Higher NVD rate limits
export NVD_API_KEY="your_nvd_api_key"
```

### Run a Hunt

```bash
# Execute discovery and validation
python main.py --hunt

# Generate reports
python main.py --report

# Hunt then report
python main.py --hunt --report

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

✓ GitHub Discovery: 23 CVEs found
✓ RSS Discovery: 18 CVEs found  
✓ Vendor Discovery: 6 CVEs found

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

```
GhostCVEs/
├── main.py                 # Entry point with argparse
├── src/
│   ├── config.py          # Configuration and constants
│   ├── discovery/         # Source scrapers
│   │   ├── base.py       # Abstract base class
│   │   ├── github_discovery.py
│   │   ├── rss_discovery.py
│   │   └── vendor_discovery.py
│   ├── registry/          # CVE validation
│   │   └── validator.py   # CVEValidator class
│   ├── storage/           # Persistence layer
│   │   ├── models.py     # SQLAlchemy models
│   │   └── database.py   # DatabaseManager
│   └── ui/                # Terminal interface
│       ├── dashboard.py   # Rich dashboards
│       └── reporter.py    # Report generation
├── .github/
│   └── workflows/
│       └── hunt.yml       # Automated hunting
└── ghost_log.db           # SQLite database
```

## 🔧 Configuration

### RSS Feeds (Pre-configured)

| Source | Type | Priority |
|--------|------|----------|
| ZDI Advisories | vulnerability_broker | 1 |
| Project Zero Blog | research_team | 1 |
| Cisco PSIRT | vendor_advisory | 2 |
| Debian Security | distro_advisory | 2 |
| Ubuntu USN | distro_advisory | 2 |
| Red Hat RHSA | vendor_advisory | 2 |
| CISA KEV | government_advisory | 1 |

### GitHub Search

- Monitors commits and code for `CVE-202[5-9]-\d{4,}`
- Supports authenticated requests for higher rate limits
- Extracts context around CVE mentions

## ⚙️ CLI Options

```bash
python main.py [OPTIONS]

Options:
  --hunt              Run CVE discovery and validation
  --report            Generate reports from database
  --dashboard         Display Ghost CVE dashboard
  --format FORMAT     Report format: console, json, csv, markdown, all
  --output-dir DIR    Output directory for reports
  --database PATH     Path to SQLite database file
  --log-level LEVEL   Logging level: DEBUG, INFO, WARNING, ERROR
  --log-file PATH     Log file path
  --workers N         Maximum concurrent workers
  --no-banner         Skip welcome banner
  --version           Show version
```

## 🤖 GitHub Actions

The workflow runs automatically every 6 hours:

1. **Discovery**: Scrapes all configured sources
2. **Validation**: Checks CVEs against NVD/MITRE
3. **Persistence**: Commits updated database to repo
4. **Reporting**: Generates artifacts and summaries
5. **Alerting**: Creates issues for new Ghost CVEs

### Required Secrets

- `GITHUB_TOKEN`: Automatic (provided by Actions)
- `NVD_API_KEY`: Optional (for higher rate limits)

## 📈 Database Schema

### GhostCVE Table
| Column | Type | Description |
|--------|------|-------------|
| cve_id | VARCHAR(20) | CVE identifier (unique) |
| first_seen | DATETIME | When CVE was first discovered |
| last_checked | DATETIME | Most recent validation |
| registry_status | VARCHAR(20) | RESERVED, NOT_FOUND, etc. |
| is_ghost | BOOLEAN | Ghost classification |
| confidence_score | FLOAT | Average discovery confidence |

### DiscoverySource Table
| Column | Type | Description |
|--------|------|-------------|
| ghost_cve_id | INTEGER | FK to GhostCVE |
| source_type | VARCHAR(50) | github_commit, rss_feed, etc. |
| evidence_url | TEXT | URL to CVE mention |
| discovered_at | DATETIME | Discovery timestamp |
| context | TEXT | Surrounding text |

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
