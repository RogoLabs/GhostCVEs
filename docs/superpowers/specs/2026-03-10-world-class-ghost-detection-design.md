# World-Class Ghost CVE Detection System - Design Specification

**Version:** 2.0
**Date:** 2026-03-10
**Status:** Approved for Implementation
**Author:** rogolabs.net with Claude Opus 4.6

---

## Executive Summary

This specification details a complete redesign of the GhostCVEs detection system to achieve world-class vulnerability intelligence. The redesign addresses 10 critical problems identified by vulnerability researcher analysis, reducing false positive rate from 40-60% to <10%.

**Key Improvements:**
- 6-hour grace period (not 30 days) for technical sync
- 23 discovery sources (up from 15)
- Multi-source validation with CVE.org API as primary
- Source reliability weighting with machine learning
- Root cause detection (vendor failure, CNA delay, fake CVE, etc.)
- Automated learning system from resolved ghosts
- Fresh start: clean database schema, no backward compatibility

**Success Criteria:**
- False positive rate < 10%
- 95%+ confidence in ghost classifications
- Root cause identified for 80%+ of ghosts
- Learning system improves accuracy over time
- Zero external infrastructure costs (100% GitHub-native)

---

## 1. Problem Statement

### Current System Issues

**Problem 1: False Positives from Normal Publication Lag** (CRITICAL)
- Current: Immediately flags CVE as ghost if RESERVED/NOT_FOUND
- Reality: 7-14 day lag between vendor advisory and NVD publication is normal
- Impact: ~40-60% false positive rate

**Problem 2: Not Checking CVE.org Directly** (HIGH)
- Current: Only local CVElist clone + NVD JSON (can be days old)
- Missing: CVE.org API - authoritative source, real-time data
- Impact: Missing CVEs that are already published

**Problem 3: No CNA Context** (HIGH)
- Current: No tracking of which CNA issued CVE
- Missing: CNA performance patterns (Microsoft: 7 days, Unknown vendor: 45 days)
- Impact: Can't set appropriate expectations per CNA

**Problem 4: No Source Reliability Weighting** (MEDIUM)
- Current: Treating ZDI advisory (99% reliable) = mailing list post (60% reliable)
- Impact: High-quality sources diluted by noise

**Problem 5: Missing Enrichment Sources** (MEDIUM)
- Current: Only RSS feeds + local registries
- Missing: GitHub Security Advisories API, ExploitDB, CVE.org monitoring, vendor pages
- Impact: Missing critical CVE disclosures

**Problem 6: No Embargo Detection** (MEDIUM)
- Current: Flags embargoed CVEs as ghosts
- Reality: Many CVEs intentionally RESERVED during coordinated disclosure
- Impact: False positives from legitimate embargo periods

**Problem 7: No Historical Analysis** (HIGH)
- Current: No learning from resolved ghosts
- Missing: Pattern recognition, source accuracy improvement
- Impact: System doesn't get smarter over time

**Problem 8: No Pattern Recognition** (MEDIUM)
- Current: No temporal or vendor-specific patterns
- Missing: Peak disclosure periods (Pwn2Own, BlackHat), vendor patterns
- Impact: Missed optimization opportunities

**Problem 9: Stale Local Data** (MEDIUM)
- Current: Local data could be hours/days old
- Missing: Freshness checks for high-priority CVEs
- Impact: Delayed detection of publications

**Problem 10: No Duplicate Detection** (LOW)
- Current: Same CVE counted multiple times across sources
- Missing: Related/duplicate/superseded CVE detection
- Impact: Inflated statistics, noise

---

## 2. Solution Architecture

### 2.1 Enhanced Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EXPANDED DISCOVERY (23 SOURCES)                  │
├─────────────────────────────────────────────────────────────────────────┤
│  RSS Feeds (15)          │  APIs (3)                │  Scrapers (5)     │
│  - ZDI (2)               │  - GitHub Security       │  - Microsoft MSRC │
│  - Vendor (8)            │  - CVE.org Recent        │  - Apple Security │
│  - Gov (1)               │  - ExploitDB             │  - Adobe Security │
│  - Mailing Lists (2)     │                          │  - Oracle Security│
│  - Registry (2)          │                          │  - Google Security│
└──────────────────────────┴──────────────────────────┴───────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                         6-STAGE PROCESSING PIPELINE                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Stage 1: Discovery (Existing)                                         │
│  └─ Output: DiscoveryResult (CVE ID, source, context)                  │
│                                                                         │
│  Stage 2: Disclosure Classification (NEW)                              │
│  └─ Input: DiscoveryResult                                             │
│  └─ Logic: CVE + description OR CVE in patch notes = PUBLIC            │
│  └─ Output: DisclosureStatus (PUBLIC, MENTIONED_ONLY, UNCERTAIN)       │
│                                                                         │
│  Stage 3: Multi-Source Validation (ENHANCED)                           │
│  └─ Primary: CVE.org API (real-time, authoritative)                    │
│  └─ Secondary: Local CVElist V5 (fast, hours old)                      │
│  └─ Tertiary: Local NVD JSON (comprehensive, days old)                 │
│  └─ Output: ValidationResult (PUBLISHED, RESERVED, NOT_FOUND)          │
│                                                                         │
│  Stage 4: Ghost Analysis (NEW)                                         │
│  └─ Apply 6-hour grace period                                          │
│  └─ Calculate confidence from source reliability                       │
│  └─ Output: GhostAnalysis (is_ghost, confidence 0.0-1.0)              │
│                                                                         │
│  Stage 5: Root Cause Detection (NEW)                                   │
│  └─ Analyze CNA, vendor, source patterns                               │
│  └─ Output: GhostRootCause (VENDOR_FAILURE, CNA_DELAY, FAKE_CVE, etc.)│
│                                                                         │
│  Stage 6: Learning System (NEW)                                        │
│  └─ When ghost resolves: update source reliability, CNA stats          │
│  └─ Track resolution patterns                                          │
│  └─ Improve future confidence scoring                                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                          STORAGE & REPORTING                            │
│  - Fresh database schema (no backward compatibility)                   │
│  - Source reliability tracking                                         │
│  - CNA registry and patterns                                           │
│  - Resolution history for learning                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Key Design Principles

1. **6-Hour Grace Period** - Technical sync only, not CVE lifecycle tolerance
2. **Public = CVE + Description OR Patch Notes** - Clear disclosure criteria
3. **Multi-Source Validation** - CVE.org first, graceful degradation
4. **Source Reliability Weighting** - Learn from outcomes
5. **Root Cause Tracking** - Understand why CVEs are ghosts
6. **Continuous Learning** - System improves with every resolution
7. **Fresh Start** - Clean slate, no backward compatibility constraints

---

## 3. Component Architecture

### 3.1 New Components

#### GhostDetectionPipeline
**Purpose:** Orchestrates 6-stage processing
**Responsibilities:**
- Coordinate data flow between stages
- Handle errors gracefully
- Maintain audit trail
- Process discoveries end-to-end

```python
class GhostDetectionPipeline:
    def __init__(self, db: DatabaseManager, config: PipelineConfig):
        self.disclosure_classifier = DisclosureClassifier()
        self.multi_source_validator = MultiSourceValidator(db)
        self.ghost_analyzer = GhostAnalyzer(db)
        self.root_cause_detector = RootCauseDetector(db)
        self.learning_system = LearningSystem(db)

    def process(self, discovery: DiscoveryResult) -> ProcessedCVE:
        # Run through all 6 stages
        # Return complete CVE analysis
```

#### DisclosureClassifier
**Purpose:** Determine if CVE mention is true public disclosure
**Rules:**
- CVE + vulnerability description → PUBLIC
- CVE in patch notes/release notes → PUBLIC
- CVE ID only mentioned → MENTIONED_ONLY
- Can't determine → UNCERTAIN

**Output:** DisclosureClassification with status, type, confidence, reasoning

#### MultiSourceValidator
**Purpose:** Validate CVE across multiple sources with intelligent fallback
**Priority Order:**
1. CVE.org API (real-time, authoritative)
2. Local CVElist V5 (fast, hours old)
3. Local NVD JSON (comprehensive, days old)

**Features:**
- 1-hour validation cache
- Rate limiting per source
- Graceful degradation on errors

#### GhostAnalyzer
**Purpose:** Determine if CVE is a Ghost with confidence scoring
**Logic:**
```
Ghost = PUBLIC disclosure
        AND (RESERVED or NOT_FOUND)
        AND past 6-hour grace period
        AND confidence ≥ 0.60
```

**Confidence Scoring:**
- Base: Disclosure clarity (0.7-1.0)
- Weighted by: Source reliability (0.6-0.98)
- Boost: Multiple sources (+10-20%)
- Boost: High-quality sources (+15%)
- Boost: Age (72hr: +10%, 7d: +20%)
- Penalty: Only mailing lists (-20%)

#### RootCauseDetector
**Purpose:** Identify why CVE is a Ghost
**Root Causes:**
- **VENDOR_FAILURE** - Vendor disclosed but didn't publish CVE
- **CNA_DELAY** - CNA hasn't processed publication request
- **SYSTEM_LAG** - API/sync delays (rare with 6hr grace)
- **FAKE_CVE** - Suspicious patterns, likely fake
- **EMBARGO** - Under coordinated disclosure
- **UNKNOWN** - Can't determine yet

**Detection Logic:**
- Check for fake indicators (ID > 100k, all-same-digits, future year)
- Check embargo indicators (keywords, ZDI Upcoming feed)
- Analyze CNA performance (slow CNAs vs fast CNAs)
- Check source quality (official vendor vs forum)

#### LearningSystem
**Purpose:** Learn from resolved Ghosts to improve detection
**On Ghost Resolution:**
1. Determine if true ghost (>1 day) or false positive (<1 day)
2. Update source reliability scores
3. Update CNA statistics (avg lag, ghost rate)
4. Store resolution pattern
5. Recalculate weights if threshold met (50 resolutions or 7 days)

#### SourceReliabilityTracker
**Purpose:** Track and learn source reliability over time
**Metrics:**
- Reliability score (0.0-1.0)
- Total discoveries
- True positives / false positives
- Average time to publish
- Median time to publish

**Learning:**
- True ghost → increase reliability
- False positive → decrease reliability
- Fast publication → bonus
- Recalculate weekly or per 50 resolutions

#### CNARegistry
**Purpose:** Track CNA metadata and patterns
**Data:**
- CNA name and type
- Average publication lag (days)
- Median publication lag
- Reliability score
- Total CVEs tracked
- Ghost rate (%)
- ID allocation ranges

**Learning:**
- Update lag times from resolutions
- Track ghost rates per CNA
- Identify slow vs fast CNAs

### 3.2 Enhanced Components

#### CVEValidator → MultiSourceValidator
**Changes:**
- Add CVE.org API as primary source
- Implement fallback chain
- Add validation cache (1hr TTL)
- Remove NVD API calls (use local NVD + CVE.org instead)

#### DiscoveryOrchestrator
**Changes:**
- Add 8 new discovery modules (4 APIs, 5 scrapers)
- Parallel execution with ThreadPoolExecutor
- Deduplication by CVE ID
- Source merging for multi-source CVEs

---

## 4. Discovery Module Expansion

### 4.1 New API-Based Discovery

#### GitHubAdvisoryDiscovery
**Source:** GitHub Security Advisories Database
**Method:** GitHub GraphQL API
**Reliability:** 0.90 (high quality, curated)
**Rate Limit:** 5000 requests/hour (GitHub token)
**Query:** Advisories updated in last 30 days with CVE IDs
**Output:** Structured data (description, severity, affected packages)

#### CVEOrgMonitor
**Source:** CVE.org Recent Changes
**Method:** CVE.org API
**Reliability:** 1.0 (authoritative)
**Rate Limit:** 30 requests/minute
**Query:** `time_modified.gt=<timestamp>` for recent changes
**Purpose:** Track RESERVED→PUBLISHED transitions in real-time

#### ExploitDBDiscovery
**Source:** ExploitDB
**Method:** ExploitDB API/RSS
**Reliability:** 0.92 (verified exploits)
**Filter:** Recent exploits (last 90 days)
**Priority:** HIGH - exploited CVEs are critical

### 4.2 New Vendor Page Scrapers

**Base Class:** VendorPageScraper
**Common Features:**
- HTML parsing with BeautifulSoup
- Rate limiting (respectful crawling)
- Error handling and retries
- XPath/CSS selector based extraction

**Vendor-Specific Implementations:**

1. **MicrosoftMSRCScraper**
   - URL: https://msrc.microsoft.com/update-guide
   - Reliability: 0.95
   - Format: Structured security updates

2. **AppleSecurityScraper**
   - URL: https://support.apple.com/en-us/HT201222
   - Reliability: 0.93
   - Format: Security update tables

3. **AdobeSecurityScraper**
   - URL: https://helpx.adobe.com/security.html
   - Reliability: 0.85
   - Format: Security bulletins

4. **OracleSecurityScraper**
   - URL: https://www.oracle.com/security-alerts/
   - Reliability: 0.84
   - Format: Critical Patch Updates

5. **GoogleSecurityScraper**
   - URL: https://source.android.com/security/bulletin
   - Reliability: 0.88
   - Format: Android security bulletins

### 4.3 Discovery Summary

**Total Sources: 23**
- RSS Feeds: 15 (existing)
- APIs: 3 (new)
- Vendor Scrapers: 5 (new)

**Execution:** Parallel with ThreadPoolExecutor (max_workers=10)
**Deduplication:** By CVE ID, merge sources for same CVE
**Priority:** High-quality sources processed first

---

## 5. Data Models

### 5.1 Fresh Database Schema

**Design Decision:** Fresh start, no backward compatibility
**Rationale:** Old data has 40-60% false positives, would contaminate learning

#### Table: cves (replaces ghost_cves)

```sql
CREATE TABLE cves (
    id INTEGER PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,

    -- Discovery
    first_discovered TEXT NOT NULL,
    discovery_method TEXT,

    -- Disclosure classification
    disclosure_status TEXT NOT NULL,  -- PUBLIC, MENTIONED_ONLY, UNCERTAIN
    disclosure_type TEXT,  -- ADVISORY, PATCH_NOTES, EXPLOIT, CONFERENCE
    public_disclosure_date TEXT NOT NULL,

    -- Validation
    cve_status TEXT NOT NULL,  -- PUBLISHED, RESERVED, NOT_FOUND, REJECTED
    validated_at TEXT NOT NULL,
    validation_source TEXT,  -- CVE_ORG, CVELISTV5, NVD_LOCAL

    -- Ghost classification
    is_ghost BOOLEAN NOT NULL,
    ghost_confidence REAL,  -- 0.0-1.0
    grace_period_expires TEXT,
    root_cause TEXT,  -- VENDOR_FAILURE, CNA_DELAY, FAKE_CVE, etc.

    -- CNA info
    cna_name TEXT,
    cna_confidence REAL,

    -- Metadata
    description TEXT,
    published_date TEXT,
    last_modified TEXT,
    resolved_date TEXT,

    -- Computed
    days_since_disclosure INTEGER,
    days_to_resolution INTEGER,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_cves_is_ghost ON cves(is_ghost);
CREATE INDEX idx_cves_cve_status ON cves(cve_status);
CREATE INDEX idx_cves_grace_expires ON cves(grace_period_expires);
```

#### Table: discovery_sources (simplified)

```sql
CREATE TABLE discovery_sources (
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,  -- rss, api, scraper, vendor_page
    evidence_url TEXT,
    context TEXT,
    discovered_at TEXT NOT NULL,
    confidence REAL,

    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX idx_sources_cve_id ON discovery_sources(cve_id);
CREATE INDEX idx_sources_name ON discovery_sources(source_name);
```

#### Table: source_reliability (NEW)

```sql
CREATE TABLE source_reliability (
    source_name TEXT PRIMARY KEY,
    source_type TEXT,

    -- Performance metrics
    reliability_score REAL DEFAULT 0.75,
    total_discoveries INTEGER DEFAULT 0,
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,

    -- Timing stats
    avg_days_to_publish REAL,
    median_days_to_publish REAL,
    fastest_publish_days REAL,
    slowest_publish_days REAL,

    last_updated TEXT,
    last_recalculated TEXT
);
```

#### Table: cna_registry (NEW)

```sql
CREATE TABLE cna_registry (
    cna_name TEXT PRIMARY KEY,
    official_name TEXT,
    cna_type TEXT,

    -- Performance metrics
    avg_publication_lag_days REAL,
    median_publication_lag_days REAL,
    reliability_score REAL DEFAULT 0.80,

    -- ID allocation patterns
    id_ranges TEXT,  -- JSON

    -- Stats
    total_cves_tracked INTEGER DEFAULT 0,
    total_ghosts INTEGER DEFAULT 0,
    ghost_rate REAL,

    last_updated TEXT
);
```

#### Table: resolution_history (NEW)

```sql
CREATE TABLE resolution_history (
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,

    -- Timeline
    first_discovered TEXT NOT NULL,
    resolved_date TEXT NOT NULL,
    resolution_time_days REAL NOT NULL,

    -- Context
    cna_name TEXT,
    first_source_name TEXT,
    first_source_type TEXT,
    root_cause TEXT,

    -- Classification
    was_true_ghost BOOLEAN,
    ghost_confidence_at_peak REAL,

    contributed_to_learning BOOLEAN DEFAULT TRUE,
    created_at TEXT NOT NULL,

    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE INDEX idx_resolution_cna ON resolution_history(cna_name);
CREATE INDEX idx_resolution_time ON resolution_history(resolution_time_days);
```

#### Table: validation_cache (NEW)

```sql
CREATE TABLE validation_cache (
    cve_id TEXT PRIMARY KEY,
    cve_status TEXT NOT NULL,
    validation_source TEXT NOT NULL,
    cached_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    raw_data TEXT  -- JSON
);
```

### 5.2 Python Data Models

#### Enums

```python
class DisclosureStatus(Enum):
    PUBLIC = "PUBLIC"
    MENTIONED_ONLY = "MENTIONED_ONLY"
    UNCERTAIN = "UNCERTAIN"

class DisclosureType(Enum):
    ADVISORY = "ADVISORY"
    PATCH_NOTES = "PATCH_NOTES"
    EXPLOIT = "EXPLOIT"
    CONFERENCE = "CONFERENCE"
    OTHER = "OTHER"

class GhostRootCause(Enum):
    VENDOR_FAILURE = "VENDOR_FAILURE"
    CNA_DELAY = "CNA_DELAY"
    SYSTEM_LAG = "SYSTEM_LAG"
    FAKE_CVE = "FAKE_CVE"
    EMBARGO = "EMBARGO"
    UNKNOWN = "UNKNOWN"
```

#### Dataclasses

```python
@dataclass
class DisclosureClassification:
    status: DisclosureStatus
    disclosure_type: DisclosureType
    confidence: float
    reasoning: str

@dataclass
class GhostAnalysis:
    cve_id: str
    is_ghost: bool
    confidence: float
    disclosure_status: DisclosureStatus
    grace_period_remaining: timedelta | None
    source_confidence_avg: float
    reasoning: str

@dataclass
class CNAMetadata:
    cna_name: str
    avg_publication_lag_days: float
    reliability_score: float
    total_cves_tracked: int
    id_ranges: dict[int, tuple[int, int]]

@dataclass
class ProcessedCVE:
    discovery: DiscoveryResult
    disclosure: DisclosureClassification
    validation: ValidationResult
    ghost_analysis: GhostAnalysis
    root_cause: GhostRootCause | None
```

---

## 6. API Integrations

### 6.1 CVE.org API Client

**Base URL:** https://cveawg.mitre.org/api
**Authentication:** None required
**Rate Limit:** 30 requests/minute
**Documentation:** https://cveawg.mitre.org/api-docs

**Key Endpoints:**
- `GET /cve/{cveId}` - Get CVE details
- `GET /cve-id?state={state}&time_modified.gt={date}` - Recent changes

**Implementation:**
```python
class CVEOrgAPIClient:
    BASE_URL = "https://cveawg.mitre.org/api"

    def validate(self, cve_id: str) -> ValidationResult:
        # Primary validation source
        # Returns: status, description, dates, CNA info

    def get_recent_changes(self, since: datetime) -> list[dict]:
        # Monitor RESERVED→PUBLISHED transitions
```

### 6.2 GitHub Security Advisories (GraphQL)

**Endpoint:** https://api.github.com/graphql
**Authentication:** GitHub token (existing)
**Rate Limit:** 5000 requests/hour
**Documentation:** https://docs.github.com/en/graphql

**Query:**
```graphql
query GetRecentAdvisories {
  securityAdvisories(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}) {
    nodes {
      ghsaId
      cvss { score }
      severity
      summary
      description
      publishedAt
      updatedAt
      identifiers {
        type
        value
      }
      vulnerabilities(first: 10) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
        }
      }
    }
  }
}
```

### 6.3 ExploitDB

**RSS Feed:** https://www.exploit-db.com/rss.xml
**CSV Export:** https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
**Rate Limit:** None (RSS), respectful polling
**Update Frequency:** Check every 6 hours

**Implementation:** Use RSS feed, parse for CVE IDs

---

## 7. Confidence Scoring Algorithm

### 7.1 Ghost Confidence Calculation

```python
def calculate_ghost_confidence(
    disclosure: DisclosureClassification,
    validation: ValidationResult,
    sources: list[DiscoveryResult],
    age_hours: float
) -> float:
    """
    Calculate confidence (0.0-1.0) that this is a true ghost.

    Formula:
      base_confidence = disclosure.confidence (0.7-1.0)
      weighted_by_sources = base * avg_source_reliability
      boost_for_multiple = weighted * (1.1-1.2 if 2-3+ sources)
      boost_for_quality = boost * 1.15 if high-quality source
      boost_for_age = boost * (1.1-1.2 if 72hr-7d+)
      penalty_mailing_only = boost * 0.8 if only mailing lists
      final = min(result, 1.0)
    """

    # Base from disclosure clarity
    confidence = disclosure.confidence  # 0.7-1.0

    # Weight by source reliability
    source_reliabilities = [get_reliability(s.name) for s in sources]
    avg_reliability = sum(source_reliabilities) / len(source_reliabilities)
    confidence *= avg_reliability  # 0.6-0.98

    # Multiple sources boost
    if len(sources) >= 3:
        confidence *= 1.2  # +20%
    elif len(sources) >= 2:
        confidence *= 1.1  # +10%

    # High-quality source boost
    high_quality = ['ZDI', 'MSRC', 'PSIRT', 'CVE.org', 'ExploitDB', 'GitHub Security']
    if any(hq in s.source_name for s in sources for hq in high_quality):
        confidence *= 1.15  # +15%

    # Age boost (longer = more likely real ghost)
    if age_hours > 168:  # 7+ days
        confidence *= 1.2
    elif age_hours > 72:  # 3+ days
        confidence *= 1.1

    # Mailing list only penalty
    mailing_lists = ['OSS Security', 'Full Disclosure']
    if all(s.source_name in mailing_lists for s in sources):
        confidence *= 0.8  # -20%

    return min(confidence, 1.0)
```

### 7.2 Source Reliability Evolution

```python
def update_source_reliability(
    source_name: str,
    was_true_ghost: bool,
    resolution_days: float
):
    """
    Update source reliability based on outcome.

    True ghost → increase reliability
    False positive → decrease reliability
    Fast publication → bonus
    """

    outcomes = get_all_outcomes(source_name)
    total = len(outcomes)
    true_positives = sum(1 for o in outcomes if o.was_true_ghost)

    # Base reliability from accuracy
    accuracy = true_positives / total if total > 0 else 0.75

    # Speed bonus
    avg_days = sum(o.resolution_days for o in outcomes) / total
    if avg_days < 3.0:
        speed_bonus = 0.10
    elif avg_days < 7.0:
        speed_bonus = 0.05
    else:
        speed_bonus = 0.0

    reliability = min(accuracy + speed_bonus, 1.0)

    save_reliability(source_name, reliability)
```

### 7.3 Minimum Thresholds

**Ghost Classification Requires:**
- Confidence ≥ 0.60 (60%)
- At least 1 source (preferably 2+)
- Past 6-hour grace period
- PUBLIC disclosure status
- RESERVED or NOT_FOUND validation status

**High Confidence Ghost (report priority):**
- Confidence ≥ 0.85 (85%)
- 2+ sources
- At least 1 high-quality source

---

## 8. Testing Strategy

### 8.1 Unit Tests

**Coverage Target:** 90%+

**Key Test Categories:**
1. **Disclosure Classification**
   - Patch notes detection
   - Description detection
   - Mentioned-only detection
   - Edge cases

2. **Ghost Analysis**
   - Grace period enforcement
   - Confidence calculation
   - Multiple sources handling
   - Edge cases (0 sources, uncertain disclosure)

3. **Root Cause Detection**
   - Fake CVE detection
   - Embargo detection
   - CNA delay detection
   - Vendor failure detection

4. **Learning System**
   - Source reliability updates
   - CNA statistics updates
   - Recalculation triggers
   - Weight evolution

### 8.2 Integration Tests

**Full Pipeline Tests:**
1. Vendor advisory → Ghost detection
2. Patch notes → Ghost detection
3. Grace period prevents premature flagging
4. Multiple sources merge correctly
5. Learning system updates on resolution

### 8.3 Performance Tests

**Targets:**
- Process 100 CVEs in < 30 seconds
- Database queries < 10ms (with 10k CVEs)
- API calls < 2 seconds (p95)
- Memory usage < 500MB

### 8.4 Acceptance Tests

**Success Criteria:**
- False positive rate < 10% (vs 40-60% before)
- 95%+ confidence in high-confidence ghosts
- Root cause identified for 80%+ of ghosts
- Learning system improves accuracy over time
- All 23 discovery sources operational

---

## 9. Migration & Deployment

### 9.1 Migration Strategy

**Approach:** Fresh start with clean database

**Steps:**
1. Backup existing `ghost_log.db`
2. Rename to `ghost_log.backup.YYYYMMDD.db`
3. Create fresh `ghost_log.db` with v2 schema
4. Initialize source reliability defaults
5. Initialize CNA registry defaults
6. Run first hunt to populate with clean data

**Rationale:**
- Old data has 40-60% false positives
- Would contaminate learning system
- Fresh baseline for measuring improvements
- Historical data preserved in backup

### 9.2 Default Initialization

**Source Reliability Defaults:**
```python
HIGH_RELIABILITY = {
    "ZDI Advisories": 0.95,
    "Microsoft MSRC": 0.95,
    "CVE.org Recent Changes": 1.0,
    "ExploitDB": 0.92,
    "CISA KEV": 0.98,
    "GitHub Security Advisories": 0.90,
    # ... more ...
}

MEDIUM_RELIABILITY = {
    "OSS Security": 0.75,
    "Full Disclosure": 0.65,
    # ... more ...
}
```

**CNA Registry Defaults:**
```python
KNOWN_CNAS = {
    "mitre": {
        "avg_publication_lag_days": 3.0,
        "reliability_score": 0.95
    },
    "microsoft": {
        "avg_publication_lag_days": 7.0,
        "reliability_score": 0.90
    },
    # ... more ...
}
```

### 9.3 Deployment Checklist

**Pre-Deployment:**
- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Performance tests meet targets
- [ ] Code review completed
- [ ] Documentation updated

**Deployment:**
1. [ ] Backup current database
2. [ ] Run migration script
3. [ ] Verify new schema
4. [ ] Test discovery modules
5. [ ] Run first hunt
6. [ ] Verify results
7. [ ] Push to GitHub
8. [ ] Monitor first automated run

**Post-Deployment (First Week):**
- [ ] Monitor false positive rate
- [ ] Check grace period effectiveness
- [ ] Verify learning system updates
- [ ] Review root cause distribution
- [ ] Monitor API rate limits

### 9.4 Rollback Plan

**If Issues Occur:**
1. Stop GitHub Actions workflow
2. Restore from backup: `mv ghost_log.backup.db ghost_log.db`
3. Revert git commit
4. Push to GitHub
5. Re-enable workflow

**Backup Locations:**
- Local: `ghost_log.backup.YYYYMMDD.db`
- Git history: Previous commits
- GitHub Releases: Monthly snapshots

---

## 10. Success Metrics

### 10.1 Key Performance Indicators

**Accuracy Metrics:**
- False positive rate < 10% (baseline: 40-60%)
- High-confidence ghost accuracy > 95%
- Root cause identification rate > 80%

**Performance Metrics:**
- Processing time: < 30s per 100 CVEs
- Database query time: < 10ms (p95)
- API response time: < 2s (p95)

**Coverage Metrics:**
- Discovery sources operational: 23/23 (100%)
- CVE coverage: All public disclosures within 6 hours

**Learning Metrics:**
- Source reliability accuracy improvement over time
- CNA statistics accuracy improvement over time
- Confidence score calibration (predicted vs actual)

### 10.2 Monitoring Dashboard

**Real-Time Metrics:**
- Active ghosts count
- New ghosts in last 24h
- Ghosts by root cause (pie chart)
- Confidence distribution (histogram)
- Source contributions (bar chart)

**Learning System Metrics:**
- Source reliability scores over time (line chart)
- CNA average lag over time (line chart)
- Resolution patterns (heatmap)

**Quality Metrics:**
- False positive rate trend (line chart)
- High-confidence ghost accuracy (gauge)
- Root cause identification rate (gauge)

### 10.3 Alerting

**Critical Alerts:**
- False positive rate > 15%
- CVE.org API down for > 1 hour
- No new discoveries in 12 hours

**Warning Alerts:**
- Discovery source failing
- API rate limit approaching
- Database size > 100MB

---

## 11. Future Enhancements

### Phase 2 (Post-Launch)

**Additional Sources:**
- Vendor page scrapers for 10 more vendors
- Bug bounty platform integrations (HackerOne, Bugcrowd)
- Conference talk databases (BlackHat, DEF CON)
- VulnDB / Vulners.com integration

**Advanced Analytics:**
- Predictive lag estimation (ML model)
- Temporal pattern recognition (seasonal trends)
- Product family vulnerability clustering
- Duplicate CVE detection

**API Improvements:**
- RESTful API for external integrations
- Webhook notifications
- RSS feed for new ghosts
- GraphQL API for flexible queries

### Phase 3 (Long-Term)

**Machine Learning:**
- Deep learning for disclosure classification
- NLP for description extraction
- Anomaly detection for fake CVEs
- Time series forecasting for publication lag

**Community Features:**
- User-submitted sources
- Crowdsourced root cause verification
- Public voting on ghost classifications
- Contributor leaderboard

**Enterprise Features:**
- Multi-tenant support
- Custom discovery sources
- Private ghost tracking
- SLA monitoring

---

## 12. Conclusion

This design specification provides a comprehensive blueprint for transforming GhostCVEs from a basic discovery tool (40-60% false positive rate) into a world-class vulnerability intelligence platform (<10% false positive rate).

**Key Innovations:**
1. **6-Hour Grace Period** - Eliminates false positives from normal publication lag
2. **23 Discovery Sources** - Comprehensive coverage with API-first approach
3. **Multi-Source Validation** - CVE.org API as authoritative primary source
4. **Confidence Scoring** - Weighted by source reliability with continuous learning
5. **Root Cause Analysis** - Understand why CVEs are ghosts
6. **Automated Learning** - System improves from every resolution

**Implementation Timeline:**
- Week 1: Core pipeline + new discovery modules
- Week 2: Learning system + testing
- Week 3: Integration testing + deployment
- Week 4+: Monitoring + iteration

**Success Criteria:**
- False positive rate < 10%
- 95%+ confidence in classifications
- 80%+ root cause identification
- 100% GitHub-native (zero infrastructure costs)

This specification is approved for implementation.

---

**Document Version:** 2.0
**Last Updated:** 2026-03-10
**Status:** Ready for Implementation Plan
**Next Step:** Invoke superpowers:writing-plans skill
