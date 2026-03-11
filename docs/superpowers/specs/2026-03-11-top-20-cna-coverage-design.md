# Top 20 CNA Coverage Enhancement - Design Specification

**Date:** 2026-03-11
**Author:** Claude Opus 4.6 + gamblin
**Status:** Approved
**Target Timeline:** 4 weeks

## Executive Summary

Enhance Ghost Hunter's data collection to achieve comprehensive coverage of the top 20 CVE Numbering Authorities (CNAs) by volume, while optimizing existing sources for quality and reliability. This audit-first approach will streamline the current 23 sources down to 15-18 high-quality sources, then systematically add 8-10 new sources covering major gaps (especially the WordPress ecosystem).

**Key Goals:**
- Cover all top 20 CNAs by CVE volume
- Reduce false positive rate from ~10% to <8%
- Improve ghost detection rate by 20%+
- Maintain lightweight infrastructure (prefer feeds over complex scrapers)
- Implement source health monitoring

## Problem Statement

### Current State
- **23 discovery sources** across RSS feeds, APIs, and vendor scrapers
- **Major CNA gaps** identified from volume analysis:
  - Patchstack (~15k CVEs) - 2nd largest CNA, WordPress plugin security
  - VulDB (~12.5k CVEs) - Vulnerability database aggregator
  - GitHub_M (~11.5k CVEs) - Partial coverage, needs CNA filtering
  - Wordfence (~8.5k CVEs) - WordPress security platform
  - Microsoft MSRC (~6.5k CVEs) - Configured but not activated
  - WPScan (~4k CVEs) - WordPress vulnerability database
  - Adobe PSIRT (~3.5k CVEs) - Major vendor missing

- **WordPress ecosystem** (Patchstack + Wordfence + WPScan = ~27.5k CVEs) is a critical blind spot
- **Unknown source quality** - no systematic measurement of reliability, false positive rates, or redundancy
- **No health monitoring** - failing sources may go unnoticed for days

### Success Criteria
- ✅ All top 20 CNAs covered by at least one source
- ✅ 15-25 optimized high-quality sources
- ✅ False positive rate <8%
- ✅ Ghost detection rate improved 20%+
- ✅ Source health monitoring operational
- ✅ Hunt runtime remains <5 minutes
- ✅ Complete documentation of CNA coverage

## Architecture Overview

### Three-Phase Approach

```
┌─────────────────────────────────────────────────────────┐
│ Phase 1: Audit & Optimize (Week 1)                     │
│                                                         │
│  Input: 23 existing sources                            │
│  Process: Measure reliability, detect redundancy       │
│  Output: 15-18 streamlined high-quality sources        │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 2: Add Top 10 CNAs (Weeks 2-3)                   │
│                                                         │
│  Week 2: Simple feeds (Patchstack, Wordfence, WPScan,  │
│          Adobe, VulDB)                                  │
│  Week 3: Activations (MSRC, IBM X-Force, GitHub CNA,   │
│          F5, Juniper)                                   │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│ Phase 3: Complete Top 20 + Monitoring (Week 4)         │
│                                                         │
│  Research remaining 2-5 CNAs from top 20                │
│  Add lightweight sources where available                │
│  Implement source health monitoring                     │
└─────────────────────────────────────────────────────────┘
```

### Development Strategy

**Feature Branch:** `feature/top-20-cna-coverage`

**Optional Phase Branches:**
- `feature/phase-1-audit`
- `feature/phase-2-top10-cnas`
- `feature/phase-3-remaining-cnas`

**Merge Strategy:** Incremental merges (Option A)
- End of Week 1: Merge Phase 1 audit results
- End of Week 2: Merge Phase 2 Part A (simple feeds)
- End of Week 3: Merge Phase 2 Part B (activations)
- End of Week 4: Merge Phase 3 (monitoring + remaining CNAs)

**Benefits of incremental merges:**
- Smaller PRs, faster review cycles
- Earlier feedback on approach
- Easier to rollback if issues arise
- Progressive value delivery

## Phase 1: Source Audit & Optimization

### Goals
- Measure reliability of all 23 existing sources
- Identify redundant or low-value sources
- Remove 5-8 sources that don't meet quality thresholds
- Optimize confidence scores for remaining sources

### Implementation

#### 1.1 Audit Metrics System

**New File:** `src/analysis/source_audit.py`

```python
@dataclass
class SourceMetrics:
    source_name: str
    total_discoveries: int
    ghost_detection_rate: float      # % that became true ghosts
    false_positive_rate: float        # % already PUBLISHED
    avg_time_to_resolution: float     # Days to publication
    reliability_score: float          # Weighted composite
    last_successful_fetch: datetime
    fetch_failure_rate: float         # % of failed fetches
    avg_fetch_time: float             # Seconds per fetch
    unique_cves_found: int            # CVEs only this source found
```

**Metrics Calculation:**
- Query `discovery_sources` and `resolution_history` tables
- Calculate metrics for each of 23 existing sources
- Weight factors:
  - Ghost detection rate: 40%
  - False positive rate (inverse): 30%
  - Fetch reliability: 20%
  - Unique discoveries: 10%

#### 1.2 Redundancy Detection

**Algorithm:**
```python
def detect_redundant_sources(sources: list[SourceMetrics]) -> list[tuple[str, str]]:
    """
    Find sources with >80% CVE overlap.
    Returns list of (primary_source, redundant_source) pairs.
    """
    # Group sources by CNA/vendor
    # Calculate Jaccard similarity for CVE sets
    # Flag pairs with similarity >0.8
```

**Example redundancies to check:**
- Multiple Red Hat feeds (RSS vs API)
- Overlapping distro advisories (Debian, Ubuntu, etc.)
- Vendor scrapers vs their RSS feeds

#### 1.3 Source Classification

**Decision Matrix:**

| Reliability Score | Action | Criteria |
|-------------------|--------|----------|
| >0.80 | **Keep** | High quality, unique discoveries |
| 0.60-0.80 | **Optimize** | Fixable issues, adjust confidence |
| <0.60 | **Remove** | Low quality, redundant, or unreliable |

**Additional removal criteria:**
- Scraper with >20% fetch failure rate
- Source with zero unique discoveries in 6 months
- Redundant source when better alternative exists

#### 1.4 Deliverables

**Reports:**
- `reports/source_audit_report.md` - Detailed analysis with recommendations
- `reports/sources_to_remove.json` - List with justifications
- `reports/confidence_score_updates.json` - New scores for remaining sources

**Code Changes:**
- Update `src/config.py` - Remove low-value sources
- Update confidence scores for remaining sources
- Document rationale in comments

**Testing:**
- Verify no ghost CVEs lost after source removal
- Confirm hunt runtime maintained or improved
- Validate remaining sources have improved aggregate reliability

### Timeline: Week 1

- **Days 1-2:** Build audit tooling
- **Days 3-4:** Run analysis, generate reports
- **Day 5:** Remove sources, update configs, test

## Phase 2: Add Top 10 Missing CNAs

### Goals
- Add 8-10 new sources covering major CNA gaps
- Focus on WordPress ecosystem (critical blind spot)
- Activate existing configured but inactive sources
- Prefer simple feeds/APIs over complex scrapers

### Implementation

#### 2.1 Tier 1 - Simple RSS Feeds (Week 2, Days 1-2)

**1. Patchstack** (~15k CVEs) - HIGHEST PRIORITY
- **Source:** `https://patchstack.com/database/feed/rss`
- **Type:** RSS feed
- **Confidence:** 0.88 (vendor advisory)
- **Implementation:** Add to `RSS_FEEDS` in `src/config.py`
- **Complexity:** Low - uses existing RSS infrastructure

**2. Adobe PSIRT** (~3.5k CVEs)
- **Source:** `https://helpx.adobe.com/security/rss.xml`
- **Type:** RSS feed
- **Confidence:** 0.91 (major vendor advisory)
- **Implementation:** Add to `RSS_FEEDS` in `src/config.py`
- **Complexity:** Low - existing RSS infrastructure

#### 2.2 Tier 2 - Simple APIs (Week 2, Days 3-4)

**3. Wordfence** (~8.5k CVEs)
- **Source:** `https://www.wordfence.com/api/intelligence/v2/vulnerabilities`
- **Type:** JSON API (free tier)
- **Confidence:** 0.87 (security vendor)
- **Implementation:** New `src/discovery/wordfence_discovery.py`
- **Complexity:** Low - structured JSON response

```python
class WordfenceDiscovery(BaseDiscovery):
    """Discovers CVEs from Wordfence threat intelligence API."""

    def discover(self) -> list[DiscoveryResult]:
        response = requests.get(
            "https://www.wordfence.com/api/intelligence/v2/vulnerabilities",
            params={"per_page": 100}
        )
        # Parse JSON, extract CVE IDs
```

**4. WPScan** (~4k CVEs)
- **Source:** `https://wpscan.com/api/v3/wordpresses`
- **Type:** REST API (free tier, no auth needed for CVE IDs)
- **Confidence:** 0.90 (vulnerability database)
- **Implementation:** New `src/discovery/wpscan_discovery.py`
- **Complexity:** Low - REST API with pagination

**5. VulDB** (~12.5k CVEs)
- **Source:** `https://vuldb.com/?api`
- **Type:** REST API with RSS option
- **Confidence:** 0.82 (aggregator - may have duplicates)
- **Implementation:** New `src/discovery/vuldb_discovery.py`
- **Complexity:** Low-Medium - free tier, rate limited
- **Note:** Use RSS feed option to avoid API key requirement

#### 2.3 Tier 3 - Activations (Week 3, Days 1-2)

**6. Microsoft MSRC** (~6.5k CVEs) - ALREADY CONFIGURED!
- **Source:** Already in `VENDOR_ENDPOINTS` (config.py line 688-691)
- **Type:** CVRF API
- **Confidence:** 0.92 (major vendor)
- **Implementation:** Activate existing `VendorDiscovery` for MSRC endpoint
- **Complexity:** Very Low - just enable existing config

**7. IBM X-Force** (~3k CVEs)
- **Source:** `https://exchange.xforce.ibmcloud.com/api`
- **Type:** JSON API (free tier)
- **Confidence:** 0.89 (vendor advisory)
- **Implementation:** New `src/discovery/ibm_xforce_discovery.py`
- **Complexity:** Medium - requires free API key, good documentation

#### 2.4 Special Cases (Week 3, Days 3-4)

**8. GitHub_M CNA** (~11.5k CVEs)
- **Current:** Using `GitHubAdvisoryDiscovery` but not filtering by CNA
- **Enhancement:** Add CNA filtering to existing class
- **Implementation:** Modify `src/discovery/github_advisory_discovery.py`
- **Complexity:** Very Low - API already queried, just filter results

```python
# In GitHubAdvisoryDiscovery.discover()
for advisory in advisories:
    if advisory.get('cwe_ids'):  # Has CVE assignment
        # Check if assigned by GitHub's CNA
        if 'GitHub_M' in advisory.get('credits', []):
            # Process as high-priority GitHub CNA CVE
```

**9. F5 Networks** (~3k CVEs) - ALREADY CONFIGURED
- **Source:** Already in `VENDOR_ENDPOINTS` (config.py line 765-769)
- **Action:** Activate existing vendor scraper
- **Complexity:** Low

**10. Juniper Networks** (~2.5k CVEs) - ALREADY CONFIGURED
- **Source:** Already in `VENDOR_ENDPOINTS` (config.py line 783-787)
- **Action:** Activate existing vendor scraper
- **Complexity:** Low

### Deliverables

**New Files:**
- `src/discovery/wordfence_discovery.py`
- `src/discovery/wpscan_discovery.py`
- `src/discovery/vuldb_discovery.py`
- `src/discovery/ibm_xforce_discovery.py`

**Modified Files:**
- `src/config.py` - Add new RSS feeds, update VENDOR_ENDPOINTS
- `src/discovery/__init__.py` - Export new discovery classes
- `src/discovery/github_advisory_discovery.py` - Add CNA filtering
- `src/discovery/vendor_discovery.py` - Activate MSRC, F5, Juniper

**Testing:**
- Unit tests for each new discovery class
- Integration test with full pipeline
- Verify WordPress CVEs now detected (Patchstack, Wordfence, WPScan)
- Check for duplicate CVE handling

### Timeline: Weeks 2-3

**Week 2:**
- Days 1-2: Add Patchstack, Adobe RSS feeds
- Days 3-4: Implement Wordfence, WPScan, VulDB APIs
- Day 5: Testing and validation

**Week 3:**
- Days 1-2: Activate MSRC, implement IBM X-Force
- Days 3-4: GitHub CNA filtering, activate F5/Juniper
- Day 5: Integration testing

## Phase 3: Complete Top 20 + Monitoring

### Goals
- Research and identify remaining 2-5 CNAs in top 20
- Add lightweight sources where available
- Implement source health monitoring system
- Complete documentation

### Implementation

#### 3.1 CNA Gap Analysis (Days 1-2)

**Research Process:**
1. Query CVE.org API or public data for 2025-2026 CNA volume rankings
2. Cross-reference with existing sources from Phases 1-2
3. Identify missing CNAs from positions 11-20

**Likely Candidates** (need verification):
- Intel Security - Already in RSS_FEEDS (line 384), may need optimization
- Qualcomm - Already in RSS_FEEDS (line 401), may need optimization
- SAP - Already in RSS_FEEDS (line 343), may need optimization
- CERT/CC - Coordination center, research feed availability
- AWS - Already in RSS_FEEDS (line 317), may need optimization
- Atlassian - Already in RSS_FEEDS (line 349), may need optimization

**Strategy:**
- First, activate/optimize existing configured sources
- Second, research actual top 20 list to identify true gaps
- Third, add only lightweight feeds/APIs for remaining CNAs
- Skip CNAs requiring complex authentication or heavy scraping

#### 3.2 Source Health Monitoring

**New File:** `src/monitoring/source_health.py`

```python
@dataclass
class SourceHealth:
    source_name: str
    status: str  # "healthy", "degraded", "failing"
    consecutive_failures: int
    last_success: datetime
    error_rate_24h: float
    avg_response_time: float
    last_error: str

class SourceHealthMonitor:
    """Tracks and reports source reliability in real-time."""

    def check_source_health(self, source_name: str) -> SourceHealth:
        """Get current health status of a source."""

    def record_success(self, source_name: str, response_time: float):
        """Record successful fetch."""

    def record_failure(self, source_name: str, error: Exception):
        """Record failed fetch, update health status."""

    def get_failing_sources(self) -> list[SourceHealth]:
        """Get sources in failing state."""
```

**Health Status Levels:**

| Status | Criteria | Action |
|--------|----------|--------|
| **Healthy** | Success rate >95%, last success <1h | Normal operation |
| **Degraded** | Success rate 80-95% OR last success 1-6h | Log warning, continue |
| **Failing** | Success rate <80% OR last success >6h | Disable temporarily, alert |

#### 3.3 Error Handling Strategy

**Level 1 - Transient Errors (Network, Timeout):**
```python
@retry(max_attempts=3, backoff=exponential)
def fetch_source(url: str) -> Response:
    """Fetch with automatic retry for transient errors."""
```
- Retry 3 times with exponential backoff (1s, 2s, 4s)
- Mark source as "degraded" after 3 consecutive failures
- Continue with other sources
- Auto-recovery when source succeeds

**Level 2 - Source Changes (404, Structure Change):**
```python
def detect_source_change(source: str, error: Exception) -> bool:
    """Detect if error indicates source structure changed."""
    if isinstance(error, HTTPError) and error.code == 404:
        return True
    if isinstance(error, ParseError):
        return True
    return False
```
- Detect via error patterns (404, parsing failures)
- Mark source as "failing" after 5 consecutive structure errors
- Create GitHub issue automatically with error details
- Disable source temporarily until manual review

**Level 3 - Rate Limiting:**
```python
class RateLimiter:
    """Per-source rate limiting."""

    def __init__(self, requests_per_minute: int):
        self.rpm = requests_per_minute
        self.tokens = requests_per_minute

    def acquire(self):
        """Wait if rate limit reached."""
```
- Implement per-source rate limiting config
- Exponential backoff when rate limited
- Cache results (1 hour TTL) to reduce requests
- Log rate limit hits for capacity planning

#### 3.4 Monitoring Dashboard

**Enhancement to existing `--dashboard` command:**

```
╭──────────────────── Source Health ─────────────────────╮
│ Source              │ Status    │ Last Success       │
├─────────────────────┼───────────┼────────────────────┤
│ Patchstack RSS      │ ✓ Healthy │ 5 minutes ago      │
│ WPScan API          │ ⚠ Degraded│ 2 hours ago        │
│ VulDB API           │ ✗ Failing │ 3 days ago         │
│ MSRC Vendor         │ ✓ Healthy │ 12 minutes ago     │
╰─────────────────────────────────────────────────────────╯

╭──────────────────── CNA Coverage ──────────────────────╮
│ Top 20 CNAs: 20/20 covered                            │
│ Active Sources: 22/25                                  │
│ Failing Sources: 1 (VulDB API - issue #123 created)   │
╰─────────────────────────────────────────────────────────╯
```

#### 3.5 GitHub Actions Alerting

**Enhancement to `.github/workflows/hunt.yml`:**

```yaml
- name: Check Source Health
  run: |
    python main.py --check-sources
    FAILING=$(python -c "
    from src.monitoring.source_health import SourceHealthMonitor
    monitor = SourceHealthMonitor()
    failing = monitor.get_failing_sources()
    print(len(failing))
    ")

    if [ "$FAILING" -gt "7" ]; then
      echo "::error::$FAILING sources are failing (>30%)"
      exit 1
    elif [ "$FAILING" -gt "2" ]; then
      echo "::warning::$FAILING sources degraded (>10%)"
    fi
```

**Auto-issue creation:**
- Create GitHub issue for sources failing >7 days
- Include error logs, last successful fetch
- Label: `source-health`, `automated`

### Deliverables

**New Files:**
- `src/monitoring/source_health.py`
- `src/monitoring/__init__.py`
- `docs/cna-coverage-matrix.md` - Complete top 20 CNA mapping

**Modified Files:**
- `src/ui/dashboard.py` - Add source health section
- `.github/workflows/hunt.yml` - Add health checks
- `src/config.py` - Add remaining CNA sources

**Documentation:**
- Complete CNA coverage matrix
- Source maintenance guide
- Troubleshooting guide for failing sources

### Timeline: Week 4

- **Days 1-2:** Research remaining CNAs, identify feeds
- **Days 3:** Implement 2-5 remaining sources
- **Days 4:** Build source health monitoring
- **Day 5:** Documentation and final testing

## Testing Strategy

### Unit Tests

**New test files:**
```
tests/test_source_audit.py
- test_calculate_source_metrics()
- test_identify_redundant_sources()
- test_reliability_score_calculation()
- test_source_classification()

tests/test_new_sources.py
- test_patchstack_discovery()
- test_wordfence_discovery()
- test_wpscan_discovery()
- test_vuldb_discovery()
- test_ibm_xforce_discovery()
- test_github_cna_filtering()

tests/test_source_health.py
- test_health_status_calculation()
- test_failure_detection()
- test_retry_logic()
- test_rate_limit_handling()
- test_auto_recovery()
```

### Integration Tests

```python
# tests/integration/test_full_pipeline.py

def test_audit_existing_sources():
    """Phase 1: Audit produces valid metrics for all sources."""

def test_discover_with_new_sources():
    """Phase 2: New sources discover CVEs without duplicates."""

def test_source_health_monitoring():
    """Phase 3: Health monitoring tracks failures correctly."""

def test_graceful_source_failure():
    """Pipeline continues when sources fail."""
```

### Regression Testing

**Before each phase merge:**

1. **Baseline Test:**
   - Run hunt on main branch
   - Save: ghost count, false positive rate, hunt duration

2. **Feature Test:**
   - Run hunt on feature branch with same parameters

3. **Comparison Checks:**
   - Ghost count: should increase or stay same (not decrease)
   - False positive rate: should decrease or stay same
   - No existing ghosts should disappear from database
   - Hunt duration: should be within 20% of baseline

4. **Historical Data Test:**
   - Re-run last 30 days of discoveries with new pipeline
   - Verify improvements in detection without false positive increase

### Manual QA Checklist

**Phase 1 (Post-Audit):**
- [ ] All removed sources documented with justification
- [ ] No ghost CVEs lost after source removal
- [ ] Remaining sources show improved aggregate reliability
- [ ] Hunt runtime maintained or improved
- [ ] Audit report generated and reviewed

**Phase 2 (Top 10 CNAs):**
- [ ] Each new source discovered at least 1 CVE in test run
- [ ] WordPress ecosystem CVEs now detected (Patchstack, Wordfence, WPScan)
- [ ] No duplicate CVEs from new sources
- [ ] Confidence scores assigned correctly
- [ ] All new sources documented

**Phase 3 (Top 20 Complete):**
- [ ] All top 20 CNAs mapped to at least one source
- [ ] Coverage matrix documentation complete
- [ ] Source health monitoring shows status for all sources
- [ ] No sources in "failing" state at merge time
- [ ] Dashboard displays health information correctly

### Performance Testing

**Acceptance Criteria:**
- Hunt completes in <5 minutes with all sources enabled
- Memory usage stays <500MB during hunt
- No individual source takes >60 seconds to fetch
- Database size increase reasonable (<20% growth from new sources)
- No memory leaks over 10 consecutive hunt runs

## Success Metrics

### Quantitative Metrics

**Coverage:**
- ✅ All top 20 CNAs covered by ≥1 source
- ✅ WordPress ecosystem: 3 sources (Patchstack, Wordfence, WPScan)
- ✅ Total sources: 15-25 (optimized from 23)

**Quality:**
- ✅ False positive rate: <8% (down from ~10%)
- ✅ Ghost detection rate improvement: +20% minimum
- ✅ Average source reliability score: >0.85
- ✅ Source fetch failure rate: <5% aggregate

**Performance:**
- ✅ Hunt runtime: <5 minutes
- ✅ Memory usage: <500MB
- ✅ Database growth: <20% from new sources

### Qualitative Metrics

**Maintainability:**
- ✅ Source health monitoring operational
- ✅ Automated alerting for failing sources
- ✅ Clear documentation of all CNA mappings
- ✅ Simplified source configuration

**User Experience:**
- ✅ Dashboard shows source health status
- ✅ Clear errors when sources fail
- ✅ No silent failures or data loss

## Risk Assessment

### High Risk

**Risk:** New sources generate high false positive rates
**Mitigation:** Incremental rollout, per-source confidence tuning, easy rollback via git

**Risk:** Source structure changes break scrapers
**Mitigation:** Health monitoring detects failures quickly, automatic issue creation, prefer feeds over scrapers

### Medium Risk

**Risk:** API rate limits cause hunt failures
**Mitigation:** Per-source rate limiting, result caching, free tier research before implementation

**Risk:** Audit removes valuable sources
**Mitigation:** Conservative thresholds, manual review of recommendations, test before removal

### Low Risk

**Risk:** Performance degradation from more sources
**Mitigation:** Parallel fetching, timeouts, performance tests before merge

## Dependencies

### External Dependencies

**No new Python dependencies required!**

All new sources use existing libraries:
- `requests` - HTTP requests
- `feedparser` - RSS parsing
- `beautifulsoup4` - HTML parsing (light scraping)

### Internal Dependencies

**Existing modules:**
- `src/discovery/base.py` - Base discovery class
- `src/storage/database.py` - Database access
- `src/pipeline/orchestrator.py` - Pipeline coordination

**New modules depend on:**
- Audit tools depend on existing database schema
- Health monitoring depends on discovery base classes
- All new sources extend `BaseDiscovery`

## Open Questions

1. **CNA Volume Data Source:** Where to get authoritative top 20 CNA list?
   - Option A: Query CVE.org API aggregated data
   - Option B: Use community-maintained CNA statistics
   - Option C: Build from our own database over time
   - **Recommendation:** Start with user-provided chart, validate with CVE.org API in Phase 3

2. **Patchstack API Key:** Does it require authentication?
   - Need to verify if RSS feed is sufficient or if API key needed
   - **Action:** Research during Week 2 Day 1

3. **VulDB Free Tier Limits:** What are the rate limits?
   - Documentation mentions free tier but limits unclear
   - **Action:** Test during implementation, may need to use RSS fallback

## Future Enhancements

**Beyond this design (not in scope):**

1. **CNA-Aware Confidence Scoring:**
   - Weight sources by CNA reliability (e.g., MSRC = high confidence)
   - Automatic confidence adjustment based on CNA track record

2. **Source Auto-Discovery:**
   - Periodically check for new CNA sources
   - Suggest new feeds based on CNA activity

3. **Advanced Health Monitoring:**
   - Anomaly detection for unusual source behavior
   - Predictive alerts before sources fail
   - Historical trend analysis

4. **Source Marketplace:**
   - Community-contributed source definitions
   - Voting system for source quality
   - Easy import/export of source configs

## References

- [CVE.org CNA Registry](https://www.cve.org/PartnerInformation/ListofPartners)
- [MITRE CNA Documentation](https://cve.mitre.org/cve/cna.html)
- Current codebase: `src/discovery/`, `src/config.py`
- User-provided CNA volume chart (2026-03-11)

## Approval

**Design Approved By:** gamblin
**Date:** 2026-03-11
**Next Step:** Create implementation plan via `writing-plans` skill
