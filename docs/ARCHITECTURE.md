# GhostCVEs Architecture

## System Overview

GhostCVEs is a CVE intelligence platform that identifies "ghost" CVEs—vulnerability identifiers that appear in public sources but remain RESERVED or NOT_FOUND in official registries. The system uses a 6-stage processing pipeline with multi-source validation, machine learning, and root cause analysis to achieve <10% false positive rate.

## Design Principles

1. **Multi-Source Validation**: Never trust a single source; validate across CVE.org API, local CVElist V5, and NVD JSON
2. **Confidence-Based Decision Making**: Every classification includes a confidence score; require 60%+ threshold for ghost detection
3. **Continuous Learning**: Track resolutions (RESERVED → PUBLISHED) to improve source reliability weights over time
4. **Grace Period Awareness**: Account for 6-hour technical sync delays to avoid false positives
5. **Root Cause Attribution**: Don't just detect ghosts—understand why they exist (vendor failure, embargo, fake CVE, etc.)
6. **Fail-Safe Fallbacks**: If primary validation fails, fall back to local sources; if all fail, mark as ERROR not ghost

## 6-Stage Processing Pipeline

### Stage 1: Discovery (23 Sources)

**Purpose**: Collect CVE mentions from diverse public sources

**Components**:
- `src/discovery/base.py`: Abstract base class defining discovery interface
- `src/discovery/rss_discovery.py`: RSS feed aggregator (15 feeds)
- `src/discovery/github_advisory_discovery.py`: GitHub Security Advisories API
- `src/discovery/exploitdb_discovery.py`: ExploitDB web scraper
- `src/discovery/cve_org_monitor.py`: CVE.org recent changes monitor
- `src/discovery/vendors/*.py`: Vendor-specific scrapers (Citrix, Ivanti, etc.)

**Output**: `DiscoveryResult` objects containing:
- `cve_id`: Normalized CVE identifier
- `source_name`: Source identifier
- `source_type`: rss_feed, api, vendor_scraper
- `confidence`: Source-specific confidence (0.0-1.0)
- `evidence_url`: URL to CVE mention
- `context`: Surrounding text/description
- `discovered_at`: Timestamp

**Key Features**:
- CVE ID pattern matching with normalization (CVE-YYYY-NNNNN)
- Rate limiting per source to respect API constraints
- Deduplication within same source
- Error handling with graceful degradation

### Stage 2: Disclosure Classification

**Purpose**: Determine if CVE is publicly disclosed and classify disclosure type

**Component**: `src/pipeline/disclosure_classifier.py`

**Algorithm**:
```python
def classify(discovery_result):
    context = discovery_result.context.lower()

    # Check if this is a patch/release note (strongest signal)
    is_patch_notes = any(indicator in context for indicator in PATCH_INDICATORS)

    # Check if vulnerability is described (not just mentioned)
    has_description = any(indicator in context for indicator in VULNERABILITY_INDICATORS)

    # Determine disclosure status
    if is_patch_notes or has_description:
        status = DisclosureStatus.PUBLIC
    elif cve_id_only:
        status = DisclosureStatus.MENTIONED_ONLY
    else:
        status = DisclosureStatus.UNCERTAIN

    # Classify disclosure type
    type = classify_disclosure_type(context)

    # Calculate confidence
    base_confidence = calculate_base_confidence(is_patch_notes, has_description)
    adjusted_confidence = base_confidence * discovery_result.confidence

    return DisclosureClassification(status, type, adjusted_confidence, reasoning)
```

**Disclosure Types**:
- `ADVISORY`: Security advisory with full details
- `PATCH_NOTES`: Mentioned in patch notes or release notes
- `EXPLOIT`: Public exploit or POC available
- `CONFERENCE`: Presented at security conference
- `OTHER`: Other public disclosure

**Confidence Adjustment**:
- Base confidence calculated from disclosure signals
- Adjusted by source confidence (unreliable sources get downweighted)
- Reasoning field documents decision logic

### Stage 3: Multi-Source Validation

**Purpose**: Determine official CVE status using authoritative sources

**Component**: `src/registry/multi_source_validator.py`

**Validation Chain**:
```
1. Check validation cache (1-hour TTL)
   ↓ miss
2. Try CVE.org API (primary, authoritative)
   ↓ fail
3. Try Local CVElist V5 (fallback 1)
   ↓ fail
4. Try Local NVD JSON (fallback 2)
   ↓ fail
5. Return ValidationResult(status=ERROR)
```

**CVE.org API Client** (`src/api/cve_org_client.py`):
- Rate limiting: 30 requests/minute
- Retry logic: 3 attempts with exponential backoff
- Response parsing: Extracts status, dates, CNA info
- Status mapping: PUBLISHED, RESERVED, REJECTED

**Local CVElist V5** (`src/registry/local_registry.py`):
- Git repo: `github.com/CVEProject/cvelistV5`
- File path: `cves/YYYY/NNNNxxx/CVE-YYYY-NNNNN.json`
- Status extraction from JSON schema v5.0

**Local NVD JSON** (`src/registry/nvd_local.py`):
- Download: `nvd.handsonhacking.org` (1.4GB, 327K+ CVEs)
- Format: JSON files by year
- Fallback for when CVElist doesn't have it

**Caching Strategy**:
- In-memory + database cache
- 1-hour TTL (balances freshness vs API load)
- Cache invalidation on resolution detection

### Stage 4: Ghost Analysis

**Purpose**: Determine if CVE meets ghost criteria

**Component**: `src/pipeline/ghost_analyzer.py`

**Ghost Detection Logic**:
```python
GRACE_PERIOD_HOURS = 6  # Technical sync delay allowance

def analyze(cve_id, disclosure, validation, sources, first_seen):
    # Calculate age
    age = datetime.utcnow() - first_seen
    in_grace_period = age.total_seconds() < (GRACE_PERIOD_HOURS * 3600)

    # Calculate average confidence
    avg_confidence = sum(s.confidence for s in sources) / len(sources)

    # Ghost criteria (ALL must be true)
    is_ghost = (
        disclosure.status == DisclosureStatus.PUBLIC and
        validation.status in (CVEStatus.RESERVED, CVEStatus.NOT_FOUND) and
        not in_grace_period and
        avg_confidence >= 0.60
    )

    return GhostAnalysis(
        is_ghost=is_ghost,
        confidence=avg_confidence,
        age_hours=age.total_seconds() / 3600,
        in_grace_period=in_grace_period,
        reasoning="..."
    )
```

**Key Decisions**:
- **6-hour grace period**: Accounts for technical sync delays between systems
- **60% confidence threshold**: Balances sensitivity vs false positives
- **PUBLIC disclosure required**: MENTIONED_ONLY is not enough
- **Multi-source averaging**: Reduces impact of single unreliable source

### Stage 5: Root Cause Detection

**Purpose**: Explain WHY a ghost CVE exists

**Component**: `src/pipeline/root_cause_detector.py`

**Detection Priority** (checked in order):
```python
def detect(cve_id, disclosure, validation, sources, cna_info):
    # 1. FAKE_CVE (highest priority - eliminates from consideration)
    if is_suspicious_id(cve_id) or all_unreliable_sources(sources):
        return RootCause.FAKE_CVE, high_confidence

    # 2. EMBARGO (coordinated disclosure)
    if has_embargo_keywords(disclosure.context):
        return RootCause.EMBARGO, medium_confidence

    # 3. VENDOR_FAILURE (vendor published but didn't notify CNA)
    if is_vendor_source(sources) and validation.status == RESERVED:
        return RootCause.VENDOR_FAILURE, high_confidence

    # 4. CNA_DELAY (CNA assigned but slow to publish)
    if cna_info and days_since_assignment > 7:
        return RootCause.CNA_DELAY, medium_confidence

    # 5. SYSTEM_LAG (within grace period)
    if in_grace_period:
        return RootCause.SYSTEM_LAG, low_confidence

    # 6. UNKNOWN (no clear cause)
    return RootCause.UNKNOWN, low_confidence
```

**Root Causes**:
- `FAKE_CVE`: Suspicious ID pattern or unreliable sources only
- `EMBARGO`: Coordinated disclosure in progress
- `VENDOR_FAILURE`: Vendor published but didn't register with CNA
- `CNA_DELAY`: CNA assigned but taking too long to publish
- `SYSTEM_LAG`: Within grace period (technical delay)
- `UNKNOWN`: No clear root cause identified

**Fake CVE Detection**:
- ID >100,000 for current year
- All same digits (CVE-2025-11111)
- Only from low-reliability sources (<0.40)
- ID format violations

### Stage 6: Continuous Learning

**Purpose**: Improve system accuracy by learning from resolutions

**Component**: `src/pipeline/learning_system.py`

**Resolution Tracking**:
```python
def check_for_resolutions():
    # Get all current ghosts
    ghosts = db.get_all_ghosts()

    for ghost in ghosts:
        # Validate current status
        current_status = multi_source_validator.validate(ghost.cve_id)

        # Check if resolved
        if ghost.registry_status == RESERVED and current_status == PUBLISHED:
            # Calculate metrics
            resolution_days = (datetime.utcnow() - ghost.first_seen).days
            was_true_ghost = resolution_days > 1.0  # >24 hours = true ghost

            # Record resolution
            for source in ghost.sources:
                db.record_resolution(
                    cve_id=ghost.cve_id,
                    source_name=source.name,
                    resolution_days=resolution_days,
                    was_true_ghost=was_true_ghost
                )

            # Update CVE status
            db.update_cve_status(ghost.cve_id, PUBLISHED)
```

**Reliability Calculation**:
```python
def recalculate_source_reliability(source_name):
    # Get resolution history
    resolutions = db.get_source_resolutions(source_name)

    # Calculate accuracy
    true_positives = sum(1 for r in resolutions if r.was_true_ghost)
    total = len(resolutions)
    accuracy = true_positives / total if total > 0 else 0.75  # Default

    # Calculate speed bonus
    avg_days = sum(r.resolution_days for r in resolutions) / total
    if avg_days < 3:
        speed_bonus = 0.10
    elif avg_days < 7:
        speed_bonus = 0.05
    else:
        speed_bonus = 0.0

    # Final reliability score
    reliability = min(accuracy + speed_bonus, 1.0)

    # Update database
    db.update_source_reliability(source_name, reliability)
```

**Learning Outcomes**:
- Source reliability weights updated
- Fast sources (<3 days) rewarded with +0.10 bonus
- Slow but accurate sources still valued
- New sources start at 0.75 (neutral)

## Pipeline Orchestration

**Component**: `src/pipeline/orchestrator.py`

**Main Workflow**:
```python
class PipelineOrchestrator:
    def run_full_pipeline(self, discovery_modules):
        stats = PipelineStats()

        # Stage 1: Discovery across all modules
        for module in discovery_modules:
            discoveries = module.discover()

            for discovery in discoveries:
                # Stage 2: Disclosure classification
                disclosure = self.disclosure_classifier.classify(discovery)

                # Stage 3: Multi-source validation
                validation = self.multi_source_validator.validate(
                    discovery.cve_id,
                    found_in_wild=True
                )

                # Get or create CVE record
                cve = self.db.get_or_create_cve(discovery.cve_id)

                # Stage 4: Ghost analysis
                ghost_analysis = self.ghost_analyzer.analyze(
                    cve_id=discovery.cve_id,
                    disclosure=disclosure,
                    validation=validation,
                    sources=[discovery],
                    first_seen=cve.first_seen
                )

                # Stage 5: Root cause detection (if ghost)
                if ghost_analysis.is_ghost:
                    root_cause = self.root_cause_detector.detect(
                        cve_id=discovery.cve_id,
                        disclosure=disclosure,
                        validation=validation,
                        sources=[discovery],
                        cna_info=validation.cna_info
                    )
                else:
                    root_cause = None

                # Store complete result
                self.db.store_processed_cve(
                    cve_id=discovery.cve_id,
                    disclosure=disclosure,
                    validation=validation,
                    ghost_analysis=ghost_analysis,
                    root_cause=root_cause,
                    sources=[discovery]
                )

                stats.update(ghost_analysis.is_ghost)

        # Stage 6: Resolution checking and learning
        self.check_for_resolutions()

        return stats
```

**Deduplication Strategy**:
- Same CVE from multiple sources: aggregate confidence scores
- Keep all sources as evidence (multi-source validation)
- Update existing record with latest validation status
- Preserve first_seen timestamp (earliest discovery)

## Data Model

### Core Entities

**CVE Record** (`src/models/dataclasses.py`):
```python
@dataclass
class ProcessedCVE:
    cve_id: str
    disclosure: DisclosureClassification
    validation: ValidationResult
    ghost_analysis: GhostAnalysis
    root_cause: Optional[RootCause]
    sources: List[DiscoveryResult]
    first_seen: datetime
    last_checked: datetime
```

**Disclosure Classification**:
```python
@dataclass
class DisclosureClassification:
    status: DisclosureStatus  # PUBLIC, MENTIONED_ONLY, UNCERTAIN
    type: DisclosureType      # ADVISORY, PATCH_NOTES, EXPLOIT, etc.
    confidence: float         # 0.0-1.0
    reasoning: str            # Human-readable explanation
```

**Validation Result**:
```python
@dataclass
class ValidationResult:
    cve_id: str
    status: CVEStatus         # PUBLISHED, RESERVED, REJECTED, NOT_FOUND
    last_modified: Optional[datetime]
    cna_info: Optional[CNAMetadata]
    raw_response: Optional[Dict]
```

**Ghost Analysis**:
```python
@dataclass
class GhostAnalysis:
    is_ghost: bool
    confidence: float
    age_hours: float
    in_grace_period: bool
    reasoning: str
```

### Database Schema

See [Database Schema V2](../README.md#-database-schema-v2) for complete table definitions.

**Key Relationships**:
- `cves` 1:N `discovery_sources` (one CVE, many sources)
- `cves` N:1 `cna_registry` (many CVEs, one CNA)
- `source_reliability` 1:N `resolution_history` (one source, many resolutions)

**Indexes**:
- Performance: `cves.cve_id`, `discovery_sources.cve_id`
- Queries: `cves.is_ghost`, `cves.last_checked`, `source_reliability.reliability_score DESC`

## Error Handling

### Validation Failures

**Strategy**: Fail gracefully with degraded service
```python
try:
    result = cve_org_client.validate(cve_id)
except APIError:
    result = local_cvelistv5.validate(cve_id)
    if result is None:
        result = local_nvd.validate(cve_id)
        if result is None:
            result = ValidationResult(status=CVEStatus.ERROR)
```

**ERROR status**:
- Not included in ghost count
- Logged for investigation
- Retried on next hunt

### Discovery Module Failures

**Strategy**: Continue with other modules
```python
for module in discovery_modules:
    try:
        discoveries = module.discover()
        process_discoveries(discoveries)
    except Exception as e:
        logger.error(f"Module {module.name} failed: {e}")
        continue  # Don't let one module kill the whole hunt
```

### Rate Limiting

**CVE.org API**:
- Limit: 30 requests/minute
- Strategy: Token bucket with sleep
- Fallback: Use cached data if available

**ExploitDB Scraping**:
- Limit: 5 requests/60 seconds
- Strategy: Rate limiter with queue
- Fallback: Skip if rate limit hit

## Performance Optimizations

### Caching Strategy

**Validation Cache** (1-hour TTL):
- Reduces CVE.org API calls by ~80%
- In-memory + database persistence
- Automatic invalidation on resolution

**Source Reliability Cache**:
- Recalculated only when resolutions recorded
- Cached in memory for hunt duration
- Persisted to database

### Parallel Processing

**Discovery Phase**:
- Each discovery module runs independently
- Async I/O for network requests
- Concurrent workers (default: 5)

**Validation Phase**:
- Sequential per CVE (API rate limits)
- Batch database writes
- Efficient SQL queries with prepared statements

### Database Optimization

**Indexes**:
- Primary keys: `cves.cve_id`, `source_reliability.source_name`
- Query optimization: `cves.is_ghost`, `cves.last_checked`
- Sort optimization: `source_reliability.reliability_score DESC`

**Batch Operations**:
- Bulk insert for discovery sources
- Transaction batching (commit every 100 records)
- Prepared statements for common queries

## Security Considerations

### API Keys

**Storage**: Environment variables only
```bash
export CVE_ORG_API_KEY="..."
export GITHUB_TOKEN="ghp_..."
```

**Never**: Logged, committed, or exposed in output

### Input Validation

**CVE ID Format**:
```python
CVE_PATTERN = re.compile(r'CVE-(\d{4})-(\d{4,})')

def is_valid_cve_id(cve_id: str) -> bool:
    match = CVE_PATTERN.match(cve_id)
    if not match:
        return False
    year = int(match.group(1))
    id_num = int(match.group(2))
    return 1999 <= year <= current_year + 1
```

**URL Validation**: All URLs sanitized before storage

### Rate Limiting

**Respect API Limits**:
- CVE.org: 30 req/min
- GitHub: 5000 req/hour (authenticated)
- ExploitDB: 5 req/60 seconds

**Consequences**: Rate limit violations can lead to IP bans

## Testing Strategy

### Unit Tests

**Coverage Target**: >80% for core components

**Key Test Suites**:
- `tests/pipeline/test_orchestrator.py`: Pipeline logic
- `tests/api/test_cve_org_client.py`: API interactions (mocked)
- `tests/registry/test_multi_source_validator.py`: Validation chain
- `tests/discovery/test_*.py`: Discovery modules (mocked)

### Integration Tests

**Test Suite**: `tests/integration/test_pipeline_e2e.py`

**Scenarios**:
1. Complete ghost detection flow (discovery → learning)
2. Published CVE flow (non-ghost path)
3. Grace period handling (within 6 hours)
4. Resolution detection (RESERVED → PUBLISHED)
5. Multi-source deduplication
6. Error recovery (validation failures)

**Approach**: In-memory database + mocked external APIs

### Manual Testing

**Checklist**:
1. Run full hunt: `python main.py --hunt`
2. Verify ghost detection: Review high-confidence ghosts
3. Check resolution tracking: `python main.py --check-resolutions`
4. Validate reports: `python main.py --report --format all`
5. Inspect dashboard: `python main.py --dashboard`

## Deployment

### GitHub Actions Workflow

**Schedule**: Every 6 hours (00:00, 06:00, 12:00, 18:00 UTC)

**Steps**:
1. Checkout repository
2. Setup Python 3.11+
3. Install dependencies
4. Run hunt: `python main.py --hunt --check-resolutions`
5. Generate reports: `python main.py --report --format all`
6. Commit updated database
7. Push to GitHub

**Artifacts**:
- `ghost_log.db`: Updated database
- `reports/ghost_report.md`: Latest ghost report
- `reports/ghost_report.json`: Machine-readable format

### Local Deployment

**Requirements**:
- Python 3.11+
- 4GB RAM minimum
- 5GB disk space (for local CVE data)
- Internet connection (for API calls)

**Installation**:
```bash
git clone https://github.com/rogolabs/GhostCVEs.git
cd GhostCVEs
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python scripts/migrate_to_v2.py  # First time only
python main.py --hunt
```

## Monitoring and Observability

### Logging

**Levels**:
- `DEBUG`: Discovery details, API calls
- `INFO`: Pipeline progress, statistics
- `WARNING`: Rate limits, validation failures
- `ERROR`: Module failures, database errors

**Output**:
- Console: INFO and above
- File: DEBUG and above (if `--log-file` specified)

### Metrics

**Tracked Metrics**:
- Total discoveries per source
- Ghosts found per hunt
- False positive rate (from resolutions)
- Average confidence per source
- API call counts and errors
- Processing time per stage

**Dashboard**: `python main.py --dashboard`

## Troubleshooting

### Common Issues

**Issue**: High false positive rate
- **Check**: Source reliability scores
- **Fix**: Let learning system run for a few resolution cycles
- **Verify**: Review `source_reliability` table

**Issue**: API rate limits hit
- **Check**: Validation cache hit rate
- **Fix**: Increase cache TTL or reduce hunt frequency
- **Verify**: Check logs for `429 Too Many Requests`

**Issue**: Missing local CVE data
- **Check**: `~/.cache/ghostcves/` directory
- **Fix**: Delete cache and re-run (will re-download)
- **Verify**: `ls -lh ~/.cache/ghostcves/`

**Issue**: Database corruption
- **Fix**: Restore from backup or re-migrate
- **Command**: `python scripts/migrate_to_v2.py`

## Future Architecture Improvements

### Planned Enhancements

1. **Distributed Processing**: Celery workers for parallel discovery
2. **Real-Time Monitoring**: WebSocket dashboard with live updates
3. **ML-Based Classification**: Train models on resolution history
4. **API Endpoint**: RESTful API for querying ghost database
5. **Notification System**: Webhook, email, Slack alerts for new ghosts
6. **STIX/TAXII Export**: Threat intelligence format support

### Scalability Considerations

**Current Limits**:
- Single-threaded validation (API rate limits)
- Local SQLite database
- Synchronous processing

**Future Scale**:
- PostgreSQL for multi-user access
- Redis for distributed caching
- Kubernetes for horizontal scaling
- GraphQL API for flexible queries

---

**Last Updated**: 2026-03-10
**Version**: 2.0
