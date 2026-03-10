# Migration Guide: V1 to V2

## Overview

GhostCVEs V2 represents a complete architectural overhaul with a fresh database schema, 6-stage processing pipeline, and machine learning capabilities. This guide covers migration from the original system to V2.

**Key Decision**: V2 uses a **fresh database schema with NO backward compatibility**. This is intentional—the old data has quality issues (40-60% false positives) and the new system requires different data structures.

## Why a Fresh Start?

### Problems with V1 Data

1. **High False Positive Rate** (40-60%)
   - No grace period for technical sync delays
   - No confidence scoring
   - No source reliability tracking
   - Many "ghosts" were just normal publication lag

2. **Missing Context**
   - No disclosure classification
   - No root cause attribution
   - No CNA information
   - No multi-source validation

3. **Inconsistent Validation**
   - Only used local NVD data (often stale)
   - No CVE.org API integration
   - No validation caching
   - No fallback chain

4. **No Learning System**
   - Fixed confidence scores
   - No resolution tracking
   - No historical analysis
   - No pattern recognition

### Benefits of Fresh Schema

1. **Clean Baseline**: Start with world-class detection from day one
2. **New Data Model**: Supports 6-stage pipeline and learning system
3. **Better Performance**: Optimized indexes and queries
4. **No Legacy Baggage**: No need to support old structures

## Migration Strategy

### Option 1: Clean Migration (Recommended)

**Best for**: Most users, production deployments

**Steps**:
1. Back up existing database
2. Create fresh V2 database
3. Initialize with default sources and CNAs
4. Start hunting with new system
5. Let learning system build reliability scores

**Advantages**:
- No data quality issues
- Immediate access to new features
- Clean audit trail from V2 start

**Disadvantages**:
- Lose historical ghost records
- No pre-trained reliability scores

### Option 2: Historical Analysis Only

**Best for**: Research, trend analysis

**Steps**:
1. Keep old database as read-only archive
2. Create separate V2 database
3. Optionally analyze old data for insights
4. Do NOT import old data into V2

**Use Cases**:
- Compare V1 vs V2 false positive rates
- Study historical ghost patterns
- Validate V2 improvements

## Step-by-Step Migration

### Prerequisites

**Python Environment**:
```bash
python --version  # Must be 3.11+
```

**Disk Space**:
- 5GB for local CVE data
- 100MB for database
- 50MB for reports

**Dependencies**:
```bash
pip install -r requirements.txt
```

### Step 1: Backup Existing Database

```bash
# Backup current database
cp ghost_log.db ghost_log_v1_backup_$(date +%Y%m%d_%H%M%S).db

# Verify backup
ls -lh ghost_log_v1_backup_*.db
```

**Important**: Keep this backup! You may want to analyze old data later.

### Step 2: Run Migration Script

```bash
# Run automated migration
python scripts/migrate_to_v2.py

# Expected output:
# ========================================
# GhostCVEs Database Migration to V2
# ========================================
#
# Backing up existing database...
# ✓ Backup created: ghost_log_backup_20260310_120000.db
#
# Creating fresh V2 schema...
# ✓ Schema created with 6 tables
#
# Initializing default data...
# ✓ Initialized 21 discovery sources
# ✓ Initialized 6 CNAs
#
# Migration complete!
#
# Next steps:
# 1. Review configuration in src/config.py
# 2. Set environment variables (GITHUB_TOKEN, CVE_ORG_API_KEY)
# 3. Run first hunt: python main.py --hunt
```

### Step 3: Verify Migration

```bash
# Check database structure
sqlite3 ghost_log.db ".schema"

# Should show 6 tables:
# - cves
# - discovery_sources
# - source_reliability
# - cna_registry
# - resolution_history
# - validation_cache

# Check default data
sqlite3 ghost_log.db "SELECT COUNT(*) FROM source_reliability;"
# Should return: 21

sqlite3 ghost_log.db "SELECT COUNT(*) FROM cna_registry;"
# Should return: 6
```

### Step 4: Configure Environment

```bash
# Set optional API keys
export GITHUB_TOKEN="ghp_your_token_here"
export CVE_ORG_API_KEY="your_cve_org_api_key"

# Verify configuration
python -c "import os; print('GitHub:', 'SET' if os.getenv('GITHUB_TOKEN') else 'NOT SET'); print('CVE.org:', 'SET' if os.getenv('CVE_ORG_API_KEY') else 'NOT SET')"
```

### Step 5: Run First Hunt

```bash
# Execute first V2 hunt
python main.py --hunt

# Monitor output
# Should see:
# - 23 discovery sources initialized
# - CVE discoveries from multiple sources
# - Disclosure classification
# - Multi-source validation
# - Ghost analysis with confidence scores
# - Root cause detection
```

### Step 6: Verify Results

```bash
# Check database
sqlite3 ghost_log.db "SELECT COUNT(*) FROM cves;"
sqlite3 ghost_log.db "SELECT COUNT(*) FROM cves WHERE is_ghost = 1;"
sqlite3 ghost_log.db "SELECT cve_id, confidence_score, root_cause FROM cves WHERE is_ghost = 1 ORDER BY confidence_score DESC LIMIT 10;"

# Generate reports
python main.py --report --format all

# View dashboard
python main.py --dashboard
```

## Post-Migration Tasks

### 1. Review Configuration

**File**: `src/config.py`

**Check These Settings**:
```python
# Discovery configuration
class DiscoveryConfig:
    MAX_WORKERS = 5  # Adjust based on system resources
    REQUEST_TIMEOUT = 10  # Seconds

# Validation configuration
class ValidationConfig:
    CACHE_TTL_HOURS = 1  # Adjust based on hunt frequency
    GRACE_PERIOD_HOURS = 6  # Don't change without good reason

# Confidence thresholds
class ConfidenceConfig:
    GHOST_THRESHOLD = 0.60  # Minimum confidence for ghost detection
    FAKE_CVE_THRESHOLD = 0.40  # Maximum reliability for fake sources
```

### 2. Let Learning System Train

**Time Required**: 1-2 weeks

**What Happens**:
- Sources get initial reliability scores (default 0.75)
- Resolutions are detected and recorded
- Reliability scores adjust based on accuracy
- Fast sources (<3 days) get bonus points

**Monitor Progress**:
```bash
# Check resolution history
sqlite3 ghost_log.db "SELECT COUNT(*) FROM resolution_history;"

# View source reliability
sqlite3 ghost_log.db "SELECT source_name, reliability_score, total_discoveries, true_positives, false_positives FROM source_reliability ORDER BY reliability_score DESC;"

# Check false positive rate
sqlite3 ghost_log.db "SELECT CAST(SUM(CASE WHEN was_true_ghost = 0 THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100 AS false_positive_rate FROM resolution_history;"
```

### 3. Setup Automated Hunting

**GitHub Actions** (if using GitHub repo):
- Already configured in `.github/workflows/hunt.yml`
- Runs every 6 hours automatically
- Commits updated database and reports

**Cron Job** (for local deployment):
```bash
# Add to crontab
crontab -e

# Run every 6 hours
0 */6 * * * cd /path/to/GhostCVEs && /path/to/venv/bin/python main.py --hunt --check-resolutions >> /var/log/ghostcves.log 2>&1
```

### 4. Monitor Performance

**Key Metrics**:
- Ghost detection rate (should be 5-15 per hunt initially)
- False positive rate (target: <10%)
- Average confidence (target: >0.70)
- Resolution time (lower is better)

**Dashboard Command**:
```bash
python main.py --dashboard
```

## Comparing V1 vs V2 Results

### Analyzing Old Data

If you want to compare V1 ghosts with V2 validation:

```python
# analyze_v1_ghosts.py
import sqlite3

# Connect to old database
old_db = sqlite3.connect("ghost_log_v1_backup_XXXXXXXX.db")
old_cursor = old_db.cursor()

# Connect to new database
new_db = sqlite3.connect("ghost_log.db")
new_cursor = new_db.cursor()

# Get V1 ghosts
old_ghosts = old_cursor.execute(
    "SELECT cve_id FROM ghost_cves WHERE is_ghost = 1"
).fetchall()

print(f"V1 had {len(old_ghosts)} ghosts")

# Check how many are still ghosts in V2
still_ghosts = 0
resolved = 0
not_found = 0

for (cve_id,) in old_ghosts:
    result = new_cursor.execute(
        "SELECT is_ghost, registry_status FROM cves WHERE cve_id = ?",
        (cve_id,)
    ).fetchone()

    if result:
        if result[0]:  # is_ghost
            still_ghosts += 1
        else:
            resolved += 1
    else:
        not_found += 1

print(f"Still ghosts in V2: {still_ghosts}")
print(f"Resolved (published): {resolved}")
print(f"Not in V2 yet: {not_found}")
print(f"False positive rate: {resolved / len(old_ghosts) * 100:.1f}%")
```

### Expected Results

**Typical V1 vs V2 Comparison**:
- V1 ghosts: 80-100
- Still ghosts in V2: 5-10 (true ghosts)
- Resolved: 60-80 (were false positives)
- Not in V2: 10-15 (low confidence sources)

**This demonstrates**:
- V1 false positive rate: 60-80%
- V2 false positive rate: <10% (after learning)

## Troubleshooting Migration Issues

### Issue: Migration Script Fails

**Error**: `sqlite3.OperationalError: table cves already exists`

**Cause**: Database already has V2 schema

**Solution**:
```bash
# Option 1: Use existing V2 database
# No action needed

# Option 2: Force fresh migration
rm ghost_log.db
python scripts/migrate_to_v2.py
```

### Issue: Missing Dependencies

**Error**: `ModuleNotFoundError: No module named 'httpx'`

**Solution**:
```bash
pip install -r requirements.txt --upgrade
```

### Issue: API Rate Limits

**Symptom**: Many validation failures, slow hunts

**Solution**:
```bash
# Set API keys for higher limits
export CVE_ORG_API_KEY="your_key"
export GITHUB_TOKEN="ghp_your_token"

# Or adjust cache TTL
# Edit src/config.py:
# CACHE_TTL_HOURS = 2  # Longer cache = fewer API calls
```

### Issue: No Ghosts Found

**Symptom**: First hunt finds 0 ghosts

**Expected**: This is normal initially!

**Reasons**:
1. 6-hour grace period filters out recent CVEs
2. 60% confidence threshold is strict
3. Multi-source validation is thorough
4. Most CVEs are properly published

**What to Do**:
- Wait 24 hours and run again
- Check for CVEs in grace period: `SELECT COUNT(*) FROM cves WHERE is_ghost = 0`
- Review low-confidence findings: `SELECT * FROM cves ORDER BY confidence_score DESC`

### Issue: High Memory Usage

**Symptom**: Python process uses >2GB RAM

**Causes**:
- Too many concurrent workers
- Large validation cache
- Many discovery sources

**Solution**:
```python
# Edit src/config.py
class DiscoveryConfig:
    MAX_WORKERS = 3  # Reduce from 5

class ValidationConfig:
    CACHE_TTL_HOURS = 0.5  # Reduce from 1
```

## Rollback Procedure

If V2 migration causes issues and you need to rollback:

### Step 1: Restore V1 Database

```bash
# Stop any running hunts
pkill -f "python main.py"

# Restore backup
cp ghost_log_v1_backup_XXXXXXXX.db ghost_log.db
```

### Step 2: Revert Code

```bash
# Checkout V1 code
git log --oneline  # Find V1 commit hash
git checkout <v1-commit-hash>
```

### Step 3: Verify Rollback

```bash
# Check database structure
sqlite3 ghost_log.db ".schema" | head -20

# Should show V1 tables (ghost_cves, discovery_sources)

# Run V1 hunt
python main.py --hunt
```

### Step 4: Report Issue

If you had to rollback, please report the issue:
- GitHub: https://github.com/rogolabs/GhostCVEs/issues
- Include: Error messages, system info, database size

## FAQ

### Q: Can I import my old ghost CVEs into V2?

**A**: Not recommended. Old ghosts have quality issues and lack the context (disclosure classification, root cause, etc.) that V2 requires. Better to start fresh.

### Q: How long until V2 reaches full accuracy?

**A**: 1-2 weeks. The learning system needs time to:
- Collect resolution data (RESERVED → PUBLISHED transitions)
- Calculate source reliability scores
- Build historical patterns

**Tip**: Run `--check-resolutions` daily to speed up learning.

### Q: Will V2 find the same ghosts as V1?

**A**: No. V2 will find **fewer but higher quality** ghosts. V1's high false positive rate means most "ghosts" weren't real issues.

### Q: Can I run V1 and V2 side-by-side?

**A**: Yes, but use different database files:
```bash
# V1 hunt
python main.py --hunt --database ghost_log_v1.db

# V2 hunt
python main.py --hunt --database ghost_log_v2.db
```

### Q: What if CVE.org API is down?

**A**: V2 automatically falls back to:
1. Local CVElist V5 repo (~2GB, official data)
2. Local NVD JSON database (~1.4GB)

### Q: How do I update local CVE data?

**A**: Automatic! V2 fetches fresh data on first run and caches it. To force update:
```bash
# Clear cache
rm -rf ~/.cache/ghostcves/

# Next hunt will re-download
python main.py --hunt
```

### Q: Can I customize confidence thresholds?

**A**: Yes, edit `src/config.py`:
```python
class ConfidenceConfig:
    GHOST_THRESHOLD = 0.60  # Adjust 0.50-0.80
    # Lower = more ghosts (higher false positive rate)
    # Higher = fewer ghosts (might miss some)
```

### Q: How do I add a new discovery source?

**A**: See [ARCHITECTURE.md](ARCHITECTURE.md#stage-1-discovery-23-sources) for details. Basic steps:
1. Create new module in `src/discovery/`
2. Inherit from `BaseDiscoveryModule`
3. Implement `discover()` method
4. Add to `src/config.py` with confidence score
5. Initialize in database: `INSERT INTO source_reliability ...`

## Additional Resources

- [ARCHITECTURE.md](ARCHITECTURE.md): Complete system design
- [README.md](../README.md): User guide and features
- [GitHub Issues](https://github.com/rogolabs/GhostCVEs/issues): Bug reports and questions

---

**Need Help?**
- GitHub Issues: https://github.com/rogolabs/GhostCVEs/issues
- Email: support@rogolabs.net

**Last Updated**: 2026-03-10
**Migration Version**: 1.0 → 2.0
