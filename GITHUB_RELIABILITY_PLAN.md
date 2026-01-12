# GitHub Link Reliability Improvement Plan

## Overview
This document outlines the strategy for ensuring GitHub links discovered by GhostCVEs are reliable and high-quality, filtering out fake repositories and low-value sources.

## Problem Statement
Some GitHub repositories are created specifically to game CVE discovery systems:
- **koreatest12/auto** - Known fake repository
- **Hex0rc1st/CVE_POC_monitor** - Known low-quality aggregator
- Other spam repos created solely to show up in CVE searches

## Implemented Solutions

### 1. Repository Blacklist System
**Location:** `src/config.py` - `GitHubQualityConfig.blacklisted_repos`

A configurable blacklist of known fake or low-quality repositories:
```python
blacklisted_repos: tuple[str, ...] = (
    "koreatest12/auto",
    "Hex0rc1st/CVE_POC_monitor",
    # Easily extensible - add more as discovered
)
```

**User Blacklist:** Also supports blacklisting entire users/organizations:
```python
blacklisted_users: tuple[str, ...] = (
    "koreatest12",
    # Add prolific fake CVE posters
)
```

### 2. Repository Quality Scoring System
**Location:** `src/discovery/github_discovery.py` - `_calculate_repo_quality_score()`

Multi-factor scoring system (0.0 to 1.0) that evaluates:

#### A. Star Count (30% weight)
- Repositories with more stars are more trustworthy
- Good threshold: 10+ stars = full score
- Formula: `min(stars / good_star_count, 1.0)`

#### B. Repository Age (20% weight)
- Newer repos are more likely to be spam
- Good threshold: 30+ days = full score
- Filters out brand-new spam repos

#### C. Recent Activity (20% weight)
- Active repos indicate real maintenance
- Activity window: 180 days
- Abandoned repos score lower

#### D. Metadata Quality (30% weight)
- Has description? (+25%)
- Has license? (+25%)
- Has topics/tags? (+25%)
- Has homepage? (+12.5%)
- Indicates legitimate project setup

### 3. Dynamic Confidence Adjustment
**Location:** Both `_process_code_item()` and `_process_commit_item()`

Base confidence scores are now adjusted based on repository quality:
```python
adjusted_confidence = (base_confidence * 0.5) + (quality_score * 0.5)
```

Example:
- Base confidence: 0.90 (code search)
- Low-quality repo (score 0.2): Final = 0.55
- High-quality repo (score 0.9): Final = 0.85

### 4. Minimum Quality Thresholds
**Location:** `src/config.py` - `GitHubQualityConfig`

Configurable filters (default: permissive, can be tightened):
- `min_stars`: 0 (recommend 3+ for strict filtering)
- `min_age_days`: 1 (prevents brand-new spam)
- `require_description`: True (must have description)
- `require_license`: False (optional but improves score)

## Configuration Guide

### Tightening Filters
Edit `src/config.py` to make filtering more strict:

```python
@dataclass(frozen=True)
class GitHubQualityConfig:
    min_stars: int = 3              # Require at least 3 stars
    min_age_days: int = 7           # Repo must be at least 1 week old
    require_description: bool = True # Must have description
    require_license: bool = True    # Must have license
```

### Adding to Blacklist
Two ways to blacklist:

1. **Specific Repository:**
```python
blacklisted_repos: tuple[str, ...] = (
    "koreatest12/auto",
    "Hex0rc1st/CVE_POC_monitor",
    "newspammer/fakecves",  # Add here
)
```

2. **Entire User/Organization:**
```python
blacklisted_users: tuple[str, ...] = (
    "koreatest12",
    "newspammer",  # Add here
)
```

### Adjusting Scoring Weights
Customize what matters most for your use case:

```python
# Default: Balanced approach
star_weight: float = 0.3
age_weight: float = 0.2
activity_weight: float = 0.2
metadata_weight: float = 0.3

# Alternative: Trust stars more
star_weight: float = 0.5
age_weight: float = 0.1
activity_weight: float = 0.2
metadata_weight: float = 0.2
```

## Recommended Configurations

### Conservative (Fewer false positives)
```python
min_stars: int = 5
min_age_days: int = 14
require_description: bool = True
require_license: bool = True
```

### Balanced (Current default)
```python
min_stars: int = 0
min_age_days: int = 1
require_description: bool = True
require_license: bool = False
```

### Aggressive (Maximum discovery)
```python
min_stars: int = 0
min_age_days: int = 0
require_description: bool = False
require_license: bool = False
```

## Future Enhancements

### 1. Machine Learning Classification
- Train model on known good/bad repos
- Features: commit patterns, file types, code complexity
- Auto-detect spam without manual blacklisting

### 2. GitHub API Enrichment
- Fetch full repo metadata on first discovery
- Check fork status (many spam repos are forks)
- Analyze commit history patterns
- Verify contributor diversity

### 3. Community Reporting
- Allow users to flag fake repos
- Shared blacklist across GhostCVEs installations
- Crowdsourced reputation system

### 4. Cross-Reference Validation
- Check if CVE appears in multiple independent sources
- Downweight repos that are the only source
- Bonus score for repos cited by known-good sources

### 5. Content Analysis
- Analyze actual code quality
- Check for generic/template patterns
- Verify if CVE is actually fixed/addressed in code
- Parse commit messages for legitimate security work

### 6. Rate Limiting by Repo Quality
- Prioritize API calls for high-quality repos
- Skip low-quality repos when rate-limited
- Adaptive crawling based on discovery value

## Monitoring and Maintenance

### Regular Review
1. Check logs for blacklisted repos that keep appearing
2. Review low-confidence discoveries for patterns
3. Update blacklist monthly based on findings

### Quality Metrics
Track in reports:
- Average repository quality score
- Percentage of discoveries filtered out
- Distribution of confidence scores
- Blacklist hit rate

### Logging
Enable debug logging to see filtering in action:
```python
log_level: str = "DEBUG"
```

Look for:
- "Skipping blacklisted repository: ..."
- "Skipping low-quality repository: ..."
- "Repository X below minimum stars: Y"

## Testing the System

### Verify Blacklist Works
```bash
# Should not appear in results:
grep -r "koreatest12/auto" reports/
grep -r "Hex0rc1st/CVE_POC_monitor" reports/
```

### Check Quality Scores
Look in report JSON files for `quality_score` field:
```json
"raw_data": {
  "repository": "example/repo",
  "quality_score": 0.85,
  "repo_stars": 42
}
```

### Monitor Confidence Distribution
High-quality repos should have confidence ~0.85-0.95
Low-quality repos should have confidence ~0.50-0.70

## Conclusion

This multi-layered approach provides:
1. **Immediate protection** via blacklist
2. **Automated filtering** via quality scoring
3. **Transparent ranking** via confidence scores
4. **Easy extensibility** for future improvements

The system balances thoroughness (not missing real CVEs) with reliability (filtering fake sources), with all parameters tunable based on your risk tolerance and discovery goals.
