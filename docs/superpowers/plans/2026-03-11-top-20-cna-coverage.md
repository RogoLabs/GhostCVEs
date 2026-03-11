# Top 20 CNA Coverage Enhancement - Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Achieve comprehensive coverage of top 20 CVE Numbering Authorities through audit-first optimization and strategic source expansion, reducing false positives while improving ghost detection.

**Architecture:** Three-phase approach: (1) Audit and optimize existing 23 sources using metrics-based analysis, (2) Add 8-10 new sources covering WordPress ecosystem and major vendors via RSS feeds and simple APIs, (3) Implement source health monitoring with automated alerting.

**Tech Stack:** Python 3.11, SQLite, requests, feedparser, beautifulsoup4, existing Ghost Hunter pipeline

**Design Document:** `docs/superpowers/specs/2026-03-11-top-20-cna-coverage-design.md`

**Feature Branch:** `feature/top-20-cna-coverage`

---

## Pre-Implementation Checklist

- [ ] **Verify design document reviewed and approved**
  - Location: `docs/superpowers/specs/2026-03-11-top-20-cna-coverage-design.md`
  - Ensure all sections approved by stakeholder

- [ ] **Create feature branch**

```bash
git checkout main
git pull origin main
git checkout -b feature/top-20-cna-coverage
git push -u origin feature/top-20-cna-coverage
```

- [ ] **Verify test environment**

```bash
# Run existing tests to ensure baseline
pytest tests/ -v
# Expected: All tests passing

# Run a baseline hunt to save metrics
python main.py --hunt --log-level INFO
# Save output for comparison
```

- [ ] **Document baseline metrics**

Create `reports/baseline-metrics.json`:
```json
{
  "date": "2026-03-11",
  "total_sources": 23,
  "ghost_count": 72,
  "hunt_duration_seconds": 0,
  "false_positive_rate": 0.10
}
```

---

## Chunk 1: Phase 1 - Source Audit System

### Task 1: Create Source Audit Data Structures

**Files:**
- Create: `src/analysis/__init__.py`
- Create: `src/analysis/source_audit.py`
- Create: `tests/test_source_audit.py`

- [ ] **Step 1: Write failing test for SourceMetrics**

Create `tests/test_source_audit.py`:

```python
"""Tests for source audit system."""
import pytest
from datetime import datetime, timedelta
from src.analysis.source_audit import SourceMetrics, calculate_reliability_score


def test_source_metrics_creation():
    """Test creating SourceMetrics instance."""
    metrics = SourceMetrics(
        source_name="test_source",
        total_discoveries=100,
        ghost_detection_rate=0.75,
        false_positive_rate=0.10,
        avg_time_to_resolution=5.5,
        reliability_score=0.0,  # Will be calculated
        last_successful_fetch=datetime.utcnow(),
        fetch_failure_rate=0.02,
        avg_fetch_time=2.5,
        unique_cves_found=25
    )

    assert metrics.source_name == "test_source"
    assert metrics.total_discoveries == 100
    assert metrics.ghost_detection_rate == 0.75


def test_reliability_score_calculation():
    """Test reliability score calculation from metrics."""
    score = calculate_reliability_score(
        ghost_detection_rate=0.80,
        false_positive_rate=0.10,
        fetch_reliability=0.95,
        unique_discoveries_ratio=0.20
    )

    # Should be weighted: 0.80*0.4 + 0.90*0.3 + 0.95*0.2 + 0.20*0.1
    # = 0.32 + 0.27 + 0.19 + 0.02 = 0.80
    assert 0.79 <= score <= 0.81
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_source_audit.py -v
```

Expected: `ModuleNotFoundError: No module named 'src.analysis'`

- [ ] **Step 3: Create analysis module structure**

Create `src/analysis/__init__.py`:

```python
"""
Analysis Module
===============

Tools for analyzing source performance, reliability, and coverage.
"""

from src.analysis.source_audit import (
    SourceMetrics,
    SourceAuditor,
    calculate_reliability_score,
    identify_redundant_sources
)

__all__ = [
    "SourceMetrics",
    "SourceAuditor",
    "calculate_reliability_score",
    "identify_redundant_sources"
]
```

- [ ] **Step 4: Implement SourceMetrics and calculation**

Create `src/analysis/source_audit.py`:

```python
"""
Source Audit System
===================

Analyzes discovery source performance, reliability, and coverage to inform
optimization decisions.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class SourceMetrics:
    """Performance and reliability metrics for a discovery source."""

    source_name: str
    total_discoveries: int
    ghost_detection_rate: float      # % that became true ghosts
    false_positive_rate: float        # % already PUBLISHED
    avg_time_to_resolution: float     # Days to publication
    reliability_score: float          # Weighted composite score
    last_successful_fetch: datetime
    fetch_failure_rate: float         # % of failed fetches
    avg_fetch_time: float             # Seconds per fetch
    unique_cves_found: int            # CVEs only this source found


def calculate_reliability_score(
    ghost_detection_rate: float,
    false_positive_rate: float,
    fetch_reliability: float,
    unique_discoveries_ratio: float
) -> float:
    """
    Calculate weighted reliability score from component metrics.

    Weights:
    - Ghost detection rate: 40% (most important - finding real ghosts)
    - False positive rate: 30% (inverted - lower is better)
    - Fetch reliability: 20% (source uptime/availability)
    - Unique discoveries: 10% (value of unique CVEs)

    Args:
        ghost_detection_rate: Ratio of discoveries that became true ghosts (0.0-1.0)
        false_positive_rate: Ratio of discoveries already PUBLISHED (0.0-1.0)
        fetch_reliability: Ratio of successful fetches (0.0-1.0)
        unique_discoveries_ratio: Ratio of unique CVEs vs total (0.0-1.0)

    Returns:
        Composite reliability score (0.0-1.0)

    Examples:
        >>> calculate_reliability_score(0.80, 0.10, 0.95, 0.20)
        0.80
        >>> calculate_reliability_score(0.50, 0.40, 0.80, 0.05)
        0.55
    """
    # Invert false positive rate (lower is better)
    fp_score = 1.0 - false_positive_rate

    # Weighted average
    score = (
        ghost_detection_rate * 0.4 +
        fp_score * 0.3 +
        fetch_reliability * 0.2 +
        unique_discoveries_ratio * 0.1
    )

    return score


def identify_redundant_sources(
    source_a_cves: set[str],
    source_b_cves: set[str],
    overlap_threshold: float = 0.80
) -> tuple[bool, float]:
    """
    Determine if two sources are redundant based on CVE overlap.

    Args:
        source_a_cves: Set of CVE IDs discovered by source A
        source_b_cves: Set of CVE IDs discovered by source B
        overlap_threshold: Minimum Jaccard similarity to consider redundant

    Returns:
        Tuple of (is_redundant, jaccard_similarity)

    Examples:
        >>> identify_redundant_sources(
        ...     {"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"},
        ...     {"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0004"},
        ...     0.50
        ... )
        (True, 0.5)
    """
    if not source_a_cves or not source_b_cves:
        return (False, 0.0)

    # Calculate Jaccard similarity: |A ∩ B| / |A ∪ B|
    intersection = source_a_cves & source_b_cves
    union = source_a_cves | source_b_cves

    similarity = len(intersection) / len(union) if union else 0.0

    is_redundant = similarity >= overlap_threshold

    return (is_redundant, similarity)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_source_audit.py -v
```

Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/analysis/__init__.py src/analysis/source_audit.py tests/test_source_audit.py
git commit -m "feat(audit): add source metrics and reliability scoring

- Add SourceMetrics dataclass for tracking source performance
- Implement calculate_reliability_score() with weighted metrics
- Add identify_redundant_sources() for overlap detection
- Tests for metrics calculation and redundancy detection

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: Implement Database Query for Historical Metrics

**Files:**
- Modify: `src/analysis/source_audit.py`
- Modify: `tests/test_source_audit.py`
- Reference: `src/storage/database.py` (existing)

- [ ] **Step 1: Write failing test for metrics collection**

Add to `tests/test_source_audit.py`:

```python
from unittest.mock import Mock, MagicMock
from src.analysis.source_audit import SourceAuditor


def test_collect_source_metrics_from_database(tmp_path):
    """Test collecting metrics from database."""
    # Create mock database with test data
    db_path = tmp_path / "test.db"

    # Mock DatabaseManager
    mock_db = Mock()
    mock_db.get_all_sources.return_value = ["test_rss", "test_api"]
    mock_db.get_source_discoveries.return_value = [
        {"cve_id": "CVE-2025-0001", "is_ghost": True, "discovered_at": "2025-01-01"},
        {"cve_id": "CVE-2025-0002", "is_ghost": False, "discovered_at": "2025-01-02"}
    ]
    mock_db.get_source_resolution_history.return_value = [
        {"cve_id": "CVE-2025-0001", "resolution_days": 5.0, "was_true_ghost": True}
    ]

    auditor = SourceAuditor(mock_db)
    metrics = auditor.collect_source_metrics("test_rss")

    assert metrics.source_name == "test_rss"
    assert metrics.total_discoveries == 2
    assert metrics.ghost_detection_rate == 0.5  # 1 of 2 was ghost


def test_audit_all_sources():
    """Test auditing all sources returns list of metrics."""
    mock_db = Mock()
    mock_db.get_all_sources.return_value = ["source1", "source2"]

    auditor = SourceAuditor(mock_db)
    # Mock collect_source_metrics
    auditor.collect_source_metrics = Mock(return_value=SourceMetrics(
        source_name="test",
        total_discoveries=10,
        ghost_detection_rate=0.7,
        false_positive_rate=0.1,
        avg_time_to_resolution=5.0,
        reliability_score=0.8,
        last_successful_fetch=datetime.utcnow(),
        fetch_failure_rate=0.05,
        avg_fetch_time=2.0,
        unique_cves_found=3
    ))

    all_metrics = auditor.audit_all_sources()

    assert len(all_metrics) == 2
    assert all(isinstance(m, SourceMetrics) for m in all_metrics)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_source_audit.py::test_collect_source_metrics_from_database -v
```

Expected: `AttributeError: 'module' object has no attribute 'SourceAuditor'`

- [ ] **Step 3: Implement SourceAuditor class**

Add to `src/analysis/source_audit.py`:

```python
class SourceAuditor:
    """
    Audits discovery sources for performance and reliability.

    Analyzes historical data from database to calculate metrics for each source:
    - Ghost detection rate (true positives)
    - False positive rate (already published CVEs)
    - Average time to resolution
    - Fetch reliability
    - Unique discovery value
    """

    def __init__(self, database_manager):
        """
        Initialize auditor with database access.

        Args:
            database_manager: DatabaseManager instance for data access
        """
        self.db = database_manager

    def collect_source_metrics(self, source_name: str) -> SourceMetrics:
        """
        Collect comprehensive metrics for a single source.

        Args:
            source_name: Name of the source to audit

        Returns:
            SourceMetrics with calculated values
        """
        logger.info(f"Collecting metrics for source: {source_name}")

        # Get all discoveries from this source
        discoveries = self.db.get_source_discoveries(source_name)
        total_discoveries = len(discoveries)

        if total_discoveries == 0:
            logger.warning(f"No discoveries found for source: {source_name}")
            return self._empty_metrics(source_name)

        # Calculate ghost detection rate
        ghost_count = sum(1 for d in discoveries if d.get("is_ghost"))
        ghost_detection_rate = ghost_count / total_discoveries if total_discoveries > 0 else 0.0

        # Calculate false positive rate (CVEs that were already PUBLISHED)
        published_count = sum(1 for d in discoveries if d.get("registry_status") == "PUBLISHED")
        false_positive_rate = published_count / total_discoveries if total_discoveries > 0 else 0.0

        # Get resolution history for this source
        resolutions = self.db.get_source_resolution_history(source_name)

        # Calculate average time to resolution
        if resolutions:
            avg_resolution_days = sum(r["resolution_days"] for r in resolutions) / len(resolutions)
        else:
            avg_resolution_days = 0.0

        # Calculate fetch reliability (placeholder - would need fetch history tracking)
        fetch_reliability = 0.95  # Default, will be improved with monitoring
        fetch_failure_rate = 0.05

        # Get unique CVEs (found only by this source)
        all_cves = {d["cve_id"] for d in discoveries}
        other_sources_cves = self._get_cves_from_other_sources(source_name)
        unique_cves = all_cves - other_sources_cves
        unique_count = len(unique_cves)
        unique_ratio = unique_count / total_discoveries if total_discoveries > 0 else 0.0

        # Calculate reliability score
        reliability_score = calculate_reliability_score(
            ghost_detection_rate=ghost_detection_rate,
            false_positive_rate=false_positive_rate,
            fetch_reliability=fetch_reliability,
            unique_discoveries_ratio=unique_ratio
        )

        # Get last successful fetch timestamp
        last_fetch = max(
            (datetime.fromisoformat(d["discovered_at"]) for d in discoveries),
            default=datetime.utcnow()
        )

        return SourceMetrics(
            source_name=source_name,
            total_discoveries=total_discoveries,
            donde_detection_rate=ghost_detection_rate,
            false_positive_rate=false_positive_rate,
            avg_time_to_resolution=avg_resolution_days,
            reliability_score=reliability_score,
            last_successful_fetch=last_fetch,
            fetch_failure_rate=fetch_failure_rate,
            avg_fetch_time=2.0,  # Placeholder
            unique_cves_found=unique_count
        )

    def audit_all_sources(self) -> list[SourceMetrics]:
        """
        Audit all sources in the database.

        Returns:
            List of SourceMetrics for all sources, sorted by reliability score
        """
        logger.info("Starting audit of all sources")

        all_sources = self.db.get_all_sources()
        logger.info(f"Found {len(all_sources)} sources to audit")

        metrics_list = []
        for source_name in all_sources:
            try:
                metrics = self.collect_source_metrics(source_name)
                metrics_list.append(metrics)
            except Exception as e:
                logger.error(f"Error auditing source {source_name}: {e}")
                continue

        # Sort by reliability score (highest first)
        metrics_list.sort(key=lambda m: m.reliability_score, reverse=True)

        return metrics_list

    def _empty_metrics(self, source_name: str) -> SourceMetrics:
        """Return empty metrics for a source with no data."""
        return SourceMetrics(
            source_name=source_name,
            total_discoveries=0,
            ghost_detection_rate=0.0,
            false_positive_rate=0.0,
            avg_time_to_resolution=0.0,
            reliability_score=0.0,
            last_successful_fetch=datetime.utcnow(),
            fetch_failure_rate=1.0,
            avg_fetch_time=0.0,
            unique_cves_found=0
        )

    def _get_cves_from_other_sources(self, exclude_source: str) -> set[str]:
        """Get set of all CVE IDs discovered by sources other than the specified one."""
        all_sources = self.db.get_all_sources()
        other_cves = set()

        for source in all_sources:
            if source != exclude_source:
                discoveries = self.db.get_source_discoveries(source)
                other_cves.update(d["cve_id"] for d in discoveries)

        return other_cves
```

- [ ] **Step 4: Add database methods placeholder**

Note: The actual database methods (get_source_discoveries, get_source_resolution_history, get_all_sources) need to be added to DatabaseManager. For now, we'll implement the auditor assuming these methods exist, and add them in the next task.

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_source_audit.py -v
```

Expected: Tests PASS (with mocks)

- [ ] **Step 6: Commit**

```bash
git add src/analysis/source_audit.py tests/test_source_audit.py
git commit -m "feat(audit): implement SourceAuditor for metrics collection

- Add SourceAuditor class for analyzing source performance
- Implement collect_source_metrics() with database queries
- Add audit_all_sources() for batch analysis
- Calculate ghost detection rate, false positives, unique discoveries
- Tests with mocked database

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: Add Database Methods for Audit Queries

**Files:**
- Modify: `src/storage/database.py`
- Modify: `tests/test_database_audit_queries.py` (create)

- [ ] **Step 1: Write failing tests for database methods**

Create `tests/test_database_audit_queries.py`:

```python
"""Tests for database audit query methods."""
import pytest
from datetime import datetime, timedelta
from src.storage.database import DatabaseManager
from src.models.enums import RegistryStatus


@pytest.fixture
def test_db(tmp_path):
    """Create test database with sample data."""
    db_path = tmp_path / "test_audit.db"
    db = DatabaseManager(str(db_path))

    # Insert test data
    # ... (would need actual test data setup)

    return db


def test_get_all_sources(test_db):
    """Test retrieving all unique source names."""
    sources = test_db.get_all_sources()

    assert isinstance(sources, list)
    assert len(sources) > 0
    assert all(isinstance(s, str) for s in sources)


def test_get_source_discoveries(test_db):
    """Test retrieving discoveries for a specific source."""
    discoveries = test_db.get_source_discoveries("test_rss_feed")

    assert isinstance(discoveries, list)
    for d in discoveries:
        assert "cve_id" in d
        assert "is_ghost" in d
        assert "discovered_at" in d
        assert "registry_status" in d


def test_get_source_resolution_history(test_db):
    """Test retrieving resolution history for a source."""
    history = test_db.get_source_resolution_history("test_rss_feed")

    assert isinstance(history, list)
    for h in history:
        assert "cve_id" in h
        assert "resolution_days" in h
        assert "was_true_ghost" in h
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_database_audit_queries.py -v
```

Expected: `AttributeError: 'DatabaseManager' object has no attribute 'get_all_sources'`

- [ ] **Step 3: Implement database methods**

Add to `src/storage/database.py`:

```python
def get_all_sources(self) -> list[str]:
    """
    Get list of all unique source names in the database.

    Returns:
        List of source names
    """
    with self.Session() as session:
        result = session.execute(
            text("SELECT DISTINCT source_name FROM discovery_sources ORDER BY source_name")
        )
        sources = [row[0] for row in result]

    return sources


def get_source_discoveries(self, source_name: str) -> list[dict]:
    """
    Get all CVE discoveries from a specific source.

    Args:
        source_name: Name of the source

    Returns:
        List of discovery records with CVE ID, ghost status, timestamp
    """
    with self.Session() as session:
        result = session.execute(
            text("""
                SELECT
                    ds.cve_id,
                    c.is_ghost,
                    ds.discovered_at,
                    c.registry_status
                FROM discovery_sources ds
                JOIN cves c ON ds.cve_id = c.cve_id
                WHERE ds.source_name = :source_name
                ORDER BY ds.discovered_at DESC
            """),
            {"source_name": source_name}
        )

        discoveries = [
            {
                "cve_id": row[0],
                "is_ghost": bool(row[1]),
                "discovered_at": row[2].isoformat() if row[2] else None,
                "registry_status": row[3]
            }
            for row in result
        ]

    return discoveries


def get_source_resolution_history(self, source_name: str) -> list[dict]:
    """
    Get resolution history for CVEs discovered by a source.

    Shows how long it took for RESERVED CVEs to become PUBLISHED.

    Args:
        source_name: Name of the source

    Returns:
        List of resolution records with timing information
    """
    with self.Session() as session:
        result = session.execute(
            text("""
                SELECT
                    rh.cve_id,
                    rh.resolution_days,
                    rh.was_true_ghost
                FROM resolution_history rh
                WHERE rh.source_name = :source_name
                AND rh.resolved_at IS NOT NULL
                ORDER BY rh.resolved_at DESC
            """),
            {"source_name": source_name}
        )

        history = [
            {
                "cve_id": row[0],
                "resolution_days": float(row[1]) if row[1] else 0.0,
                "was_true_ghost": bool(row[2])
            }
            for row in result
        ]

    return history
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_database_audit_queries.py -v
```

Expected: Tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/storage/database.py tests/test_database_audit_queries.py
git commit -m "feat(database): add audit query methods

- Add get_all_sources() to retrieve unique source names
- Add get_source_discoveries() for source-specific CVE history
- Add get_source_resolution_history() for timing analysis
- Tests for all new database methods

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Generate Audit Report

**Files:**
- Modify: `src/analysis/source_audit.py`
- Create: `tests/test_audit_report.py`

- [ ] **Step 1: Write failing test for report generation**

Create `tests/test_audit_report.py`:

```python
"""Tests for audit report generation."""
import pytest
from pathlib import Path
from unittest.mock import Mock
from datetime import datetime
from src.analysis.source_audit import SourceAuditor, SourceMetrics, generate_audit_report


def test_generate_audit_report():
    """Test generating markdown audit report."""
    metrics_list = [
        SourceMetrics(
            source_name="high_quality_source",
            total_discoveries=100,
            ghost_detection_rate=0.85,
            false_positive_rate=0.05,
            avg_time_to_resolution=3.5,
            reliability_score=0.88,
            last_successful_fetch=datetime.utcnow(),
            fetch_failure_rate=0.02,
            avg_fetch_time=2.0,
            unique_cves_found=25
        ),
        SourceMetrics(
            source_name="low_quality_source",
            total_discoveries=50,
            ghost_detection_rate=0.40,
            false_positive_rate=0.30,
            avg_time_to_resolution=10.0,
            reliability_score=0.45,
            last_successful_fetch=datetime.utcnow(),
            fetch_failure_rate=0.15,
            avg_fetch_time=5.0,
            unique_cves_found=2
        )
    ]

    report = generate_audit_report(metrics_list)

    assert "Source Audit Report" in report
    assert "high_quality_source" in report
    assert "low_quality_source" in report
    assert "0.88" in report  # Reliability score
    assert "Keep" in report  # Classification
    assert "Remove" in report  # Low quality source


def test_classify_source_recommendation():
    """Test source classification logic."""
    from src.analysis.source_audit import classify_source

    # High quality - should keep
    result = classify_source(0.85, 100, 0.02)
    assert result == "Keep"

    # Medium quality - should optimize
    result = classify_source(0.70, 50, 0.10)
    assert result == "Optimize"

    # Low quality - should remove
    result = classify_source(0.50, 20, 0.25)
    assert result == "Remove"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_audit_report.py -v
```

Expected: `ImportError: cannot import name 'generate_audit_report'`

- [ ] **Step 3: Implement report generation functions**

Add to `src/analysis/source_audit.py`:

```python
def classify_source(
    reliability_score: float,
    total_discoveries: int,
    fetch_failure_rate: float
) -> str:
    """
    Classify source into Keep/Optimize/Remove based on metrics.

    Decision criteria:
    - Keep: reliability >0.80, moderate discoveries, low failure rate
    - Optimize: reliability 0.60-0.80, could be improved
    - Remove: reliability <0.60 or very high failure rate or no discoveries

    Args:
        reliability_score: Composite reliability score (0.0-1.0)
        total_discoveries: Total CVEs discovered
        fetch_failure_rate: Ratio of failed fetches (0.0-1.0)

    Returns:
        Classification: "Keep", "Optimize", or "Remove"
    """
    # Remove if no meaningful discoveries
    if total_discoveries < 5:
        return "Remove"

    # Remove if fetch failure rate too high
    if fetch_failure_rate > 0.20:
        return "Remove"

    # Classify by reliability score
    if reliability_score >= 0.80:
        return "Keep"
    elif reliability_score >= 0.60:
        return "Optimize"
    else:
        return "Remove"


def generate_audit_report(metrics_list: list[SourceMetrics]) -> str:
    """
    Generate comprehensive markdown audit report.

    Args:
        metrics_list: List of source metrics (should be sorted by reliability)

    Returns:
        Markdown formatted audit report
    """
    report_lines = [
        "# Source Audit Report",
        "",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Sources Audited:** {len(metrics_list)}",
        "",
        "## Executive Summary",
        ""
    ]

    # Count by classification
    classifications = [classify_source(m.reliability_score, m.total_discoveries, m.fetch_failure_rate)
                       for m in metrics_list]
    keep_count = classifications.count("Keep")
    optimize_count = classifications.count("Optimize")
    remove_count = classifications.count("Remove")

    report_lines.extend([
        f"- **Keep (High Quality):** {keep_count} sources",
        f"- **Optimize (Medium Quality):** {optimize_count} sources",
        f"- **Remove (Low Quality):** {remove_count} sources",
        "",
        "## Detailed Source Analysis",
        "",
        "| Source | Reliability | Discoveries | Ghosts | FP Rate | Unique | Recommendation |",
        "|--------|-------------|-------------|--------|---------|--------|----------------|"
    ])

    # Add each source
    for metrics in metrics_list:
        classification = classify_source(
            metrics.reliability_score,
            metrics.total_discoveries,
            metrics.fetch_failure_rate
        )

        # Format row
        row = (
            f"| {metrics.source_name} "
            f"| {metrics.reliability_score:.2f} "
            f"| {metrics.total_discoveries} "
            f"| {metrics.ghost_detection_rate:.1%} "
            f"| {metrics.false_positive_rate:.1%} "
            f"| {metrics.unique_cves_found} "
            f"| **{classification}** |"
        )
        report_lines.append(row)

    report_lines.extend([
        "",
        "## Recommendations",
        "",
        "### Sources to Keep",
        ""
    ])

    # List sources to keep
    for metrics in metrics_list:
        if classify_source(metrics.reliability_score, metrics.total_discoveries, metrics.fetch_failure_rate) == "Keep":
            report_lines.append(
                f"- **{metrics.source_name}**: "
                f"Reliability {metrics.reliability_score:.2f}, "
                f"{metrics.unique_cves_found} unique discoveries"
            )

    report_lines.extend([
        "",
        "### Sources to Optimize",
        ""
    ])

    # List sources to optimize
    for metrics in metrics_list:
        if classify_source(metrics.reliability_score, metrics.total_discoveries, metrics.fetch_failure_rate) == "Optimize":
            report_lines.append(
                f"- **{metrics.source_name}**: "
                f"Could improve - reliability {metrics.reliability_score:.2f}, "
                f"FP rate {metrics.false_positive_rate:.1%}"
            )

    report_lines.extend([
        "",
        "### Sources to Remove",
        ""
    ])

    # List sources to remove with justification
    for metrics in metrics_list:
        if classify_source(metrics.reliability_score, metrics.total_discoveries, metrics.fetch_failure_rate) == "Remove":
            reasons = []
            if metrics.reliability_score < 0.60:
                reasons.append(f"low reliability ({metrics.reliability_score:.2f})")
            if metrics.fetch_failure_rate > 0.20:
                reasons.append(f"high failure rate ({metrics.fetch_failure_rate:.1%})")
            if metrics.total_discoveries < 5:
                reasons.append("minimal discoveries")
            if metrics.unique_cves_found == 0:
                reasons.append("no unique CVEs")

            justification = ", ".join(reasons)
            report_lines.append(
                f"- **{metrics.source_name}**: {justification}"
            )

    return "\n".join(report_lines)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_audit_report.py -v
```

Expected: Tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/analysis/source_audit.py tests/test_audit_report.py
git commit -m "feat(audit): add audit report generation

- Add classify_source() for Keep/Optimize/Remove decisions
- Implement generate_audit_report() for markdown output
- Include metrics table and detailed recommendations
- Tests for classification and report generation

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: Add CLI Command for Running Audit

**Files:**
- Modify: `main.py`
- Create: `tests/test_audit_cli.py`

- [ ] **Step 1: Write failing test for CLI command**

Create `tests/test_audit_cli.py`:

```python
"""Tests for audit CLI command."""
import pytest
from click.testing import CliRunner
from pathlib import Path
from main import cli


def test_audit_command_creates_report(tmp_path):
    """Test that --audit command generates report file."""
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ['--audit'])

        assert result.exit_code == 0
        assert "Source Audit Complete" in result.output

        # Check report file created
        report_path = Path("reports/source_audit_report.md")
        assert report_path.exists()


def test_audit_command_with_output_dir(tmp_path):
    """Test audit command with custom output directory."""
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ['--audit', '--output-dir', 'custom_reports'])

        assert result.exit_code == 0
        report_path = Path("custom_reports/source_audit_report.md")
        assert report_path.exists()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_audit_cli.py -v
```

Expected: `TypeError: cli() missing required argument '--audit'`

- [ ] **Step 3: Add audit command to CLI**

Modify `main.py` to add `--audit` option:

```python
@click.option('--audit', is_flag=True, help='Run source audit and generate report')
def cli(
    hunt: bool,
    check_resolutions: bool,
    report: bool,
    dashboard: bool,
    audit: bool,  # New parameter
    format: str,
    output_dir: str,
    database: str,
    log_level: str,
    log_file: str,
    workers: int,
    no_banner: bool
):
    """Ghost Hunter - CVE Ghost Detection System."""

    # ... existing setup code ...

    if audit:
        run_audit(output_dir)
        return


def run_audit(output_dir: str):
    """
    Run source audit and generate report.

    Args:
        output_dir: Directory to save report
    """
    from src.storage.database import DatabaseManager
    from src.analysis.source_audit import SourceAuditor, generate_audit_report
    from pathlib import Path

    console.print("\n[bold cyan]🔍 Starting Source Audit...[/bold cyan]\n")

    # Initialize database and auditor
    db = DatabaseManager()
    auditor = SourceAuditor(db)

    # Collect metrics for all sources
    with console.status("[bold green]Analyzing sources...") as status:
        metrics_list = auditor.audit_all_sources()

    console.print(f"✓ Analyzed {len(metrics_list)} sources\n")

    # Generate report
    report_content = generate_audit_report(metrics_list)

    # Save report
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    report_file = output_path / "source_audit_report.md"

    report_file.write_text(report_content)

    console.print(f"[bold green]✓ Source Audit Complete[/bold green]")
    console.print(f"Report saved to: [cyan]{report_file}[/cyan]\n")

    # Print summary
    classifications = {}
    for m in metrics_list:
        from src.analysis.source_audit import classify_source
        classification = classify_source(m.reliability_score, m.total_discoveries, m.fetch_failure_rate)
        classifications[classification] = classifications.get(classification, 0) + 1

    console.print("[bold]Summary:[/bold]")
    console.print(f"  Keep: {classifications.get('Keep', 0)}")
    console.print(f"  Optimize: {classifications.get('Optimize', 0)}")
    console.print(f"  Remove: {classifications.get('Remove', 0)}")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_audit_cli.py -v
```

Expected: Tests PASS

- [ ] **Step 5: Test audit command manually**

```bash
python main.py --audit --output-dir reports/audit
```

Expected: Report generated in `reports/audit/source_audit_report.md`

- [ ] **Step 6: Commit**

```bash
git add main.py tests/test_audit_cli.py
git commit -m "feat(cli): add --audit command for source analysis

- Add --audit flag to main CLI
- Implement run_audit() function
- Generate and save audit report to file
- Display summary statistics
- Tests for audit CLI command

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 6: Run Audit and Review Results

**Manual Step - No Automated Tests**

- [ ] **Step 1: Run full audit on production database**

```bash
# Make sure you're on feature branch
git branch --show-current
# Should show: feature/top-20-cna-coverage

# Run audit
python main.py --audit --output-dir reports/phase1-audit

# Review the generated report
cat reports/phase1-audit/source_audit_report.md
```

- [ ] **Step 2: Analyze recommendations**

Review the audit report sections:
- Sources to Keep: Verify these are high-quality
- Sources to Optimize: Note confidence score adjustments needed
- Sources to Remove: Verify justifications are sound

- [ ] **Step 3: Document removal decisions**

Create `reports/phase1-audit/removal-decisions.md`:

```markdown
# Source Removal Decisions - Phase 1 Audit

## Sources to Remove

### [Source Name 1]
- **Reliability Score:** X.XX
- **Justification:** [Specific reasons]
- **Impact:** [How many unique CVEs will be lost, if any]
- **Decision:** REMOVE / KEEP (with reason if keeping despite recommendation)

### [Source Name 2]
...

## Sources to Optimize

### [Source Name]
- **Current Confidence:** X.XX
- **Recommended Confidence:** X.XX
- **Rationale:** [Why adjustment needed]

## Summary

- Sources removing: X
- Unique CVEs lost: X (acceptable/unacceptable)
- Expected reliability improvement: X%
```

- [ ] **Step 4: Commit audit results**

```bash
git add reports/phase1-audit/
git commit -m "docs(audit): Phase 1 audit results and removal decisions

Audit findings:
- Total sources analyzed: [number]
- Sources to keep: [number]
- Sources to remove: [number]
- Expected reliability improvement: [X]%

Documented removal justifications and impact analysis.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 7: Remove Low-Quality Sources

**Files:**
- Modify: `src/config.py`

- [ ] **Step 1: Backup current config**

```bash
cp src/config.py src/config.py.phase1-backup
git add src/config.py.phase1-backup
git commit -m "backup: save pre-audit config for Phase 1"
```

- [ ] **Step 2: Remove sources from RSS_FEEDS**

Based on audit recommendations, remove low-quality RSS feeds from `src/config.py`:

```python
# In RSS_FEEDS list, comment out or remove entries like:

# REMOVED - Low reliability (audit: 2026-03-11)
# RSSFeed(
#     name="Low Quality Source",
#     url="https://example.com/feed",
#     source_type="aggregator",
#     priority=3
# ),
```

- [ ] **Step 3: Remove sources from VENDOR_ENDPOINTS**

Similarly, remove low-quality vendor endpoints:

```python
# REMOVED - High failure rate (audit: 2026-03-11)
# VendorEndpoint(
#     name="Unreliable Vendor",
#     ...
# ),
```

- [ ] **Step 4: Update confidence scores**

For sources marked "Optimize", adjust their confidence scores in the appropriate configs.

- [ ] **Step 5: Test configuration loads**

```bash
python -c "from src.config import RSS_FEEDS, VENDOR_ENDPOINTS; print(f'RSS Feeds: {len(RSS_FEEDS)}, Vendor Endpoints: {len(VENDOR_ENDPOINTS)}')"
```

Expected: No errors, counts reduced from baseline

- [ ] **Step 6: Run hunt to verify no regressions**

```bash
python main.py --hunt --log-level INFO > reports/phase1-audit/post-removal-hunt.log 2>&1
```

Review results:
- Hunt should complete successfully
- Ghost count should be similar or higher (not significantly lower)
- Check for any errors

- [ ] **Step 7: Commit source removal**

```bash
git add src/config.py
git commit -m "refactor(sources): remove low-quality sources from Phase 1 audit

Removed [X] sources based on audit recommendations:
- [Source 1]: low reliability (0.XX)
- [Source 2]: high failure rate (XX%)
- [Source 3]: no unique discoveries

Remaining sources: [X] (down from 23)
Expected quality improvement: [X]%

See reports/phase1-audit/removal-decisions.md for details.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 8: Phase 1 Completion and Merge

- [ ] **Step 1: Run final Phase 1 tests**

```bash
# Run all tests
pytest tests/ -v

# Run full hunt and compare to baseline
python main.py --hunt --report --format all

# Check metrics
python -c "
from src.storage.database import DatabaseManager
db = DatabaseManager()
stats = db.get_statistics()
print(f'Ghosts: {stats.get(\"total_ghosts\", 0)}')
print(f'Sources: {stats.get(\"total_sources\", 0)}')
"
```

- [ ] **Step 2: Update documentation**

Create `docs/PHASE1-RESULTS.md`:

```markdown
# Phase 1: Source Audit Results

## Metrics

### Before
- Total sources: 23
- Average reliability: X.XX
- Ghost count: XX
- False positive rate: X%

### After
- Total sources: XX (removed X)
- Average reliability: X.XX (+X%)
- Ghost count: XX (no regression)
- False positive rate: X% (improved)

## Sources Removed

[List with justifications]

## Confidence Score Updates

[List of adjusted confidence scores]

## Validation

- ✅ All tests passing
- ✅ No ghost CVEs lost
- ✅ Hunt runtime maintained
- ✅ Reliability improved
```

- [ ] **Step 3: Create Phase 1 PR**

```bash
git push origin feature/top-20-cna-coverage

# Create PR via GitHub CLI or web interface
gh pr create \
  --title "Phase 1: Source Audit and Optimization" \
  --body "Implements source audit system and removes low-quality sources.

## Changes
- Add source audit system with metrics calculation
- Add database methods for historical analysis
- Add --audit CLI command
- Remove [X] low-quality sources based on audit
- Improve average source reliability by [X]%

## Testing
- Unit tests for audit system
- Integration tests with database
- Manual validation of recommendations
- No regression in ghost detection

## Results
See docs/PHASE1-RESULTS.md for detailed metrics.

Ref: docs/superpowers/specs/2026-03-11-top-20-cna-coverage-design.md" \
  --base main

```

- [ ] **Step 4: Wait for review and approval**

Address any review comments, then merge Phase 1 to main.

- [ ] **Step 5: Tag Phase 1 completion**

```bash
git checkout main
git pull origin main
git tag -a phase1-audit-complete -m "Phase 1: Source audit and optimization complete"
git push origin phase1-audit-complete
```

---

## Chunk 2: Phase 2 Part A - WordPress Ecosystem Sources

### Task 9: Add Patchstack RSS Feed

**Files:**
- Modify: `src/config.py`
- Create: `tests/test_patchstack_discovery.py`

- [ ] **Step 1: Research Patchstack feed format**

```bash
# Test the Patchstack RSS feed
curl -s "https://patchstack.com/database/feed/rss" | head -50
```

Document the feed structure and CVE ID extraction pattern.

- [ ] **Step 2: Write failing test for Patchstack**

Create `tests/test_patchstack_discovery.py`:

```python
"""Tests for Patchstack CVE discovery."""
import pytest
from unittest.mock import Mock, patch
from src.discovery.rss_discovery import RSSDiscovery
from src.config import RSS_FEEDS


def test_patchstack_feed_configured():
    """Test that Patchstack feed is in configuration."""
    patchstack_feeds = [f for f in RSS_FEEDS if "patchstack" in f.name.lower()]
    assert len(patchstack_feeds) > 0

    feed = patchstack_feeds[0]
    assert "patchstack.com" in feed.url
    assert feed.source_type == "vendor_advisory"


@patch('src.discovery.rss_discovery.feedparser.parse')
def test_patchstack_cve_extraction(mock_parse):
    """Test extracting CVE IDs from Patchstack feed."""
    # Mock Patchstack RSS response
    mock_parse.return_value = {
        'entries': [
            {
                'title': 'WordPress Plugin Vulnerability - CVE-2025-1234',
                'link': 'https://patchstack.com/database/vulnerability/plugin-name/cve-2025-1234',
                'description': 'Cross-Site Scripting vulnerability in WordPress plugin',
                'published': 'Mon, 10 Mar 2025 10:00:00 GMT'
            },
            {
                'title': 'Theme Security Issue CVE-2025-5678',
                'link': 'https://patchstack.com/database/vulnerability/theme-name/cve-2025-5678',
                'description': 'SQL Injection in theme',
                'published': 'Mon, 10 Mar 2025 11:00:00 GMT'
            }
        ]
    }

    discoverer = RSSDiscovery()
    results = discoverer.discover()

    # Should find both CVEs
    cve_ids = [r.cve_id for r in results if r.source_name == "Patchstack"]
    assert "CVE-2025-1234" in cve_ids
    assert "CVE-2025-5678" in cve_ids
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/test_patchstack_discovery.py -v
```

Expected: Test fails because Patchstack not in RSS_FEEDS yet

- [ ] **Step 4: Add Patchstack to RSS_FEEDS**

Modify `src/config.py`, add to RSS_FEEDS list:

```python
# WordPress Ecosystem (High Value - ~28k CVEs combined)
RSSFeed(
    name="Patchstack Database",
    url="https://patchstack.com/database/feed/rss",
    source_type="vendor_advisory",
    priority=1  # High priority - 15k CVEs
),
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_patchstack_discovery.py -v
```

Expected: Tests PASS

- [ ] **Step 6: Test live feed**

```bash
python -c "
from src.discovery.rss_discovery import RSSDiscovery
discoverer = RSSDiscovery()
results = discoverer.discover()
patchstack_results = [r for r in results if 'patchstack' in r.source_name.lower()]
print(f'Found {len(patchstack_results)} CVEs from Patchstack')
for r in patchstack_results[:5]:
    print(f'  {r.cve_id}: {r.context[:100]}')
"
```

- [ ] **Step 7: Commit**

```bash
git add src/config.py tests/test_patchstack_discovery.py
git commit -m "feat(sources): add Patchstack WordPress security database

- Add Patchstack RSS feed (est. 15k CVEs)
- Covers WordPress plugin vulnerabilities
- Priority 1 source (high reliability expected)
- Tests for feed configuration and CVE extraction

Part of Phase 2: WordPress ecosystem coverage

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 10: Add Adobe PSIRT RSS Feed

**Files:**
- Modify: `src/config.py`
- Create: `tests/test_adobe_discovery.py`

- [ ] **Step 1: Research Adobe PSIRT feed**

```bash
# Test Adobe security feed
curl -s "https://helpx.adobe.com/security.rss" | head -50
```

- [ ] **Step 2: Write failing test**

Create `tests/test_adobe_discovery.py`:

```python
"""Tests for Adobe PSIRT discovery."""
import pytest
from unittest.mock import patch
from src.discovery.rss_discovery import RSSDiscovery
from src.config import RSS_FEEDS


def test_adobe_feed_configured():
    """Test that Adobe PSIRT feed is in configuration."""
    adobe_feeds = [f for f in RSS_FEEDS if "adobe" in f.name.lower()]
    assert len(adobe_feeds) > 0

    feed = adobe_feeds[0]
    assert "adobe.com" in feed.url or "helpx.adobe.com" in feed.url
    assert feed.source_type == "vendor_advisory"


@patch('src.discovery.rss_discovery.feedparser.parse')
def test_adobe_cve_extraction(mock_parse):
    """Test extracting CVE IDs from Adobe security bulletins."""
    mock_parse.return_value = {
        'entries': [
            {
                'title': 'Security update available for Adobe Acrobat and Reader',
                'link': 'https://helpx.adobe.com/security/products/acrobat/apsb25-01.html',
                'description': 'Adobe has released security updates for Acrobat addressing CVE-2025-12345 and CVE-2025-12346',
                'published': 'Tue, 11 Mar 2025 09:00:00 GMT'
            }
        ]
    }

    discoverer = RSSDiscovery()
    results = discoverer.discover()

    adobe_cves = [r.cve_id for r in results if "adobe" in r.source_name.lower()]
    assert "CVE-2025-12345" in adobe_cves
    assert "CVE-2025-12346" in adobe_cves
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/test_adobe_discovery.py -v
```

- [ ] **Step 4: Add Adobe to RSS_FEEDS**

Modify `src/config.py`:

```python
# Adobe (Major Vendor - ~3.5k CVEs)
RSSFeed(
    name="Adobe Security Bulletins",
    url="https://helpx.adobe.com/security.rss",
    source_type="vendor_advisory",
    priority=1
),
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_adobe_discovery.py -v
```

- [ ] **Step 6: Test live feed**

```bash
python -c "
from src.discovery.rss_discovery import RSSDiscovery
discoverer = RSSDiscovery()
results = discoverer.discover()
adobe_results = [r for r in results if 'adobe' in r.source_name.lower()]
print(f'Found {len(adobe_results)} CVEs from Adobe')
"
```

- [ ] **Step 7: Commit**

```bash
git add src/config.py tests/test_adobe_discovery.py
git commit -m "feat(sources): add Adobe PSIRT security bulletins

- Add Adobe security RSS feed (est. 3.5k CVEs)
- Covers Acrobat, Reader, Creative Cloud products
- Priority 1 major vendor source
- Tests for feed configuration and parsing

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 11: Implement Wordfence Discovery Class

**Files:**
- Create: `src/discovery/wordfence_discovery.py`
- Modify: `src/discovery/__init__.py`
- Create: `tests/test_wordfence_discovery.py`

- [ ] **Step 1: Research Wordfence API**

```bash
# Test Wordfence intelligence API
curl -s "https://www.wordfence.com/api/intelligence/v2/vulnerabilities?per_page=10" | jq '.' | head -50
```

Document API structure, pagination, CVE ID field location.

- [ ] **Step 2: Write failing test**

Create `tests/test_wordfence_discovery.py`:

```python
"""Tests for Wordfence intelligence API discovery."""
import pytest
from unittest.mock import Mock, patch
from src.discovery.wordfence_discovery import WordfenceDiscovery
from src.discovery.base import DiscoveryResult


@patch('src.discovery.wordfence_discovery.requests.get')
def test_wordfence_api_discovery(mock_get):
    """Test discovering CVEs from Wordfence API."""
    # Mock API response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'vulnerabilities': [
            {
                'id': 12345,
                'title': 'XSS Vulnerability in Plugin Name',
                'cve': 'CVE-2025-9999',
                'cvss': {'score': 6.1},
                'software': [{'slug': 'plugin-name', 'type': 'plugin'}],
                'published': '2025-03-10T10:00:00Z'
            },
            {
                'id': 12346,
                'title': 'SQL Injection',
                'cve': 'CVE-2025-9998',
                'cvss': {'score': 9.8},
                'software': [{'slug': 'another-plugin', 'type': 'plugin'}],
                'published': '2025-03-10T11:00:00Z'
            }
        ],
        'pagination': {
            'current_page': 1,
            'total_pages': 1
        }
    }
    mock_get.return_value = mock_response

    discoverer = WordfenceDiscovery()
    results = discoverer.discover()

    assert len(results) >= 2
    cve_ids = [r.cve_id for r in results]
    assert "CVE-2025-9999" in cve_ids
    assert "CVE-2025-9998" in cve_ids

    # Check result properties
    result = results[0]
    assert result.source_name == "Wordfence Intelligence"
    assert result.source_type == "vendor_advisory"
    assert "wordpress" in result.context.lower() or "plugin" in result.context.lower()


def test_wordfence_pagination():
    """Test handling paginated API responses."""
    # Would test pagination logic if needed
    pass
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/test_wordfence_discovery.py -v
```

Expected: `ModuleNotFoundError: No module named 'src.discovery.wordfence_discovery'`

- [ ] **Step 4: Implement Wordfence discovery class**

Create `src/discovery/wordfence_discovery.py`:

```python
"""
Wordfence Intelligence API Discovery
=====================================

Discovers CVEs from Wordfence threat intelligence database for WordPress.
"""

import requests
import logging
from typing import List
from datetime import datetime

from src.discovery.base import BaseDiscovery, DiscoveryResult
from src.config import APP_SETTINGS

logger = logging.getLogger(__name__)


class WordfenceDiscovery(BaseDiscovery):
    """
    Discovers CVE mentions from Wordfence Intelligence API.

    Wordfence maintains a comprehensive database of WordPress plugin and theme
    vulnerabilities with ~8.5k CVEs.
    """

    BASE_URL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities"

    def __init__(self):
        """Initialize Wordfence discovery."""
        super().__init__()
        self.source_name = "Wordfence Intelligence"
        self.source_type = "vendor_advisory"
        self.confidence = 0.87  # Security vendor, WordPress-specific

    def discover(self) -> List[DiscoveryResult]:
        """
        Discover CVEs from Wordfence API.

        Returns:
            List of DiscoveryResult objects
        """
        logger.info(f"Starting {self.source_name} discovery")
        results = []

        try:
            # Fetch vulnerabilities (paginated)
            page = 1
            max_pages = 10  # Limit to prevent excessive requests

            while page <= max_pages:
                logger.debug(f"Fetching Wordfence page {page}")

                response = requests.get(
                    self.BASE_URL,
                    params={
                        'per_page': 100,
                        'page': page
                    },
                    headers={'User-Agent': APP_SETTINGS.user_agent},
                    timeout=30
                )

                if response.status_code != 200:
                    logger.error(f"Wordfence API returned {response.status_code}")
                    break

                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                if not vulnerabilities:
                    break

                # Extract CVEs
                for vuln in vulnerabilities:
                    cve_id = vuln.get('cve')

                    if not cve_id or not cve_id.startswith('CVE-'):
                        continue

                    # Build context
                    title = vuln.get('title', '')
                    software_list = vuln.get('software', [])
                    software_names = ', '.join(s.get('slug', '') for s in software_list)
                    cvss_score = vuln.get('cvss', {}).get('score', 0)

                    context = f"{title}. Affects: {software_names}. CVSS: {cvss_score}"

                    # Evidence URL
                    vuln_id = vuln.get('id')
                    evidence_url = f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{vuln_id}"

                    result = DiscoveryResult(
                        cve_id=cve_id,
                        source_name=self.source_name,
                        source_type=self.source_type,
                        confidence=self.confidence,
                        context=context,
                        evidence_url=evidence_url,
                        discovered_at=datetime.utcnow()
                    )

                    results.append(result)

                # Check pagination
                pagination = data.get('pagination', {})
                current_page = pagination.get('current_page', page)
                total_pages = pagination.get('total_pages', 1)

                if current_page >= total_pages:
                    break

                page += 1

            logger.info(f"{self.source_name}: Found {len(results)} CVE mentions")

        except Exception as e:
            logger.error(f"Error in Wordfence discovery: {e}")

        return results
```

- [ ] **Step 5: Add to discovery exports**

Modify `src/discovery/__init__.py`:

```python
from src.discovery.wordfence_discovery import WordfenceDiscovery

__all__ = [
    "BaseDiscovery",
    "DiscoveryResult",
    "GitHubDiscovery",
    "RSSDiscovery",
    "VendorDiscovery",
    "ExploitDBDiscovery",
    "WordfenceDiscovery",  # New
]
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
pytest tests/test_wordfence_discovery.py -v
```

- [ ] **Step 7: Test live API**

```bash
python -c "
from src.discovery.wordfence_discovery import WordfenceDiscovery
discoverer = WordfenceDiscovery()
results = discoverer.discover()
print(f'Found {len(results)} CVEs from Wordfence')
for r in results[:5]:
    print(f'  {r.cve_id}: {r.context[:80]}')
"
```

- [ ] **Step 8: Commit**

```bash
git add src/discovery/wordfence_discovery.py src/discovery/__init__.py tests/test_wordfence_discovery.py
git commit -m "feat(sources): add Wordfence Intelligence API discovery

- Implement WordfenceDiscovery class for API access
- Support paginated vulnerability queries
- Extract CVE IDs with WordPress plugin context
- Est. 8.5k CVEs from WordPress security vendor
- Tests with mocked API responses

Part of Phase 2: WordPress ecosystem coverage

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

*Due to length constraints, I'll now save this plan and prepare to dispatch the plan reviewer. The plan continues with more tasks for Phase 2 and Phase 3.*

## Plan Continuation Marker

**Note:** This is Chunk 1 of the implementation plan. Additional chunks will cover:
- Chunk 2: Remaining Phase 2 Part A tasks (WPScan, VulDB)
- Chunk 3: Phase 2 Part B (Activations and GitHub CNA filtering)
- Chunk 4: Phase 3 (Source health monitoring and remaining CNAs)

**Current Status:** Ready for Chunk 1 review and approval before proceeding.
