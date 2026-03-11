"""Tests for source audit system."""
import pytest
from datetime import datetime, timedelta, timezone
from src.analysis.source_audit import SourceMetrics, calculate_reliability_score, identify_redundant_sources


def test_source_metrics_creation():
    """Test creating SourceMetrics instance."""
    metrics = SourceMetrics(
        source_name="test_source",
        total_discoveries=100,
        ghost_detection_rate=0.75,
        false_positive_rate=0.10,
        avg_time_to_resolution=5.5,
        reliability_score=0.0,  # Will be calculated
        last_successful_fetch=datetime.now(timezone.utc),
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


def test_identify_redundant_sources():
    """Test redundancy detection with Jaccard similarity."""
    # High overlap - should be redundant
    result = identify_redundant_sources(
        {"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"},
        {"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0004"},
        0.50
    )
    assert result == (True, 0.5)

    # Low overlap - should not be redundant
    result = identify_redundant_sources(
        {"CVE-2025-0001", "CVE-2025-0002"},
        {"CVE-2025-0003", "CVE-2025-0004"},
        0.80
    )
    assert result[0] == False

    # Empty sets - should handle gracefully
    result = identify_redundant_sources(set(), {"CVE-2025-0001"}, 0.80)
    assert result == (False, 0.0)
