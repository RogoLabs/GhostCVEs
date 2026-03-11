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
        false_positive_rate=0.10,  # Not used in scoring
        fetch_reliability=0.95,
        unique_discoveries_ratio=0.20
    )

    # Should be weighted: 0.80*0.6 + 0.20*0.3 + 0.95*0.1
    # = 0.48 + 0.06 + 0.095 = 0.635
    assert 0.63 <= score <= 0.64


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


def test_source_auditor_initialization():
    """Test SourceAuditor can be initialized with database."""
    from unittest.mock import Mock
    from src.analysis.source_audit import SourceAuditor

    mock_db = Mock()
    auditor = SourceAuditor(mock_db)

    assert auditor.db == mock_db


def test_collect_source_metrics_from_database():
    """Test collecting metrics from database."""
    from unittest.mock import Mock
    from src.analysis.source_audit import SourceAuditor

    # Mock DatabaseManager
    mock_db = Mock()
    mock_db.get_source_discoveries.return_value = [
        {
            "cve_id": "CVE-2025-0001",
            "is_ghost": True,
            "discovered_at": "2025-01-01T00:00:00",
            "registry_status": "RESERVED"
        },
        {
            "cve_id": "CVE-2025-0002",
            "is_ghost": False,
            "discovered_at": "2025-01-02T00:00:00",
            "registry_status": "PUBLISHED"
        }
    ]
    mock_db.get_source_resolution_history.return_value = [
        {"cve_id": "CVE-2025-0001", "resolution_days": 5.0, "was_true_ghost": True}
    ]
    mock_db.get_all_sources.return_value = ["test_rss", "other_source"]
    mock_db.get_source_discoveries.side_effect = [
        # First call for test_rss
        [
            {"cve_id": "CVE-2025-0001", "is_ghost": True, "discovered_at": "2025-01-01T00:00:00", "registry_status": "RESERVED"},
            {"cve_id": "CVE-2025-0002", "is_ghost": False, "discovered_at": "2025-01-02T00:00:00", "registry_status": "PUBLISHED"}
        ],
        # Second call for other_source (for unique CVE calculation)
        [{"cve_id": "CVE-2025-0003", "is_ghost": True, "discovered_at": "2025-01-03T00:00:00", "registry_status": "RESERVED"}]
    ]

    auditor = SourceAuditor(mock_db)
    metrics = auditor.collect_source_metrics("test_rss")

    assert metrics.source_name == "test_rss"
    assert metrics.total_discoveries == 2
    assert metrics.ghost_detection_rate == 0.5  # 1 of 2 was ghost
    assert metrics.false_positive_rate == 0.5  # 1 of 2 was already PUBLISHED
    assert metrics.avg_time_to_resolution == 5.0


def test_collect_source_metrics_no_data():
    """Test collecting metrics for source with no data."""
    from unittest.mock import Mock
    from src.analysis.source_audit import SourceAuditor

    mock_db = Mock()
    mock_db.get_source_discoveries.return_value = []

    auditor = SourceAuditor(mock_db)
    metrics = auditor.collect_source_metrics("empty_source")

    assert metrics.source_name == "empty_source"
    assert metrics.total_discoveries == 0
    assert metrics.ghost_detection_rate == 0.0
    assert metrics.reliability_score == 0.0


def test_audit_all_sources():
    """Test auditing all sources returns list of metrics sorted by reliability."""
    from unittest.mock import Mock
    from src.analysis.source_audit import SourceAuditor, SourceMetrics

    mock_db = Mock()
    mock_db.get_all_sources.return_value = ["source1", "source2"]
    mock_db.get_source_discoveries.side_effect = [
        # source1 - high reliability
        [{"cve_id": "CVE-2025-0001", "is_ghost": True, "discovered_at": "2025-01-01T00:00:00", "registry_status": "RESERVED"}] * 10,
        [{"cve_id": "CVE-2025-0010", "is_ghost": True, "discovered_at": "2025-01-01T00:00:00", "registry_status": "RESERVED"}] * 5,
        # source2 - low reliability
        [{"cve_id": "CVE-2025-0020", "is_ghost": False, "discovered_at": "2025-01-01T00:00:00", "registry_status": "PUBLISHED"}] * 10,
        [{"cve_id": "CVE-2025-0030", "is_ghost": False, "discovered_at": "2025-01-01T00:00:00", "registry_status": "PUBLISHED"}] * 5,
    ]
    mock_db.get_source_resolution_history.return_value = []

    auditor = SourceAuditor(mock_db)
    all_metrics = auditor.audit_all_sources()

    assert len(all_metrics) == 2
    assert all(isinstance(m, SourceMetrics) for m in all_metrics)
    # Should be sorted by reliability score (highest first)
    assert all_metrics[0].reliability_score >= all_metrics[1].reliability_score
