"""Tests for audit report generation."""
import pytest
from datetime import datetime, timezone
from src.analysis.source_audit import (
    SourceMetrics,
    generate_audit_report,
    classify_source
)


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
            last_successful_fetch=datetime.now(timezone.utc),
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
            last_successful_fetch=datetime.now(timezone.utc),
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


def test_classify_source_keep():
    """Test classification of high-quality source."""
    result = classify_source(0.85, 100, 0.02)
    assert result == "Keep"


def test_classify_source_optimize():
    """Test classification of medium-quality source."""
    result = classify_source(0.70, 50, 0.10)
    assert result == "Optimize"


def test_classify_source_remove_low_reliability():
    """Test classification of low-reliability source."""
    result = classify_source(0.50, 20, 0.10)
    assert result == "Remove"


def test_classify_source_remove_few_discoveries():
    """Test classification of source with few discoveries."""
    result = classify_source(0.90, 3, 0.05)
    assert result == "Remove"


def test_classify_source_remove_high_failure_rate():
    """Test classification of source with high failure rate."""
    result = classify_source(0.85, 100, 0.25)
    assert result == "Remove"
