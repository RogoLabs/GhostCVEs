"""
Test timezone-defensive handling in GhostAnalyzer.

Verifies the analyzer can handle both timezone-naive (old DB data) and
timezone-aware (new data) timestamps without TypeError.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.discovery.base import DiscoveryResult
from src.models.dataclasses import DisclosureClassification
from src.models.enums import DisclosureStatus, DisclosureType, CVEStatus
from src.pipeline.ghost_analyzer import GhostAnalyzer
from src.registry.validator import ValidationResult


def test_normalize_datetime_with_naive():
    """Test _normalize_datetime converts naive to aware."""
    naive_dt = datetime(2026, 3, 11, 12, 0, 0)  # No tzinfo
    normalized = GhostAnalyzer._normalize_datetime(naive_dt)

    assert normalized.tzinfo is not None
    assert normalized.tzinfo == timezone.utc
    assert normalized.year == 2026
    assert normalized.month == 3
    assert normalized.day == 11


def test_normalize_datetime_with_aware():
    """Test _normalize_datetime preserves aware datetimes."""
    aware_dt = datetime(2026, 3, 11, 12, 0, 0, tzinfo=timezone.utc)
    normalized = GhostAnalyzer._normalize_datetime(aware_dt)

    assert normalized.tzinfo is not None
    assert normalized == aware_dt


def test_analyze_with_mixed_naive_and_aware_timestamps():
    """Test analyze() handles mixed naive and aware timestamps from DB."""
    analyzer = GhostAnalyzer(grace_period_hours=6, confidence_threshold=0.60)

    # Simulate old DB data (naive) and new data (aware)
    naive_discovery = DiscoveryResult(
        cve_id="CVE-2026-12345",
        source_type="github_advisory",
        source_name="GitHub Advisory",
        evidence_url="https://github.com/advisories/GHSA-xxxx",
        discovered_at=datetime.now() - timedelta(hours=24),  # Naive (old data)
        context="Test advisory",
        confidence=0.90,
        raw_data={},
    )

    aware_discovery = DiscoveryResult(
        cve_id="CVE-2026-12345",
        source_type="exploit_db",
        source_name="ExploitDB",
        evidence_url="https://exploit-db.com/exploits/12345",
        discovered_at=datetime.now(timezone.utc) - timedelta(hours=12),  # Aware (new data)
        context="Test exploit",
        confidence=0.85,
        raw_data={},
    )

    disclosure = DisclosureClassification(
        status=DisclosureStatus.PUBLIC,
        disclosure_type=DisclosureType.ADVISORY,
        confidence=0.88,
        reasoning="Found in multiple public sources",
    )

    validation = ValidationResult(
        cve_id="CVE-2026-12345",
        status=CVEStatus.RESERVED,
        is_ghost=False,  # Ghost analyzer will determine this
        registry_source="nvd_local",
        description=None,
        published_date=None,
    )

    # This should NOT raise TypeError even with mixed timestamps
    result = analyzer.analyze(
        discoveries=[naive_discovery, aware_discovery],
        disclosure=disclosure,
        validation=validation,
    )

    # Verify analysis completed successfully
    assert result.cve_id == "CVE-2026-12345"
    assert result.is_ghost is True  # Past grace period, reserved, high confidence
    assert result.confidence > 0.6


def test_analyze_with_all_naive_timestamps():
    """Test analyze() handles all naive timestamps (old DB state)."""
    analyzer = GhostAnalyzer(grace_period_hours=6, confidence_threshold=0.60)

    # Simulate old DB state where all timestamps are naive
    discovery1 = DiscoveryResult(
        cve_id="CVE-2026-54321",
        source_type="vendor_advisory",
        source_name="Vendor Advisory",
        evidence_url="https://vendor.com/advisory/123",
        discovered_at=datetime.now() - timedelta(hours=48),  # Naive
        context="Security advisory",
        confidence=0.95,
        raw_data={},
    )

    discovery2 = DiscoveryResult(
        cve_id="CVE-2026-54321",
        source_type="github_commit",
        source_name="GitHub Commit",
        evidence_url="https://github.com/user/repo/commit/abc123",
        discovered_at=datetime.now() - timedelta(hours=36),  # Naive
        context="Fix commit",
        confidence=0.80,
        raw_data={},
    )

    disclosure = DisclosureClassification(
        status=DisclosureStatus.PUBLIC,
        disclosure_type=DisclosureType.ADVISORY,
        confidence=0.90,
        reasoning="Public sources",
    )

    validation = ValidationResult(
        cve_id="CVE-2026-54321",
        status=CVEStatus.NOT_FOUND,
        is_ghost=False,  # Ghost analyzer will determine this
        registry_source="nvd_api",
        description=None,
        published_date=None,
    )

    # Should NOT raise TypeError with all naive timestamps
    result = analyzer.analyze(
        discoveries=[discovery1, discovery2],
        disclosure=disclosure,
        validation=validation,
    )

    assert result.cve_id == "CVE-2026-54321"
    assert result.is_ghost is True


def test_analyze_with_all_aware_timestamps():
    """Test analyze() handles all aware timestamps (new code)."""
    analyzer = GhostAnalyzer(grace_period_hours=6, confidence_threshold=0.60)

    # Simulate new code state where all timestamps are aware
    discovery1 = DiscoveryResult(
        cve_id="CVE-2026-99999",
        source_type="cert",
        source_name="CERT",
        evidence_url="https://cert.org/advisory/123",
        discovered_at=datetime.now(timezone.utc) - timedelta(hours=72),
        context="CERT advisory",
        confidence=0.95,
        raw_data={},
    )

    discovery2 = DiscoveryResult(
        cve_id="CVE-2026-99999",
        source_type="cve_org",
        source_name="CVE.org",
        evidence_url="https://cve.org/CVERecord?id=CVE-2026-99999",
        discovered_at=datetime.now(timezone.utc) - timedelta(hours=60),
        context="CVE record",
        confidence=1.0,
        raw_data={},
    )

    disclosure = DisclosureClassification(
        status=DisclosureStatus.PUBLIC,
        disclosure_type=DisclosureType.ADVISORY,
        confidence=0.98,
        reasoning="Official sources",
    )

    validation = ValidationResult(
        cve_id="CVE-2026-99999",
        status=CVEStatus.RESERVED,
        is_ghost=False,  # Ghost analyzer will determine this
        registry_source="cve_org",
        description=None,
        published_date=None,
    )

    # Should work perfectly with all aware timestamps
    result = analyzer.analyze(
        discoveries=[discovery1, discovery2],
        disclosure=disclosure,
        validation=validation,
    )

    assert result.cve_id == "CVE-2026-99999"
    assert result.is_ghost is True
