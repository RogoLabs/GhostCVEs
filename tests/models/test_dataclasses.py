"""
Tests for pipeline dataclasses.

Tests the four main dataclasses used in the 6-stage pipeline:
- DisclosureClassification (Stage 2 output)
- GhostAnalysis (Stage 4 output)
- CNAMetadata (CNA tracking data)
- ProcessedCVE (Complete pipeline output)
"""

import pytest
from datetime import datetime, timedelta
from src.models.enums import (
    DisclosureStatus,
    DisclosureType,
    GhostRootCause,
    CVEStatus,
)
from src.models.dataclasses import (
    DisclosureClassification,
    GhostAnalysis,
    CNAMetadata,
    ProcessedCVE,
)
from src.discovery.base import DiscoveryResult


class TestDisclosureClassification:
    """Tests for DisclosureClassification dataclass."""

    def test_basic_construction(self):
        """Test basic construction with all required fields."""
        disc = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="CVE ID mentioned with full details in security advisory"
        )
        assert disc.status == DisclosureStatus.PUBLIC
        assert disc.disclosure_type == DisclosureType.ADVISORY
        assert disc.confidence == 0.95
        assert "security advisory" in disc.reasoning

    def test_confidence_validation(self):
        """Test that confidence is in valid range."""
        # Valid confidences
        for conf in [0.0, 0.5, 0.99, 1.0]:
            disc = DisclosureClassification(
                status=DisclosureStatus.MENTIONED_ONLY,
                disclosure_type=DisclosureType.PATCH_NOTES,
                confidence=conf,
                reasoning="test"
            )
            assert disc.confidence == conf

    def test_all_status_types(self):
        """Test all DisclosureStatus values."""
        for status in DisclosureStatus:
            disc = DisclosureClassification(
                status=status,
                disclosure_type=DisclosureType.OTHER,
                confidence=0.5,
                reasoning="test"
            )
            assert disc.status == status

    def test_all_disclosure_types(self):
        """Test all DisclosureType values."""
        for disc_type in DisclosureType:
            disc = DisclosureClassification(
                status=DisclosureStatus.PUBLIC,
                disclosure_type=disc_type,
                confidence=0.5,
                reasoning="test"
            )
            assert disc.disclosure_type == disc_type

    def test_repr_and_str(self):
        """Test string representations."""
        disc = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.EXPLOIT,
            confidence=0.85,
            reasoning="Exploit code published"
        )
        # Should have useful repr
        repr_str = repr(disc)
        assert "DisclosureClassification" in repr_str or "PUBLIC" in repr_str


class TestGhostAnalysis:
    """Tests for GhostAnalysis dataclass."""

    def test_basic_construction_ghost_true(self):
        """Test construction when is_ghost=True."""
        analysis = GhostAnalysis(
            cve_id="CVE-2025-12345",
            is_ghost=True,
            confidence=0.88,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=timedelta(hours=2),
            source_confidence_avg=0.92,
            reasoning="CVE in multiple sources, RESERVED status past 6h grace period"
        )
        assert analysis.cve_id == "CVE-2025-12345"
        assert analysis.is_ghost is True
        assert analysis.confidence == 0.88
        assert analysis.grace_period_remaining == timedelta(hours=2)

    def test_basic_construction_ghost_false(self):
        """Test construction when is_ghost=False."""
        analysis = GhostAnalysis(
            cve_id="CVE-2025-99999",
            is_ghost=False,
            confidence=0.05,
            disclosure_status=DisclosureStatus.UNCERTAIN,
            grace_period_remaining=None,
            source_confidence_avg=0.50,
            reasoning="Within grace period or too few sources"
        )
        assert analysis.cve_id == "CVE-2025-99999"
        assert analysis.is_ghost is False
        assert analysis.grace_period_remaining is None

    def test_grace_period_can_be_none(self):
        """Test that grace_period_remaining can be None."""
        analysis = GhostAnalysis(
            cve_id="CVE-2025-12345",
            is_ghost=True,
            confidence=0.90,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,  # Past grace period
            source_confidence_avg=0.95,
            reasoning="Grace period expired"
        )
        assert analysis.grace_period_remaining is None

    def test_grace_period_as_timedelta(self):
        """Test that grace_period_remaining accepts timedelta."""
        grace = timedelta(hours=3, minutes=30)
        analysis = GhostAnalysis(
            cve_id="CVE-2025-12345",
            is_ghost=True,
            confidence=0.80,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=grace,
            source_confidence_avg=0.85,
            reasoning="test"
        )
        assert analysis.grace_period_remaining == grace
        assert analysis.grace_period_remaining.total_seconds() > 0

    def test_confidence_range(self):
        """Test various confidence values."""
        for conf in [0.0, 0.60, 0.75, 1.0]:
            analysis = GhostAnalysis(
                cve_id="CVE-2025-12345",
                is_ghost=(conf >= 0.60),
                confidence=conf,
                disclosure_status=DisclosureStatus.PUBLIC,
                grace_period_remaining=None,
                source_confidence_avg=0.80,
                reasoning="test"
            )
            assert analysis.confidence == conf

    def test_all_disclosure_status_values(self):
        """Test all DisclosureStatus values in GhostAnalysis."""
        for status in DisclosureStatus:
            analysis = GhostAnalysis(
                cve_id="CVE-2025-12345",
                is_ghost=True,
                confidence=0.80,
                disclosure_status=status,
                grace_period_remaining=None,
                source_confidence_avg=0.80,
                reasoning="test"
            )
            assert analysis.disclosure_status == status


class TestCNAMetadata:
    """Tests for CNAMetadata dataclass."""

    def test_basic_construction(self):
        """Test basic construction with required fields."""
        metadata = CNAMetadata(
            cna_name="mitre",
            avg_publication_lag_days=3.5,
            reliability_score=0.95,
            total_cves_tracked=1000,
            id_ranges={
                2000: (2000, 2999),
                3000: (3000, 3999),
            }
        )
        assert metadata.cna_name == "mitre"
        assert metadata.avg_publication_lag_days == 3.5
        assert metadata.reliability_score == 0.95
        assert metadata.total_cves_tracked == 1000
        assert len(metadata.id_ranges) == 2

    def test_empty_id_ranges(self):
        """Test construction with empty ID ranges."""
        metadata = CNAMetadata(
            cna_name="unknown_cna",
            avg_publication_lag_days=0.0,
            reliability_score=0.75,
            total_cves_tracked=0,
            id_ranges={}
        )
        assert metadata.id_ranges == {}

    def test_id_ranges_structure(self):
        """Test ID ranges dictionary structure."""
        ranges = {
            2000: (2000, 2999),
            3000: (3000, 3999),
            4000: (4000, 4999),
        }
        metadata = CNAMetadata(
            cna_name="test",
            avg_publication_lag_days=5.0,
            reliability_score=0.80,
            total_cves_tracked=3000,
            id_ranges=ranges
        )
        assert metadata.id_ranges == ranges
        # Verify structure
        for key, (start, end) in metadata.id_ranges.items():
            assert isinstance(key, int)
            assert isinstance(start, int)
            assert isinstance(end, int)
            assert start <= end

    def test_large_cve_count(self):
        """Test with large CVE tracking counts."""
        metadata = CNAMetadata(
            cna_name="microsoft",
            avg_publication_lag_days=7.0,
            reliability_score=0.90,
            total_cves_tracked=50000,
            id_ranges={}
        )
        assert metadata.total_cves_tracked == 50000

    def test_known_cna_example(self):
        """Test with example of known CNA (Microsoft)."""
        metadata = CNAMetadata(
            cna_name="microsoft",
            avg_publication_lag_days=7.0,
            reliability_score=0.90,
            total_cves_tracked=5000,
            id_ranges={
                2014: (2014, 3000),
                3001: (3001, 3500),
            }
        )
        assert "microsoft" in metadata.cna_name.lower()
        assert metadata.avg_publication_lag_days > 0


class TestProcessedCVE:
    """Tests for ProcessedCVE dataclass."""

    def test_basic_construction(self):
        """Test construction with minimal required fields."""
        # Create required components
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="rss_feed",
            source_name="ZDI Advisories",
            evidence_url="https://example.com/cve-2025-12345"
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Full disclosure in ZDI advisory"
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-12345",
            is_ghost=True,
            confidence=0.88,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.92,
            reasoning="Meets all ghost criteria"
        )

        root_cause = GhostRootCause.CNA_DELAY

        processed = ProcessedCVE(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            root_cause=root_cause
        )

        assert processed.cve_id == "CVE-2025-12345"
        assert processed.discovery == discovery
        assert processed.disclosure == disclosure
        assert processed.ghost_analysis == ghost_analysis
        assert processed.root_cause == GhostRootCause.CNA_DELAY

    def test_root_cause_can_be_none(self):
        """Test that root_cause can be None for non-ghosts."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-99999",
            source_type="rss_feed",
            source_name="NVD",
            evidence_url="https://nvd.nist.gov/vuln/detail/CVE-2025-99999"
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.UNCERTAIN,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.50,
            reasoning="Unclear disclosure context"
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-99999",
            is_ghost=False,
            confidence=0.30,
            disclosure_status=DisclosureStatus.UNCERTAIN,
            grace_period_remaining=None,
            source_confidence_avg=0.50,
            reasoning="Not meeting ghost criteria"
        )

        processed = ProcessedCVE(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            root_cause=None
        )

        assert processed.root_cause is None
        assert processed.is_ghost is False

    def test_is_ghost_property(self):
        """Test is_ghost property returns correct value."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="rss_feed",
            source_name="Test",
            evidence_url="https://example.com"
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.90,
            reasoning="test"
        )

        # Ghost case
        ghost_analysis_true = GhostAnalysis(
            cve_id="CVE-2025-12345",
            is_ghost=True,
            confidence=0.85,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.90,
            reasoning="test"
        )

        processed_ghost = ProcessedCVE(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis_true,
            root_cause=GhostRootCause.VENDOR_FAILURE
        )
        assert processed_ghost.is_ghost is True

        # Non-ghost case
        ghost_analysis_false = GhostAnalysis(
            cve_id="CVE-2025-12345",
            is_ghost=False,
            confidence=0.30,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.50,
            reasoning="test"
        )

        processed_non_ghost = ProcessedCVE(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis_false,
            root_cause=None
        )
        assert processed_non_ghost.is_ghost is False

    def test_all_root_causes(self):
        """Test ProcessedCVE with all root cause types."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="rss_feed",
            source_name="Test",
            evidence_url="https://example.com"
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.90,
            reasoning="test"
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-12345",
            is_ghost=True,
            confidence=0.85,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.90,
            reasoning="test"
        )

        for root_cause in GhostRootCause:
            processed = ProcessedCVE(
                discovery=discovery,
                disclosure=disclosure,
                ghost_analysis=ghost_analysis,
                root_cause=root_cause
            )
            assert processed.root_cause == root_cause

    def test_cve_id_property_matches_discovery(self):
        """Test that cve_id property returns discovery's cve_id."""
        cve_id = "CVE-2025-11111"
        discovery = DiscoveryResult(
            cve_id=cve_id,
            source_type="rss_feed",
            source_name="Test",
            evidence_url="https://example.com"
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.90,
            reasoning="test"
        )

        ghost_analysis = GhostAnalysis(
            cve_id=cve_id,
            is_ghost=True,
            confidence=0.85,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.90,
            reasoning="test"
        )

        processed = ProcessedCVE(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            root_cause=None
        )

        assert processed.cve_id == cve_id
        assert processed.cve_id == discovery.cve_id


class TestDataclassesIntegration:
    """Integration tests combining multiple dataclasses."""

    def test_full_pipeline_ghost_example(self):
        """Test a complete ghost detection scenario."""
        # Vendor disclosed CVE but it's still RESERVED in registry
        discovery = DiscoveryResult(
            cve_id="CVE-2025-10001",
            source_type="rss_feed",
            source_name="Microsoft Security Advisory",
            evidence_url="https://msrc.microsoft.com/update-guide",
            context="Security update released",
            confidence=0.98
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.99,
            reasoning="CVE-2025-10001 mentioned in Microsoft patch notes with CVSS score"
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-10001",
            is_ghost=True,
            confidence=0.92,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.98,
            reasoning="RESERVED status despite public patch notes for 2+ days"
        )

        processed = ProcessedCVE(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            root_cause=GhostRootCause.VENDOR_FAILURE
        )

        assert processed.is_ghost is True
        assert processed.cve_id == "CVE-2025-10001"
        assert processed.root_cause == GhostRootCause.VENDOR_FAILURE
        assert processed.ghost_analysis.confidence >= 0.85

    def test_full_pipeline_false_positive_example(self):
        """Test a false positive scenario within grace period."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-20001",
            source_type="rss_feed",
            source_name="Vendor Advisory",
            evidence_url="https://example.com/advisory"
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.85,
            reasoning="CVE mentioned with details in advisory"
        )

        grace_remaining = timedelta(hours=2)
        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-20001",
            is_ghost=False,
            confidence=0.15,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=grace_remaining,
            source_confidence_avg=0.80,
            reasoning="Still within 6-hour grace period for NVD sync"
        )

        processed = ProcessedCVE(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            root_cause=GhostRootCause.SYSTEM_LAG
        )

        assert processed.is_ghost is False
        assert processed.ghost_analysis.grace_period_remaining is not None
        assert processed.ghost_analysis.confidence < 0.60
