"""
Tests for Ghost Analyzer (Stage 4 of pipeline).

Tests the GhostAnalyzer that determines if a CVE is a ghost with confidence
scoring and grace period tracking. Critical: 6-hour grace period, not 30 days.

Author: rogolabs.net
"""

import pytest
from datetime import datetime, timedelta
from src.pipeline.ghost_analyzer import GhostAnalyzer, SourceReliabilityTracker
from src.models.enums import DisclosureStatus, DisclosureType, CVEStatus
from src.models.dataclasses import DisclosureClassification, GhostAnalysis
from src.discovery.base import DiscoveryResult
from src.registry.validator import ValidationResult


@pytest.fixture
def analyzer():
    """Create a GhostAnalyzer instance for testing."""
    return GhostAnalyzer()


@pytest.fixture
def reliability_tracker():
    """Create a SourceReliabilityTracker stub for testing."""
    return SourceReliabilityTracker()


class TestGhostAnalyzerBasic:
    """Test basic functionality of GhostAnalyzer."""

    def test_initialization(self, analyzer):
        """Test that analyzer initializes properly."""
        assert analyzer is not None
        assert analyzer.grace_period_hours == 6  # Critical: 6 hours, not 30 days
        assert analyzer.confidence_threshold == 0.60
        assert analyzer.reliability_tracker is not None

    def test_returns_ghost_analysis(self, analyzer):
        """Test that analyze returns GhostAnalysis object."""
        # Create test data
        discovery = DiscoveryResult(
            cve_id="CVE-2025-1234",
            source_type="github_commit",
            source_name="test-repo",
            evidence_url="https://github.com/test/repo/commit/abc123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Fix CVE-2025-1234: buffer overflow in parser",
            confidence=0.85
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.80,
            reasoning="Patch indicators found"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze(
            discoveries=[discovery],
            disclosure=disclosure,
            validation=validation
        )

        assert isinstance(result, GhostAnalysis)
        assert result.cve_id == "CVE-2025-1234"
        assert isinstance(result.is_ghost, bool)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.reasoning, str)
        assert len(result.reasoning) > 0


class TestGhostDetectionRules:
    """Test ghost detection rules: PUBLIC + (RESERVED|NOT_FOUND) + past 6hr + confidence >= 60%."""

    def test_ghost_reserved_past_grace_high_confidence(self, analyzer):
        """Test: PUBLIC + RESERVED + past 6hr grace + high confidence = GHOST."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2001",
            source_type="vendor_advisory",
            source_name="Microsoft Security",
            evidence_url="https://msrc.microsoft.com/update-guide/CVE-2025-2001",
            discovered_at=datetime.utcnow() - timedelta(hours=12),  # 12 hours old
            context="CVE-2025-2001: Remote code execution vulnerability in Windows RDP",
            confidence=0.95
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.90,
            reasoning="Official advisory with vuln description"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2001",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is True
        assert result.confidence >= 0.60
        assert result.grace_period_remaining is None  # Past grace period
        assert "ghost" in result.reasoning.lower()

    def test_ghost_not_found_past_grace_high_confidence(self, analyzer):
        """Test: PUBLIC + NOT_FOUND + past 6hr grace + high confidence = GHOST."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2002",
            source_type="github_security_advisory",
            source_name="apache/struts",
            evidence_url="https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            discovered_at=datetime.utcnow() - timedelta(hours=24),  # 24 hours old
            context="CVE-2025-2002: SQL injection in Struts framework",
            confidence=0.90
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.85,
            reasoning="GitHub security advisory with details"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2002",
            status=CVEStatus.NOT_FOUND,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is True
        assert result.confidence >= 0.60
        assert result.grace_period_remaining is None

    def test_not_ghost_within_grace_period(self, analyzer):
        """Test: Within 6hr grace period = NOT GHOST (regardless of other factors)."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2003",
            source_type="vendor_advisory",
            source_name="Cisco Security",
            evidence_url="https://sec.cloudapps.cisco.com/security/CVE-2025-2003",
            discovered_at=datetime.utcnow() - timedelta(hours=3),  # 3 hours old - within grace
            context="CVE-2025-2003: Critical vulnerability in IOS XE",
            confidence=0.95
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Official vendor advisory"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2003",
            status=CVEStatus.RESERVED,
            is_ghost=True,  # Validator says ghost, but we should override due to grace period
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is False  # NOT a ghost due to grace period
        assert result.grace_period_remaining is not None
        assert result.grace_period_remaining.total_seconds() > 0
        assert "grace period" in result.reasoning.lower()

    def test_not_ghost_mentioned_only_status(self, analyzer):
        """Test: MENTIONED_ONLY status = NOT GHOST."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2004",
            source_type="social_media",
            source_name="Twitter",
            evidence_url="https://twitter.com/user/status/123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Just heard about CVE-2025-2004",
            confidence=0.50
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.MENTIONED_ONLY,  # Not PUBLIC
            disclosure_type=DisclosureType.OTHER,
            confidence=0.45,
            reasoning="CVE mentioned but no details"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2004",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is False
        assert "not public disclosure" in result.reasoning.lower()

    def test_not_ghost_published_status(self, analyzer):
        """Test: PUBLISHED validation status = NOT GHOST."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2005",
            source_type="vendor_advisory",
            source_name="RedHat Security",
            evidence_url="https://access.redhat.com/security/cve/CVE-2025-2005",
            discovered_at=datetime.utcnow() - timedelta(hours=48),
            context="CVE-2025-2005: Privilege escalation in kernel",
            confidence=0.90
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.88,
            reasoning="Official advisory"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2005",
            status=CVEStatus.PUBLISHED,  # Published, not reserved
            is_ghost=False,
            registry_source="CVE_ORG",
            description="Linux kernel privilege escalation",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is False
        assert "published" in result.reasoning.lower()

    def test_not_ghost_low_confidence(self, analyzer):
        """Test: Confidence < 60% = NOT GHOST."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2006",
            source_type="blog",
            source_name="Personal Blog",
            evidence_url="https://blog.example.com/post/123",
            discovered_at=datetime.utcnow() - timedelta(hours=24),
            context="CVE-2025-2006 might be relevant",
            confidence=0.30
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.35,  # Low confidence
            reasoning="Minimal context, low quality source"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2006",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        # Even though validation says ghost, low confidence should prevent classification
        assert result.is_ghost is False
        assert result.confidence < 0.60
        assert "confidence" in result.reasoning.lower()


class TestConfidenceScoring:
    """Test confidence score calculation with source reliability weighting."""

    def test_high_confidence_official_source(self, analyzer):
        """Test high confidence with official high-reliability source."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-3001",
            source_type="vendor_advisory",
            source_name="Microsoft Security Response",
            evidence_url="https://msrc.microsoft.com/update-guide/CVE-2025-3001",
            discovered_at=datetime.utcnow() - timedelta(days=7),  # 7 days old
            context="CVE-2025-3001: Critical RCE in Windows. Patch available.",
            confidence=0.95
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.92,
            reasoning="Official vendor advisory with patch"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-3001",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is True
        assert result.confidence >= 0.85  # High confidence expected
        assert result.source_confidence_avg >= 0.90

    def test_multiple_sources_boost(self, analyzer):
        """Test confidence boost for multiple corroborating sources."""
        # Two discoveries of the same CVE
        discovery1 = DiscoveryResult(
            cve_id="CVE-2025-3002",
            source_type="vendor_advisory",
            source_name="RedHat Security",
            evidence_url="https://access.redhat.com/security/cve/CVE-2025-3002",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-3002: Buffer overflow in glibc",
            confidence=0.85
        )

        discovery2 = DiscoveryResult(
            cve_id="CVE-2025-3002",
            source_type="github_commit",
            source_name="glibc/glibc",
            evidence_url="https://github.com/glibc/glibc/commit/xyz",
            discovered_at=datetime.utcnow() - timedelta(hours=10),
            context="Fix CVE-2025-3002: heap overflow in malloc",
            confidence=0.80
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.82,
            reasoning="Multiple sources with patch details"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-3002",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        # Single source
        result_single = analyzer.analyze([discovery1], disclosure, validation)

        # Multiple sources
        result_multiple = analyzer.analyze([discovery1, discovery2], disclosure, validation)

        # Multiple sources should have higher confidence
        assert result_multiple.confidence > result_single.confidence
        assert ("multiple sources" in result_multiple.reasoning.lower() or
                "independent sources" in result_multiple.reasoning.lower())

    def test_age_boost_for_older_ghosts(self, analyzer):
        """Test confidence boost for older ghosts (7+ days)."""
        # Recent discovery
        discovery_recent = DiscoveryResult(
            cve_id="CVE-2025-3003",
            source_type="vendor_advisory",
            source_name="Vendor",
            evidence_url="https://vendor.com/advisory",
            discovered_at=datetime.utcnow() - timedelta(hours=8),  # 8 hours old
            context="CVE-2025-3003: Security vulnerability",
            confidence=0.80
        )

        # Old discovery
        discovery_old = DiscoveryResult(
            cve_id="CVE-2025-3004",
            source_type="vendor_advisory",
            source_name="Vendor",
            evidence_url="https://vendor.com/advisory2",
            discovered_at=datetime.utcnow() - timedelta(days=10),  # 10 days old
            context="CVE-2025-3004: Security vulnerability",
            confidence=0.80
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.78,
            reasoning="Vendor advisory"
        )

        validation_recent = ValidationResult(
            cve_id="CVE-2025-3003",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        validation_old = ValidationResult(
            cve_id="CVE-2025-3004",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result_recent = analyzer.analyze([discovery_recent], disclosure, validation_recent)
        result_old = analyzer.analyze([discovery_old], disclosure, validation_old)

        # Older ghost should have higher confidence boost
        assert result_old.confidence > result_recent.confidence

    def test_mailing_list_penalty(self, analyzer):
        """Test confidence penalty for mailing-list-only sources."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-3005",
            source_type="mailing_list",
            source_name="oss-security",
            evidence_url="https://seclists.org/oss-sec/2025/q1/123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-3005: Vulnerability discovered in package X",
            confidence=0.70
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.68,
            reasoning="Mailing list disclosure"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-3005",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        # Should have penalty applied
        assert result.confidence < 0.70  # Below source confidence due to mailing list penalty


class TestGracePeriodCalculation:
    """Test grace period calculation and remaining time tracking."""

    def test_grace_period_calculation_within(self, analyzer):
        """Test grace period remaining calculation when within grace period."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-4001",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/abc",
            discovered_at=datetime.utcnow() - timedelta(hours=2),  # 2 hours ago
            context="Fix CVE-2025-4001",
            confidence=0.80
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.75,
            reasoning="Patch notes"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-4001",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is False  # Within grace period
        assert result.grace_period_remaining is not None
        # Should have approximately 4 hours remaining (6 - 2)
        remaining_hours = result.grace_period_remaining.total_seconds() / 3600
        assert 3.5 <= remaining_hours <= 4.5

    def test_grace_period_calculation_past(self, analyzer):
        """Test grace period remaining is None when past grace period."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-4002",
            source_type="vendor_advisory",  # High reliability source
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/def",
            discovered_at=datetime.utcnow() - timedelta(hours=10),  # 10 hours ago
            context="Fix CVE-2025-4002: security vulnerability with details",
            confidence=0.90
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.85,
            reasoning="Patch notes with vulnerability details"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-4002",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is True  # Past grace period
        assert result.grace_period_remaining is None

    def test_grace_period_uses_oldest_discovery(self, analyzer):
        """Test that grace period is calculated from oldest discovery."""
        # Older discovery
        discovery1 = DiscoveryResult(
            cve_id="CVE-2025-4003",
            source_type="github_commit",
            source_name="repo1",
            evidence_url="https://github.com/repo1/commit/abc",
            discovered_at=datetime.utcnow() - timedelta(hours=8),  # 8 hours ago
            context="Fix CVE-2025-4003",
            confidence=0.80
        )

        # Newer discovery
        discovery2 = DiscoveryResult(
            cve_id="CVE-2025-4003",
            source_type="vendor_advisory",
            source_name="Vendor",
            evidence_url="https://vendor.com/advisory",
            discovered_at=datetime.utcnow() - timedelta(hours=2),  # 2 hours ago
            context="CVE-2025-4003: vulnerability details",
            confidence=0.90
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.85,
            reasoning="Advisory with details"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-4003",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery1, discovery2], disclosure, validation)

        # Should be past grace period based on oldest discovery (8 hours > 6 hours)
        assert result.is_ghost is True
        assert result.grace_period_remaining is None


class TestReasoningQuality:
    """Test that reasoning strings are informative and accurate."""

    def test_reasoning_explains_ghost_decision(self, analyzer):
        """Test that reasoning explains why CVE is classified as ghost."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-5001",
            source_type="vendor_advisory",
            source_name="Cisco",
            evidence_url="https://sec.cloudapps.cisco.com/security/CVE-2025-5001",
            discovered_at=datetime.utcnow() - timedelta(days=5),
            context="CVE-2025-5001: Critical RCE vulnerability",
            confidence=0.95
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.92,
            reasoning="Official vendor advisory"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-5001",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        reasoning_lower = result.reasoning.lower()
        assert len(result.reasoning) > 30
        # Should mention key ghost factors
        assert "public" in reasoning_lower or "disclosed" in reasoning_lower
        assert "reserved" in reasoning_lower or "not found" in reasoning_lower
        assert result.is_ghost is True

    def test_reasoning_explains_non_ghost_decision(self, analyzer):
        """Test that reasoning explains why CVE is NOT a ghost."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-5002",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/xyz",
            discovered_at=datetime.utcnow() - timedelta(hours=2),  # Within grace
            context="Fix CVE-2025-5002",
            confidence=0.85
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.80,
            reasoning="Patch notes"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-5002",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze([discovery], disclosure, validation)

        assert result.is_ghost is False
        reasoning_lower = result.reasoning.lower()
        assert "grace period" in reasoning_lower


class TestSourceReliabilityTracker:
    """Test SourceReliabilityTracker stub (full version in Chunk 8)."""

    def test_tracker_initialization(self, reliability_tracker):
        """Test that tracker initializes as stub."""
        assert reliability_tracker is not None

    def test_get_source_reliability_returns_default(self, reliability_tracker):
        """Test that stub returns default reliability scores."""
        # Should return reasonable defaults
        reliability = reliability_tracker.get_source_reliability("vendor_advisory")
        assert 0.0 <= reliability <= 1.0

        reliability2 = reliability_tracker.get_source_reliability("social_media")
        assert 0.0 <= reliability2 <= 1.0

        # Official sources should have higher reliability than social media
        official = reliability_tracker.get_source_reliability("vendor_advisory")
        social = reliability_tracker.get_source_reliability("social_media")
        assert official >= social

    def test_is_high_quality_source(self, reliability_tracker):
        """Test high quality source detection."""
        # Official sources should be high quality
        assert reliability_tracker.is_high_quality_source("vendor_advisory") is True
        assert reliability_tracker.is_high_quality_source("security_advisory") is True
        assert reliability_tracker.is_high_quality_source("cve_org") is True

        # Social media should not be high quality
        assert reliability_tracker.is_high_quality_source("social_media") is False
        assert reliability_tracker.is_high_quality_source("blog") is False


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_discoveries_list(self, analyzer):
        """Test handling of empty discoveries list."""
        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.70,
            reasoning="Public disclosure"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-6001",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        # Should handle empty list gracefully
        with pytest.raises(ValueError, match="at least one discovery"):
            analyzer.analyze([], disclosure, validation)

    def test_mismatched_cve_ids(self, analyzer):
        """Test handling of mismatched CVE IDs."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-6002",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/abc",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Fix CVE-2025-6002",
            confidence=0.80
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.75,
            reasoning="Patch notes"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-9999",  # Different CVE ID
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        # Should raise error for mismatched IDs
        with pytest.raises(ValueError, match="CVE ID mismatch"):
            analyzer.analyze([discovery], disclosure, validation)

    def test_confidence_capped_at_100_percent(self, analyzer):
        """Test that confidence is capped at 1.0."""
        # Create scenario with many boosting factors
        discoveries = [
            DiscoveryResult(
                cve_id="CVE-2025-6003",
                source_type="vendor_advisory",
                source_name=f"Vendor{i}",
                evidence_url=f"https://vendor{i}.com/advisory",
                discovered_at=datetime.utcnow() - timedelta(days=30),  # Very old
                context="CVE-2025-6003: Critical security vulnerability with full details",
                confidence=0.99
            )
            for i in range(5)  # 5 sources
        ]

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.99,
            reasoning="Multiple official advisories"
        )

        validation = ValidationResult(
            cve_id="CVE-2025-6003",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow()
        )

        result = analyzer.analyze(discoveries, disclosure, validation)

        # Confidence should not exceed 1.0
        assert result.confidence <= 1.0
        assert result.is_ghost is True
