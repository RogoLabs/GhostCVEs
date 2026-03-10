"""
Tests for Root Cause Detector (Stage 5 of pipeline).

Tests the RootCauseDetector that determines why a CVE is a ghost with
priority-based root cause classification:

1. FAKE_CVE: ID >100k, all same digit pattern, invalid year, only unreliable sources
2. EMBARGO: Keywords (embargo, coordinated disclosure, upcoming, scheduled for, etc.)
3. CNA_DELAY: CNA avg_publication_lag_days > 14
4. VENDOR_FAILURE: Vendor source (MSRC, PSIRT, Security Advisory, Security Bulletin) + RESERVED
5. SYSTEM_LAG: NOT_FOUND + grace_period_remaining not None
6. UNKNOWN: Default

Author: rogolabs.net
"""

import pytest
from datetime import datetime, timedelta
from src.pipeline.root_cause_detector import RootCauseDetector
from src.models.enums import DisclosureStatus, DisclosureType, GhostRootCause, CVEStatus
from src.models.dataclasses import (
    DisclosureClassification,
    GhostAnalysis,
    CNAMetadata,
    ProcessedCVE,
)
from src.discovery.base import DiscoveryResult
from src.registry.validator import ValidationResult


@pytest.fixture
def detector():
    """Create a RootCauseDetector instance for testing."""
    return RootCauseDetector()


@pytest.fixture
def cna_registry():
    """Create a sample CNA registry for testing."""
    return {
        "mitre": CNAMetadata(
            cna_name="mitre",
            avg_publication_lag_days=7.5,
            reliability_score=0.95,
            total_cves_tracked=10000,
            id_ranges={2025: (1000, 3000), 2026: (3000, 5000)},
        ),
        "slow_cna": CNAMetadata(
            cna_name="slow_cna",
            avg_publication_lag_days=20.0,  # Above 14-day threshold
            reliability_score=0.70,
            total_cves_tracked=500,
            id_ranges={2025: (100, 200)},
        ),
    }


class TestRootCauseDetectorBasic:
    """Test basic functionality of RootCauseDetector."""

    def test_initialization(self, detector):
        """Test that detector initializes properly."""
        assert detector is not None

    def test_returns_root_cause(self, detector):
        """Test that detect returns GhostRootCause enum or None."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-1234",
            source_type="vendor_advisory",
            source_name="Microsoft MSRC",
            evidence_url="https://msrc.microsoft.com/update-guide/CVE-2025-1234",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-1234: Buffer overflow in Windows",
            confidence=0.95,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.90,
            reasoning="Official vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-1234",
            is_ghost=True,
            confidence=0.85,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.90,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        # Result should be either GhostRootCause or None (if not ghost)
        assert result is None or isinstance(result, GhostRootCause)


class TestFakeCVEDetection:
    """Test FAKE_CVE root cause detection."""

    def test_fake_cve_id_over_100k(self, detector):
        """Test: ID > 100,000 = FAKE_CVE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-999999",  # Way too high
            source_type="social_media",
            source_name="Twitter",
            evidence_url="https://twitter.com/user/status/123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-999999",
            confidence=0.40,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.40,
            reasoning="Mentioned on social media",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-999999",
            is_ghost=True,
            confidence=0.35,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.40,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-999999",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.FAKE_CVE

    def test_fake_cve_all_same_digit(self, detector):
        """Test: All same digit pattern (4+ digits) = FAKE_CVE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-11111",  # All 1s
            source_type="forum",
            source_name="SecurityForum",
            evidence_url="https://forum.example.com/post/123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-11111",
            confidence=0.30,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.30,
            reasoning="Forum discussion",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-11111",
            is_ghost=True,
            confidence=0.25,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.30,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-11111",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.FAKE_CVE

    def test_fake_cve_invalid_year(self, detector):
        """Test: Invalid year (future or before CVE system) = FAKE_CVE."""
        # Future year CVE (we're in 2026, so 2030 is future)
        discovery = DiscoveryResult(
            cve_id="CVE-2030-1234",
            source_type="blog",
            source_name="FakeBlog",
            evidence_url="https://blog.fake.com/post/123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2030-1234",
            confidence=0.40,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.40,
            reasoning="Blog post",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2030-1234",
            is_ghost=True,
            confidence=0.35,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.40,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2030-1234",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.FAKE_CVE

    def test_fake_cve_only_low_quality_sources(self, detector):
        """Test: Only low-quality/unreliable sources + suspicious patterns = FAKE_CVE."""
        # Multiple low-quality sources with suspicious ID
        discoveries = [
            DiscoveryResult(
                cve_id="CVE-2025-88888",
                source_type="reddit",
                source_name="Reddit",
                evidence_url="https://reddit.com/r/security/post/123",
                discovered_at=datetime.utcnow() - timedelta(hours=12),
                context="CVE-2025-88888",
                confidence=0.25,
            ),
            DiscoveryResult(
                cve_id="CVE-2025-88888",
                source_type="social_media",
                source_name="Twitter",
                evidence_url="https://twitter.com/user/status/456",
                discovered_at=datetime.utcnow() - timedelta(hours=10),
                context="CVE-2025-88888",
                confidence=0.20,
            ),
        ]

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.25,
            reasoning="Low-quality sources",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-88888",
            is_ghost=True,
            confidence=0.20,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.23,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-88888",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        # Use first discovery for detect
        result = detector.detect(
            discovery=discoveries[0],
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
            additional_discoveries=discoveries[1:],
        )

        # Should flag as FAKE_CVE due to all-same-digit and low-quality sources
        assert result == GhostRootCause.FAKE_CVE


class TestEmbargoDetection:
    """Test EMBARGO root cause detection."""

    def test_embargo_keyword_embargo(self, detector):
        """Test: 'embargo' keyword in context = EMBARGO."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-5500",
            source_type="vendor_advisory",
            source_name="Apple Security",
            evidence_url="https://support.apple.com/security",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="This CVE is under embargo and will be disclosed on 2026-04-01",
            confidence=0.85,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.80,
            reasoning="Vendor advisory with embargo notice",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-5500",
            is_ghost=True,
            confidence=0.75,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.85,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-5500",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.EMBARGO

    def test_embargo_keyword_coordinated_disclosure(self, detector):
        """Test: 'coordinated disclosure' keyword = EMBARGO."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-6600",
            source_type="research_team",
            source_name="Project Zero",
            evidence_url="https://googleprojectzero.blogspot.com/post/123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="We are following coordinated disclosure practices with the vendor",
            confidence=0.90,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.85,
            reasoning="Research team disclosure",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-6600",
            is_ghost=True,
            confidence=0.80,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.90,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-6600",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.EMBARGO

    def test_embargo_keyword_upcoming(self, detector):
        """Test: 'upcoming' keyword in source_name (ZDI) = EMBARGO."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-7700",
            source_type="vulnerability_broker",
            source_name="ZDI Upcoming",  # Contains 'upcoming'
            evidence_url="https://www.zerodayinitiative.com/rss/upcoming/",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-7700 upcoming disclosure scheduled",
            confidence=0.80,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.75,
            reasoning="ZDI upcoming listing",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-7700",
            is_ghost=True,
            confidence=0.70,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.80,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-7700",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.EMBARGO

    def test_embargo_keyword_will_be_disclosed(self, detector):
        """Test: 'will be disclosed' keyword = EMBARGO."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-8800",
            source_type="vendor_advisory",
            source_name="Cisco PSIRT",
            evidence_url="https://sec.cloudapps.cisco.com/security/center/",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Details will be disclosed after Q1 2026 patch release",
            confidence=0.85,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.80,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-8800",
            is_ghost=True,
            confidence=0.75,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.85,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-8800",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.EMBARGO

    def test_embargo_keyword_patch_pending(self, detector):
        """Test: 'patch pending' keyword = EMBARGO."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-9900",
            source_type="vendor_advisory",
            source_name="Vendor Security",
            evidence_url="https://vendor.com/advisory",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Security update: Patch pending for CVE-2025-9900",
            confidence=0.80,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.78,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-9900",
            is_ghost=True,
            confidence=0.72,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.80,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-9900",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.EMBARGO


class TestCNADelayDetection:
    """Test CNA_DELAY root cause detection."""

    def test_cna_delay_high_lag(self, detector, cna_registry):
        """Test: CNA with avg_publication_lag_days > 14 = CNA_DELAY."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-1000",
            source_type="vendor_advisory",
            source_name="Slow CNA Advisory",
            evidence_url="https://slowcna.org/advisory",
            discovered_at=datetime.utcnow() - timedelta(days=20),  # Old
            context="Disclosed 20 days ago but CVE not published yet",
            confidence=0.75,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.72,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-1000",
            is_ghost=True,
            confidence=0.68,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.75,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-1000",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
            cna_name="slow_cna",
            cna_registry=cna_registry,
        )

        assert result == GhostRootCause.CNA_DELAY

    def test_not_cna_delay_under_threshold(self, detector, cna_registry):
        """Test: CNA with avg_publication_lag_days <= 14 = not CNA_DELAY."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2000",
            source_type="vendor_advisory",
            source_name="MITRE Advisory",
            evidence_url="https://mitre.org/advisory",
            discovered_at=datetime.utcnow() - timedelta(days=5),
            context="Disclosed but CVE still RESERVED",
            confidence=0.85,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.82,
            reasoning="Official advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-2000",
            is_ghost=True,
            confidence=0.78,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.85,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2000",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
            cna_name="mitre",
            cna_registry=cna_registry,
        )

        # Should not be CNA_DELAY (MITRE has 7.5 day lag < 14)
        # Result will depend on other factors, but not CNA_DELAY
        assert result != GhostRootCause.CNA_DELAY or result is None


class TestVendorFailureDetection:
    """Test VENDOR_FAILURE root cause detection."""

    def test_vendor_failure_msrc_reserved(self, detector):
        """Test: MSRC source + RESERVED = VENDOR_FAILURE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-3000",
            source_type="vendor_advisory",
            source_name="Microsoft MSRC",
            evidence_url="https://msrc.microsoft.com/update-guide/CVE-2025-3000",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Microsoft Security Response Center published but CVE RESERVED",
            confidence=0.95,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.92,
            reasoning="Official MSRC advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-3000",
            is_ghost=True,
            confidence=0.88,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.95,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-3000",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.VENDOR_FAILURE

    def test_vendor_failure_psirt_reserved(self, detector):
        """Test: PSIRT source + RESERVED = VENDOR_FAILURE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-4000",
            source_type="vendor_advisory",
            source_name="Cisco PSIRT",
            evidence_url="https://tools.cisco.com/security/center/psirt",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Cisco PSIRT disclosed but CVE RESERVED",
            confidence=0.90,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.88,
            reasoning="Official PSIRT advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-4000",
            is_ghost=True,
            confidence=0.84,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.90,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-4000",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.VENDOR_FAILURE

    def test_vendor_failure_security_advisory_reserved(self, detector):
        """Test: 'Security Advisory' in source_name + RESERVED = VENDOR_FAILURE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-5000",
            source_type="vendor_advisory",
            source_name="Fortinet Security Advisory",
            evidence_url="https://www.fortiguard.com/psirt",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Security Advisory published but CVE RESERVED",
            confidence=0.88,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.85,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-5000",
            is_ghost=True,
            confidence=0.80,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.88,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-5000",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.VENDOR_FAILURE

    def test_vendor_failure_security_bulletin_reserved(self, detector):
        """Test: 'Security Bulletin' in source_name + RESERVED = VENDOR_FAILURE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-6000",
            source_type="vendor_advisory",
            source_name="Oracle Security Bulletin",
            evidence_url="https://www.oracle.com/security-alerts/",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Security Bulletin published but CVE RESERVED",
            confidence=0.87,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.84,
            reasoning="Vendor bulletin",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-6000",
            is_ghost=True,
            confidence=0.79,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.87,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-6000",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.VENDOR_FAILURE

    def test_not_vendor_failure_without_reserved(self, detector):
        """Test: Vendor source + NOT_FOUND (not RESERVED) = not VENDOR_FAILURE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-7000",
            source_type="vendor_advisory",
            source_name="Microsoft MSRC",
            evidence_url="https://msrc.microsoft.com/update-guide/CVE-2025-7000",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="MSRC published but CVE NOT_FOUND",
            confidence=0.85,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.82,
            reasoning="Official MSRC advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-7000",
            is_ghost=True,
            confidence=0.78,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.85,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-7000",
            status=CVEStatus.NOT_FOUND,  # Not RESERVED
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        # NOT_FOUND should trigger SYSTEM_LAG or UNKNOWN, not VENDOR_FAILURE
        assert result != GhostRootCause.VENDOR_FAILURE


class TestSystemLagDetection:
    """Test SYSTEM_LAG root cause detection."""

    def test_system_lag_does_not_apply_to_ghosts(self, detector):
        """Test: SYSTEM_LAG only applies when grace_period_remaining is not None.

        Since grace_period_remaining is not None only when is_ghost=False,
        SYSTEM_LAG can't be detected for actual ghosts (is_ghost=True).
        This is a logical constraint of the system design.
        """
        # When grace_period_remaining is not None, is_ghost should be False
        discovery = DiscoveryResult(
            cve_id="CVE-2025-8000",
            source_type="vendor_advisory",
            source_name="Vendor Security",
            evidence_url="https://vendor.com/advisory",
            discovered_at=datetime.utcnow() - timedelta(hours=2),  # Recent
            context="Recently disclosed, not yet found in registry",
            confidence=0.80,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.78,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-8000",
            is_ghost=False,  # Not a ghost - within grace period
            confidence=0.75,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=timedelta(hours=4),  # Still in grace period
            source_confidence_avg=0.80,
            reasoning="Within grace period",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-8000",
            status=CVEStatus.NOT_FOUND,
            is_ghost=False,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        # Non-ghosts return None (no root cause)
        # SYSTEM_LAG detection requires is_ghost=True, which contradicts grace_period_remaining not None
        assert result is None


class TestPriorityOrder:
    """Test that root cause detection follows priority order."""

    def test_priority_fake_cve_before_embargo(self, detector):
        """Test: FAKE_CVE takes priority over EMBARGO."""
        # Create CVE with both FAKE_CVE patterns and embargo keywords
        discovery = DiscoveryResult(
            cve_id="CVE-2025-99999",  # Fake: > 100k
            source_type="social_media",
            source_name="Twitter",
            evidence_url="https://twitter.com/user/status/123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-99999 under embargo until next month",  # Embargo keyword
            confidence=0.25,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.OTHER,
            confidence=0.25,
            reasoning="Social media",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-99999",
            is_ghost=True,
            confidence=0.20,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.25,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-99999",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        # Should be FAKE_CVE (higher priority) not EMBARGO
        assert result == GhostRootCause.FAKE_CVE

    def test_priority_embargo_before_cna_delay(self, detector, cna_registry):
        """Test: EMBARGO takes priority over CNA_DELAY."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-1500",
            source_type="vendor_advisory",
            source_name="Vendor Advisory",
            evidence_url="https://vendor.com/advisory",
            discovered_at=datetime.utcnow() - timedelta(days=20),  # Qualifies for CNA_DELAY
            context="This vulnerability is under embargo until coordinated disclosure",
            confidence=0.85,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.82,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-1500",
            is_ghost=True,
            confidence=0.78,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.85,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-1500",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
            cna_name="slow_cna",
            cna_registry=cna_registry,
        )

        # Should be EMBARGO (higher priority) not CNA_DELAY
        assert result == GhostRootCause.EMBARGO


class TestUnknownDefault:
    """Test UNKNOWN as default when no specific cause is detected."""

    def test_unknown_default(self, detector):
        """Test: No matching patterns = UNKNOWN."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2500",
            source_type="github_commit",
            source_name="GitHub Repository",
            evidence_url="https://github.com/user/repo/commit/abc123",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="Fix for CVE-2025-2500 in parser",
            confidence=0.75,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.PATCH_NOTES,
            confidence=0.72,
            reasoning="Patch in commit history",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-2500",
            is_ghost=True,
            confidence=0.68,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.75,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-2500",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.UNKNOWN


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_case_insensitive_keyword_matching(self, detector):
        """Test that keyword matching is case-insensitive."""
        # Test with uppercase EMBARGO keyword
        discovery = DiscoveryResult(
            cve_id="CVE-2025-3500",
            source_type="vendor_advisory",
            source_name="Vendor",
            evidence_url="https://vendor.com/advisory",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-3500 is under EMBARGO (all caps)",
            confidence=0.80,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.78,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-3500",
            is_ghost=True,
            confidence=0.74,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.80,
            reasoning="Ghost detected",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-3500",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        assert result == GhostRootCause.EMBARGO

    def test_non_ghost_returns_none(self, detector):
        """Test that non-ghost CVEs return None."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-4500",
            source_type="vendor_advisory",
            source_name="Vendor",
            evidence_url="https://vendor.com/advisory",
            discovered_at=datetime.utcnow() - timedelta(hours=12),
            context="CVE-2025-4500",
            confidence=0.90,
        )

        disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.88,
            reasoning="Vendor advisory",
        )

        ghost_analysis = GhostAnalysis(
            cve_id="CVE-2025-4500",
            is_ghost=False,  # Not a ghost
            confidence=0.85,
            disclosure_status=DisclosureStatus.PUBLIC,
            grace_period_remaining=None,
            source_confidence_avg=0.90,
            reasoning="Not a ghost",
        )

        validation = ValidationResult(
            cve_id="CVE-2025-4500",
            status=CVEStatus.PUBLISHED,  # Published in registry
            is_ghost=False,
            registry_source="CVE_ORG",
            description="Some vulnerability",
            validated_at=datetime.utcnow(),
        )

        result = detector.detect(
            discovery=discovery,
            disclosure=disclosure,
            ghost_analysis=ghost_analysis,
            validation=validation,
        )

        # Should return None for non-ghosts
        assert result is None
