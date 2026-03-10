"""
Tests for disclosure classifier (Stage 2 of pipeline).

Tests the DisclosureClassifier that analyzes discovery context to determine
if a CVE mention is true PUBLIC disclosure vs just a passing mention.

Author: rogolabs.net
"""

import pytest
from datetime import datetime
from src.pipeline.disclosure_classifier import DisclosureClassifier
from src.models.enums import DisclosureStatus, DisclosureType
from src.models.dataclasses import DisclosureClassification
from src.discovery.base import DiscoveryResult


@pytest.fixture
def classifier():
    """Create a DisclosureClassifier instance for testing."""
    return DisclosureClassifier()


class TestDisclosureClassifierBasic:
    """Test basic functionality of DisclosureClassifier."""

    def test_initialization(self, classifier):
        """Test that classifier initializes with proper indicators."""
        assert classifier is not None
        # Should have patch indicators
        assert len(classifier.patch_indicators) >= 20
        # Should have vulnerability indicators
        assert len(classifier.vuln_indicators) >= 40
        # Check some key indicators exist
        assert "patch" in classifier.patch_indicators
        assert "buffer overflow" in classifier.vuln_indicators

    def test_returns_disclosure_classification(self, classifier):
        """Test that classify returns DisclosureClassification object."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-1234",
            source_type="github_commit",
            source_name="test-repo",
            evidence_url="https://github.com/test/repo/commit/abc123",
            context="Fix CVE-2025-1234: buffer overflow in parser"
        )
        result = classifier.classify(discovery)
        assert isinstance(result, DisclosureClassification)
        assert isinstance(result.status, DisclosureStatus)
        assert isinstance(result.disclosure_type, DisclosureType)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.reasoning, str)
        assert len(result.reasoning) > 0


class TestPublicDisclosureScenarios:
    """Test scenarios that should be classified as PUBLIC disclosure."""

    def test_cve_with_vulnerability_description(self, classifier):
        """Test CVE + vulnerability description = PUBLIC."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-1001",
            source_type="github_commit",
            source_name="apache/struts",
            evidence_url="https://github.com/apache/struts/commit/abc123",
            context="Fixed CVE-2025-1001: Remote code execution vulnerability in file upload handler. "
                    "Attacker can execute arbitrary code by uploading malicious file."
        )
        result = classifier.classify(discovery)
        assert result.status == DisclosureStatus.PUBLIC
        assert result.confidence >= 0.70
        assert "vulnerability" in result.reasoning.lower() or "description" in result.reasoning.lower()

    def test_cve_in_patch_notes(self, classifier):
        """Test CVE in patch notes/release notes = PUBLIC."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-2002",
            source_type="github_release",
            source_name="nodejs/node",
            evidence_url="https://github.com/nodejs/node/releases/tag/v18.0.0",
            context="Release Notes v18.0.0:\n\n"
                    "Security Fixes:\n"
                    "- CVE-2025-2002: Fixed timing attack in crypto module\n"
                    "- CVE-2025-2003: Updated dependencies\n\n"
                    "Bug Fixes:\n"
                    "- Fixed memory leak in streams"
        )
        result = classifier.classify(discovery)
        assert result.status == DisclosureStatus.PUBLIC
        assert result.disclosure_type == DisclosureType.PATCH_NOTES
        assert result.confidence >= 0.70
        assert "patch" in result.reasoning.lower() or "release" in result.reasoning.lower()

    def test_cve_in_security_advisory(self, classifier):
        """Test CVE in security advisory with description = PUBLIC."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-3003",
            source_type="vendor_advisory",
            source_name="Microsoft Security Advisory",
            evidence_url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-3003",
            context="Microsoft Security Advisory\n\n"
                    "CVE-2025-3003: Windows Remote Desktop Services Remote Code Execution Vulnerability\n\n"
                    "An elevation of privilege vulnerability exists when the Windows Remote Desktop "
                    "Services improperly handles objects in memory. An attacker who successfully "
                    "exploited this vulnerability could gain elevated privileges.",
            confidence=0.95
        )
        result = classifier.classify(discovery)
        assert result.status == DisclosureStatus.PUBLIC
        assert result.disclosure_type == DisclosureType.ADVISORY
        assert result.confidence >= 0.85  # High confidence for official advisory
        assert "advisory" in result.reasoning.lower() or "official" in result.reasoning.lower()


class TestMentionedOnlyScenarios:
    """Test scenarios that should be classified as MENTIONED_ONLY."""

    def test_cve_id_only_no_description(self, classifier):
        """Test CVE ID only without description = MENTIONED_ONLY."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-4004",
            source_type="social_media",
            source_name="Twitter",
            evidence_url="https://twitter.com/user/status/123456",
            context="Just heard about CVE-2025-4004. Anyone have details?",
            confidence=0.6
        )
        result = classifier.classify(discovery)
        assert result.status == DisclosureStatus.MENTIONED_ONLY
        assert result.confidence < 0.70
        assert "mention" in result.reasoning.lower() or "no details" in result.reasoning.lower()

    def test_cve_list_without_details(self, classifier):
        """Test CVE in list without details = MENTIONED_ONLY."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-5005",
            source_type="github_issue",
            source_name="project/tracker",
            evidence_url="https://github.com/project/tracker/issues/789",
            context="Tracking these CVEs: CVE-2025-5005, CVE-2025-5006, CVE-2025-5007",
            confidence=0.7
        )
        result = classifier.classify(discovery)
        assert result.status == DisclosureStatus.MENTIONED_ONLY
        assert result.confidence <= 0.70


class TestUncertainScenarios:
    """Test scenarios that should be classified as UNCERTAIN."""

    def test_ambiguous_context(self, classifier):
        """Test ambiguous context = UNCERTAIN."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-6006",
            source_type="forum",
            source_name="Security Forum",
            evidence_url="https://forum.example.com/thread/456",
            context="CVE-2025-6006 might be related to the issue we're seeing.",
            confidence=0.5
        )
        result = classifier.classify(discovery)
        assert result.status == DisclosureStatus.UNCERTAIN
        assert result.confidence < 0.60

    def test_no_context_low_confidence_source(self, classifier):
        """Test no context + low confidence source = UNCERTAIN."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-7007",
            source_type="social_media",
            source_name="Reddit",
            evidence_url="https://reddit.com/r/netsec/comments/xyz",
            context=None,  # No context
            confidence=0.4
        )
        result = classifier.classify(discovery)
        assert result.status == DisclosureStatus.UNCERTAIN
        assert result.confidence < 0.60


class TestSourceQualityAdjustment:
    """Test source quality confidence adjustments."""

    def test_official_source_confidence_boost(self, classifier):
        """Test that official sources get confidence boost."""
        # Official advisory source
        official_discovery = DiscoveryResult(
            cve_id="CVE-2025-8001",
            source_type="vendor_advisory",
            source_name="RedHat Security Advisory",
            evidence_url="https://access.redhat.com/security/cve/CVE-2025-8001",
            context="CVE-2025-8001: Security update for kernel package. "
                    "Fixes privilege escalation vulnerability.",
            confidence=0.95
        )
        official_result = classifier.classify(official_discovery)

        # Same content from forum
        forum_discovery = DiscoveryResult(
            cve_id="CVE-2025-8002",
            source_type="forum",
            source_name="Tech Forum",
            evidence_url="https://forum.example.com/thread/999",
            context="CVE-2025-8002: Security update for kernel package. "
                    "Fixes privilege escalation vulnerability.",
            confidence=0.5
        )
        forum_result = classifier.classify(forum_discovery)

        # Official source should have higher confidence
        assert official_result.confidence > forum_result.confidence

    def test_social_media_confidence_penalty(self, classifier):
        """Test that social media sources get confidence penalty."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-9001",
            source_type="social_media",
            source_name="Twitter",
            evidence_url="https://twitter.com/user/status/789",
            context="CVE-2025-9001: SQL injection vulnerability in web application. "
                    "Allows attacker to dump database contents.",
            confidence=0.6
        )
        result = classifier.classify(discovery)
        # Even with vuln description, social media should have reduced confidence
        assert result.confidence < 0.80


class TestConfidenceCalculation:
    """Test confidence score calculation logic."""

    def test_high_confidence_multiple_indicators(self, classifier):
        """Test high confidence when multiple strong indicators present."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-9501",
            source_type="vendor_advisory",
            source_name="Cisco Security Advisory",
            evidence_url="https://sec.cloudapps.cisco.com/security/CVE-2025-9501",
            context="Security Advisory: CVE-2025-9501 - Buffer overflow vulnerability in IOS XE. "
                    "Remote attacker can execute arbitrary code. Security patch available. "
                    "Critical severity. Exploit code published.",
            confidence=0.95
        )
        result = classifier.classify(discovery)
        # Many indicators + official source = very high confidence
        assert result.confidence >= 0.85
        assert result.status == DisclosureStatus.PUBLIC

    def test_medium_confidence_weak_indicators(self, classifier):
        """Test medium confidence with weak indicators."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-9502",
            source_type="github_commit",
            source_name="user/project",
            evidence_url="https://github.com/user/project/commit/xyz",
            context="Update dependencies including fix for CVE-2025-9502",
            confidence=0.75
        )
        result = classifier.classify(discovery)
        # Some indicators but minimal detail
        assert 0.50 <= result.confidence <= 0.80

    def test_low_confidence_no_indicators(self, classifier):
        """Test low confidence with no indicators."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-9503",
            source_type="blog",
            source_name="Personal Blog",
            evidence_url="https://blog.example.com/post/123",
            context="CVE-2025-9503",
            confidence=0.5
        )
        result = classifier.classify(discovery)
        # No indicators = low confidence
        assert result.confidence < 0.60


class TestDisclosureTypeClassification:
    """Test disclosure type classification."""

    def test_advisory_type(self, classifier):
        """Test ADVISORY disclosure type detection."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-10001",
            source_type="vendor_advisory",
            source_name="Oracle Security Advisory",
            evidence_url="https://www.oracle.com/security-alerts/cpujan2025.html",
            context="Oracle Critical Patch Update Advisory - January 2025\n"
                    "CVE-2025-10001: WebLogic Server vulnerability"
        )
        result = classifier.classify(discovery)
        assert result.disclosure_type == DisclosureType.ADVISORY

    def test_patch_notes_type(self, classifier):
        """Test PATCH_NOTES disclosure type detection."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-10002",
            source_type="github_release",
            source_name="rails/rails",
            evidence_url="https://github.com/rails/rails/releases/tag/v7.0.0",
            context="Release Notes v7.0.0\nSecurity: Fixed CVE-2025-10002"
        )
        result = classifier.classify(discovery)
        assert result.disclosure_type == DisclosureType.PATCH_NOTES

    def test_exploit_type(self, classifier):
        """Test EXPLOIT disclosure type detection."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-10003",
            source_type="exploit_db",
            source_name="ExploitDB",
            evidence_url="https://www.exploit-db.com/exploits/50000",
            context="Exploit for CVE-2025-10003. Proof of concept code demonstrating vulnerability."
        )
        result = classifier.classify(discovery)
        assert result.disclosure_type == DisclosureType.EXPLOIT

    def test_conference_type(self, classifier):
        """Test CONFERENCE disclosure type detection."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-10004",
            source_type="conference",
            source_name="Black Hat USA 2025",
            evidence_url="https://blackhat.com/us-25/briefings.html",
            context="Black Hat presentation: Breaking Things - CVE-2025-10004 discovered during research"
        )
        result = classifier.classify(discovery)
        assert result.disclosure_type == DisclosureType.CONFERENCE

    def test_other_type(self, classifier):
        """Test OTHER disclosure type for miscellaneous sources."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-10005",
            source_type="blog",
            source_name="Security Blog",
            evidence_url="https://blog.example.com/cve-2025-10005",
            context="Blog post about CVE-2025-10005 vulnerability analysis"
        )
        result = classifier.classify(discovery)
        assert result.disclosure_type == DisclosureType.OTHER


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_context(self, classifier):
        """Test handling of empty context."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-11001",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/abc",
            context=""
        )
        result = classifier.classify(discovery)
        assert isinstance(result, DisclosureClassification)
        assert result.status in [DisclosureStatus.MENTIONED_ONLY, DisclosureStatus.UNCERTAIN]
        assert result.confidence < 0.60

    def test_none_context(self, classifier):
        """Test handling of None context."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-11002",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/def",
            context=None
        )
        result = classifier.classify(discovery)
        assert isinstance(result, DisclosureClassification)
        assert result.status in [DisclosureStatus.MENTIONED_ONLY, DisclosureStatus.UNCERTAIN]

    def test_very_long_context(self, classifier):
        """Test handling of very long context."""
        long_context = "Security update. " * 1000 + "CVE-2025-11003 fixed. Buffer overflow vulnerability."
        discovery = DiscoveryResult(
            cve_id="CVE-2025-11003",
            source_type="vendor_advisory",
            source_name="Vendor",
            evidence_url="https://vendor.com/advisory",
            context=long_context
        )
        result = classifier.classify(discovery)
        assert isinstance(result, DisclosureClassification)
        assert result.status == DisclosureStatus.PUBLIC

    def test_unicode_and_special_characters(self, classifier):
        """Test handling of unicode and special characters."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-11004",
            source_type="vendor_advisory",
            source_name="日本ベンダー",
            evidence_url="https://vendor.jp/advisory/CVE-2025-11004",
            context="CVE-2025-11004: 🔒 セキュリティ脆弱性の修正。Buffer overflow führt zu RCE."
        )
        result = classifier.classify(discovery)
        assert isinstance(result, DisclosureClassification)
        assert result.confidence > 0.0

    def test_case_insensitivity(self, classifier):
        """Test that indicators are matched case-insensitively."""
        # Uppercase indicators
        discovery_upper = DiscoveryResult(
            cve_id="CVE-2025-11005",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/ghi",
            context="SECURITY PATCH FOR CVE-2025-11005: BUFFER OVERFLOW VULNERABILITY"
        )
        result_upper = classifier.classify(discovery_upper)

        # Lowercase indicators
        discovery_lower = DiscoveryResult(
            cve_id="CVE-2025-11006",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/jkl",
            context="security patch for CVE-2025-11006: buffer overflow vulnerability"
        )
        result_lower = classifier.classify(discovery_lower)

        # Both should be PUBLIC with similar confidence
        assert result_upper.status == DisclosureStatus.PUBLIC
        assert result_lower.status == DisclosureStatus.PUBLIC
        assert abs(result_upper.confidence - result_lower.confidence) < 0.05


class TestReasoningQuality:
    """Test that reasoning strings are informative."""

    def test_reasoning_explains_decision(self, classifier):
        """Test that reasoning explains the classification decision."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12001",
            source_type="vendor_advisory",
            source_name="Adobe Security Bulletin",
            evidence_url="https://helpx.adobe.com/security/CVE-2025-12001.html",
            context="Adobe Security Bulletin: CVE-2025-12001 - Use-after-free vulnerability "
                    "in Acrobat Reader. Arbitrary code execution possible."
        )
        result = classifier.classify(discovery)
        reasoning_lower = result.reasoning.lower()

        # Reasoning should mention key factors
        assert len(result.reasoning) > 20  # Non-trivial explanation
        # Should mention why it's PUBLIC (vuln indicators or source type)
        has_vuln_mention = any(
            word in reasoning_lower
            for word in ["vulnerability", "description", "detail", "security"]
        )
        has_source_mention = any(
            word in reasoning_lower for word in ["advisory", "official", "source"]
        )
        assert has_vuln_mention or has_source_mention

    def test_reasoning_includes_confidence_factors(self, classifier):
        """Test that reasoning includes factors affecting confidence."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12002",
            source_type="social_media",
            source_name="Reddit",
            evidence_url="https://reddit.com/r/netsec/comments/abc",
            context="CVE-2025-12002",
            confidence=0.3
        )
        result = classifier.classify(discovery)
        reasoning_lower = result.reasoning.lower()

        # Should mention low confidence factors
        assert len(result.reasoning) > 10
        # Should mention lack of details or low source quality
        has_mention = any(
            word in reasoning_lower
            for word in ["no details", "minimal", "mention", "uncertain", "low"]
        )
        assert has_mention
