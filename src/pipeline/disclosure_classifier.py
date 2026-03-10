"""
Disclosure Classifier - Stage 2 of 6-stage pipeline.

Analyzes discovery context to determine if a CVE mention constitutes true
public disclosure. Classification rules:
- CVE + vulnerability description → PUBLIC
- CVE in patch notes/release notes → PUBLIC
- CVE ID only mentioned → MENTIONED_ONLY
- Ambiguous → UNCERTAIN

Confidence scoring based on:
- Presence of vulnerability indicators (40+ patterns)
- Presence of patch indicators (20+ patterns)
- Source quality (official sources boosted, social media penalized)
- Context richness

Author: rogolabs.net
"""

import logging
from typing import Set
from src.discovery.base import DiscoveryResult
from src.models.dataclasses import DisclosureClassification
from src.models.enums import DisclosureStatus, DisclosureType

logger = logging.getLogger(__name__)


class DisclosureClassifier:
    """
    Stage 2: Disclosure classification.

    Determines if a CVE mention is true PUBLIC disclosure vs just a mention.
    Uses pattern matching on context and source analysis to classify disclosure
    status and type with confidence scoring.
    """

    # Patch/release indicators (20+)
    PATCH_INDICATORS = {
        "patch", "update", "fix", "fixes", "fixed", "fixing",
        "release notes", "changelog", "change log", "security update",
        "hotfix", "bugfix", "bug fix", "security fix", "security patch",
        "release", "version", "upgrade", "updated", "patched",
        "remediation", "mitigation"
    }

    # Vulnerability indicators (40+)
    VULN_INDICATORS = {
        # Vulnerability types
        "buffer overflow", "stack overflow", "heap overflow",
        "use after free", "use-after-free", "double free",
        "null pointer", "null dereference",
        "sql injection", "xss", "cross-site scripting", "cross site scripting",
        "csrf", "cross-site request forgery", "cross site request forgery",
        "remote code execution", "rce", "arbitrary code execution",
        "command injection", "code injection", "path traversal",
        "directory traversal", "file inclusion", "lfi", "rfi",
        "denial of service", "dos", "ddos",
        "privilege escalation", "escalation of privilege",
        "authentication bypass", "authorization bypass",
        "information disclosure", "information leak", "memory leak",
        "race condition", "integer overflow", "integer underflow",

        # Attack/impact terms
        "vulnerability", "exploit", "malicious", "attacker",
        "allows attacker", "allows remote", "allows local",
        "arbitrary code", "execute code", "gain access",
        "elevation of privilege", "elevated privileges",
        "unauthorized access", "bypass authentication", "bypass authorization",
        "leak information", "disclose information", "sensitive data",
        "crash", "security issue", "security flaw", "security vulnerability"
    }

    # Official/high-quality source types
    OFFICIAL_SOURCES = {
        "vendor_advisory", "security_advisory", "cve_org", "nvd",
        "github_security_advisory", "cert", "cisa"
    }

    # Low-quality source types
    LOW_QUALITY_SOURCES = {
        "social_media", "forum", "chat", "reddit", "twitter",
        "facebook", "linkedin", "blog", "personal_blog"
    }

    def __init__(self):
        """Initialize the disclosure classifier with indicator sets."""
        self.patch_indicators = self.PATCH_INDICATORS.copy()
        self.vuln_indicators = self.VULN_INDICATORS.copy()
        self.official_sources = self.OFFICIAL_SOURCES.copy()
        self.low_quality_sources = self.LOW_QUALITY_SOURCES.copy()
        logger.info(
            f"DisclosureClassifier initialized with "
            f"{len(self.patch_indicators)} patch indicators, "
            f"{len(self.vuln_indicators)} vulnerability indicators"
        )

    def classify(self, discovery: DiscoveryResult) -> DisclosureClassification:
        """
        Classify disclosure status and type for a CVE discovery.

        Args:
            discovery: The CVE discovery to classify

        Returns:
            DisclosureClassification with status, type, confidence, and reasoning
        """
        context = discovery.context or ""
        context_lower = context.lower()
        source_type = discovery.source_type.lower()

        # Count indicators
        patch_count = self._count_indicators(context_lower, self.patch_indicators)
        vuln_count = self._count_indicators(context_lower, self.vuln_indicators)

        # Determine disclosure type
        disclosure_type = self._determine_disclosure_type(
            discovery, context_lower, source_type
        )

        # Calculate base confidence
        base_confidence = self._calculate_base_confidence(
            context_lower, patch_count, vuln_count
        )

        # Adjust for source quality
        adjusted_confidence = self._adjust_for_source_quality(
            base_confidence, source_type, discovery.confidence
        )

        # Determine disclosure status
        status = self._determine_status(
            context_lower, patch_count, vuln_count, adjusted_confidence
        )

        # Generate reasoning
        reasoning = self._generate_reasoning(
            status, disclosure_type, patch_count, vuln_count,
            source_type, adjusted_confidence, context
        )

        logger.debug(
            f"Classified {discovery.cve_id}: {status.value}, "
            f"type={disclosure_type.value}, confidence={adjusted_confidence:.2f}"
        )

        return DisclosureClassification(
            status=status,
            disclosure_type=disclosure_type,
            confidence=adjusted_confidence,
            reasoning=reasoning
        )

    def _count_indicators(self, text: str, indicators: Set[str]) -> int:
        """Count how many indicators are present in text."""
        count = 0
        for indicator in indicators:
            if indicator in text:
                count += 1
        return count

    def _determine_disclosure_type(
        self,
        discovery: DiscoveryResult,
        context_lower: str,
        source_type: str
    ) -> DisclosureType:
        """Determine the type of disclosure based on source and context."""
        # Check source type first
        if "advisory" in source_type or "security_advisory" in source_type:
            return DisclosureType.ADVISORY

        if "exploit" in source_type or "exploit" in context_lower:
            return DisclosureType.EXPLOIT

        if "conference" in source_type or any(
            conf in context_lower
            for conf in ["black hat", "defcon", "def con", "conference talk", "presentation"]
        ):
            return DisclosureType.CONFERENCE

        # Check for patch notes indicators
        patch_notes_indicators = [
            "release notes", "release note", "changelog", "change log",
            "version", "release", "patch notes", "security update"
        ]
        if any(indicator in context_lower for indicator in patch_notes_indicators):
            return DisclosureType.PATCH_NOTES

        # Check URL for hints
        evidence_url = discovery.evidence_url.lower()
        if "advisory" in evidence_url or "security" in evidence_url:
            return DisclosureType.ADVISORY
        if "release" in evidence_url or "changelog" in evidence_url:
            return DisclosureType.PATCH_NOTES
        if "exploit" in evidence_url:
            return DisclosureType.EXPLOIT

        # Default to OTHER
        return DisclosureType.OTHER

    def _calculate_base_confidence(
        self,
        context_lower: str,
        patch_count: int,
        vuln_count: int
    ) -> float:
        """Calculate base confidence score before source adjustments."""
        # No context = low confidence
        if not context_lower or len(context_lower) < 10:
            return 0.30

        # Strong indicators = high confidence
        total_indicators = patch_count + vuln_count

        if total_indicators >= 5:
            return 0.90
        elif total_indicators >= 3:
            return 0.75
        elif total_indicators >= 2:
            return 0.65
        elif total_indicators >= 1:
            return 0.55
        else:
            # No indicators, but has some context
            if len(context_lower) > 100:
                return 0.45
            elif len(context_lower) > 50:
                return 0.40
            else:
                return 0.35

    def _adjust_for_source_quality(
        self,
        base_confidence: float,
        source_type: str,
        source_confidence: float
    ) -> float:
        """Adjust confidence based on source quality."""
        confidence = base_confidence

        # Boost for official sources
        if source_type in self.official_sources:
            confidence *= 1.15
        elif any(official in source_type for official in self.official_sources):
            confidence *= 1.10

        # Penalty for low-quality sources
        if source_type in self.low_quality_sources:
            confidence *= 0.70
        elif any(low_qual in source_type for low_qual in self.low_quality_sources):
            confidence *= 0.80

        # Factor in discovery source confidence (weighted more towards lower confidence)
        confidence = (confidence * 0.6 + source_confidence * 0.4)

        # Ensure in valid range
        return max(0.0, min(1.0, confidence))

    def _determine_status(
        self,
        context_lower: str,
        patch_count: int,
        vuln_count: int,
        confidence: float
    ) -> DisclosureStatus:
        """Determine disclosure status based on indicators and confidence."""
        # High confidence + vulnerability indicators = PUBLIC
        if vuln_count >= 2 and confidence >= 0.70:
            return DisclosureStatus.PUBLIC

        # Patch indicators suggest PUBLIC disclosure
        if patch_count >= 2 and confidence >= 0.65:
            return DisclosureStatus.PUBLIC

        # Some indicators + decent confidence = PUBLIC
        if (patch_count + vuln_count) >= 2 and confidence >= 0.65:
            return DisclosureStatus.PUBLIC

        # Empty or very minimal context = UNCERTAIN
        if not context_lower or len(context_lower) < 10:
            return DisclosureStatus.UNCERTAIN

        # Has some context with no technical indicators
        if vuln_count == 0 and patch_count == 0:
            # Very low confidence = UNCERTAIN
            if confidence < 0.40:
                return DisclosureStatus.UNCERTAIN
            # Has context but no details = MENTIONED_ONLY
            else:
                return DisclosureStatus.MENTIONED_ONLY

        # Low confidence with minimal indicators = UNCERTAIN
        if confidence < 0.40:
            return DisclosureStatus.UNCERTAIN

        # Some context but no strong indicators = MENTIONED_ONLY
        if vuln_count == 0 and patch_count <= 1 and confidence < 0.70:
            return DisclosureStatus.MENTIONED_ONLY

        # Middle ground cases
        if confidence >= 0.60 and (vuln_count >= 1 or patch_count >= 1):
            return DisclosureStatus.PUBLIC
        else:
            return DisclosureStatus.MENTIONED_ONLY

    def _generate_reasoning(
        self,
        status: DisclosureStatus,
        disclosure_type: DisclosureType,
        patch_count: int,
        vuln_count: int,
        source_type: str,
        confidence: float,
        context: str
    ) -> str:
        """Generate human-readable reasoning for the classification."""
        parts = []

        # Status explanation
        if status == DisclosureStatus.PUBLIC:
            if vuln_count >= 2:
                parts.append(f"Multiple vulnerability indicators found ({vuln_count})")
            if patch_count >= 2:
                parts.append(f"Multiple patch indicators found ({patch_count})")
            if vuln_count + patch_count >= 2:
                if not parts:  # Avoid duplication
                    parts.append(f"Strong disclosure indicators present ({patch_count + vuln_count} total)")
        elif status == DisclosureStatus.MENTIONED_ONLY:
            parts.append("CVE mentioned but minimal technical details provided")
            if vuln_count == 0:
                parts.append("No vulnerability description found")
        elif status == DisclosureStatus.UNCERTAIN:
            parts.append("Ambiguous or insufficient context for classification")
            if confidence < 0.50:
                parts.append("Low confidence in available information")

        # Disclosure type
        if disclosure_type != DisclosureType.OTHER:
            parts.append(f"Source type: {disclosure_type.value}")

        # Source quality
        if source_type in self.official_sources or any(
            official in source_type for official in self.official_sources
        ):
            parts.append("Official/high-quality source")
        elif source_type in self.low_quality_sources or any(
            low_qual in source_type for low_qual in self.low_quality_sources
        ):
            parts.append("Low-confidence source type")

        # Context length
        if not context or len(context) < 20:
            parts.append("Minimal or no context available")

        reasoning = ". ".join(parts)
        if reasoning:
            reasoning += "."
        else:
            reasoning = f"Classified as {status.value} with {confidence:.0%} confidence."

        return reasoning
