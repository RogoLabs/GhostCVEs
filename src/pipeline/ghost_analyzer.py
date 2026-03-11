"""
Ghost Analyzer - Stage 4 of 6-stage pipeline.

Determines if a CVE is a Ghost with confidence scoring and grace period tracking.

Ghost Detection Rules:
- Ghost = PUBLIC disclosure + (RESERVED | NOT_FOUND) + past 6hr grace + confidence >= 60%
- 6-hour grace period (not 30 days) - user's explicit requirement

Confidence Calculation:
- Base: disclosure.confidence (0.0-1.0)
- Weight by source reliability: multiply by avg source reliability
- Boost for multiple sources: +10% (2 sources), +20% (3+ sources)
- Boost for high-quality sources: +15% if any high-quality source
- Boost for age: +10% (3+ days), +20% (7+ days)
- Penalty for mailing lists only: -20%
- Cap at 1.0

Author: rogolabs.net
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List

from src.discovery.base import DiscoveryResult
from src.models.dataclasses import DisclosureClassification, GhostAnalysis
from src.models.enums import DisclosureStatus, CVEStatus
from src.registry.validator import ValidationResult

logger = logging.getLogger(__name__)


class SourceReliabilityTracker:
    """
    Stub for source reliability tracking (full version in Chunk 8).

    Tracks reliability scores for discovery sources based on historical
    performance. This is a simplified stub that returns reasonable defaults.
    """

    # High-quality source types (reliability >= 0.80)
    HIGH_QUALITY_SOURCES = {
        "vendor_advisory",
        "security_advisory",
        "cve_org",
        "nvd",
        "github_security_advisory",
        "cert",
        "cisa",
    }

    # Official/reliable source types (reliability >= 0.70)
    RELIABLE_SOURCES = {
        "github_commit",
        "github_release",
        "exploit_db",
        "conference",
    }

    # Medium quality sources (reliability >= 0.50)
    MEDIUM_SOURCES = {
        "rss_feed",
        "blog",
        "news",
    }

    # Low quality sources (reliability < 0.50)
    LOW_QUALITY_SOURCES = {
        "social_media",
        "forum",
        "chat",
        "reddit",
        "twitter",
        "mailing_list",
    }

    def __init__(self):
        """Initialize the reliability tracker stub."""
        logger.debug("SourceReliabilityTracker initialized (stub)")

    def get_source_reliability(self, source_type: str) -> float:
        """
        Get reliability score for a source type.

        Args:
            source_type: Type of source (e.g., "vendor_advisory", "social_media")

        Returns:
            Reliability score (0.0-1.0)
        """
        source_type = source_type.lower()

        # High quality sources
        if source_type in self.HIGH_QUALITY_SOURCES:
            return 0.90
        if any(hq in source_type for hq in self.HIGH_QUALITY_SOURCES):
            return 0.85

        # Reliable sources
        if source_type in self.RELIABLE_SOURCES:
            return 0.75
        if any(rel in source_type for rel in self.RELIABLE_SOURCES):
            return 0.70

        # Medium sources
        if source_type in self.MEDIUM_SOURCES:
            return 0.60
        if any(med in source_type for med in self.MEDIUM_SOURCES):
            return 0.55

        # Low quality sources
        if source_type in self.LOW_QUALITY_SOURCES:
            return 0.40
        if any(low in source_type for low in self.LOW_QUALITY_SOURCES):
            return 0.45

        # Default for unknown sources
        return 0.50

    def is_high_quality_source(self, source_type: str) -> bool:
        """
        Check if a source type is high quality.

        Args:
            source_type: Type of source

        Returns:
            True if high quality source
        """
        source_type = source_type.lower()
        return (
            source_type in self.HIGH_QUALITY_SOURCES
            or any(hq in source_type for hq in self.HIGH_QUALITY_SOURCES)
        )


class GhostAnalyzer:
    """
    Stage 4: Ghost analysis with confidence scoring.

    Determines if a CVE is a Ghost based on disclosure status, validation status,
    grace period, and confidence scoring with source reliability weighting.

    Attributes:
        grace_period_hours: Grace period in hours (default: 6)
        confidence_threshold: Minimum confidence for ghost classification (default: 0.60)
        reliability_tracker: Source reliability tracker
    """

    def __init__(
        self,
        grace_period_hours: int = 6,
        confidence_threshold: float = 0.60,
        reliability_tracker: SourceReliabilityTracker = None,
    ):
        """
        Initialize the ghost analyzer.

        Args:
            grace_period_hours: Grace period in hours (default: 6)
            confidence_threshold: Minimum confidence for ghost (default: 0.60)
            reliability_tracker: Optional custom reliability tracker
        """
        self.grace_period_hours = grace_period_hours
        self.confidence_threshold = confidence_threshold
        self.reliability_tracker = reliability_tracker or SourceReliabilityTracker()

        logger.info(
            f"GhostAnalyzer initialized: grace_period={grace_period_hours}h, "
            f"threshold={confidence_threshold:.0%}"
        )

    def analyze(
        self,
        discoveries: List[DiscoveryResult],
        disclosure: DisclosureClassification,
        validation: ValidationResult,
    ) -> GhostAnalysis:
        """
        Analyze if a CVE is a Ghost with confidence scoring.

        Args:
            discoveries: List of discoveries for this CVE (at least one)
            disclosure: Disclosure classification from Stage 2
            validation: Validation result from Stage 3

        Returns:
            GhostAnalysis with ghost determination and confidence

        Raises:
            ValueError: If discoveries list is empty or CVE IDs don't match
        """
        # Validation
        if not discoveries:
            raise ValueError("Must provide at least one discovery for analysis")

        cve_id = validation.cve_id

        # Verify all discoveries are for the same CVE
        for discovery in discoveries:
            if discovery.cve_id != cve_id:
                raise ValueError(
                    f"CVE ID mismatch: discovery has {discovery.cve_id}, "
                    f"validation has {cve_id}"
                )

        logger.debug(f"Analyzing {cve_id}: {len(discoveries)} discoveries")

        # Get oldest discovery for grace period calculation
        oldest_discovery = min(discoveries, key=lambda d: d.discovered_at)
        age = datetime.now(timezone.utc) - oldest_discovery.discovered_at
        grace_period_delta = timedelta(hours=self.grace_period_hours)

        # Calculate grace period remaining
        grace_period_remaining = None
        if age < grace_period_delta:
            grace_period_remaining = grace_period_delta - age

        # Calculate confidence score
        confidence = self._calculate_confidence(
            discoveries=discoveries,
            disclosure=disclosure,
            validation=validation,
            age=age,
        )

        # Calculate average source confidence
        source_confidence_avg = sum(d.confidence for d in discoveries) / len(discoveries)

        # Determine if this is a ghost
        is_ghost = self._is_ghost(
            disclosure_status=disclosure.status,
            validation_status=validation.status,
            grace_period_remaining=grace_period_remaining,
            confidence=confidence,
        )

        # Generate reasoning
        reasoning = self._generate_reasoning(
            is_ghost=is_ghost,
            disclosure=disclosure,
            validation=validation,
            grace_period_remaining=grace_period_remaining,
            confidence=confidence,
            num_sources=len(discoveries),
            age=age,
        )

        logger.debug(
            f"Ghost analysis for {cve_id}: is_ghost={is_ghost}, "
            f"confidence={confidence:.2f}"
        )

        return GhostAnalysis(
            cve_id=cve_id,
            is_ghost=is_ghost,
            confidence=confidence,
            disclosure_status=disclosure.status,
            grace_period_remaining=grace_period_remaining,
            source_confidence_avg=source_confidence_avg,
            reasoning=reasoning,
        )

    def _is_ghost(
        self,
        disclosure_status: DisclosureStatus,
        validation_status: CVEStatus,
        grace_period_remaining: timedelta | None,
        confidence: float,
    ) -> bool:
        """
        Determine if CVE is a ghost based on criteria.

        Ghost = PUBLIC + (RESERVED | NOT_FOUND) + past grace period + confidence >= threshold

        Args:
            disclosure_status: Disclosure status from Stage 2
            validation_status: Validation status from Stage 3
            grace_period_remaining: Time remaining in grace period (None if past)
            confidence: Calculated confidence score

        Returns:
            True if CVE is classified as a ghost
        """
        # Must be PUBLIC disclosure
        if disclosure_status != DisclosureStatus.PUBLIC:
            return False

        # Must be RESERVED or NOT_FOUND in registry
        if validation_status not in (CVEStatus.RESERVED, CVEStatus.NOT_FOUND):
            return False

        # Must be past grace period
        if grace_period_remaining is not None:
            return False

        # Must meet confidence threshold
        if confidence < self.confidence_threshold:
            return False

        return True

    def _calculate_confidence(
        self,
        discoveries: List[DiscoveryResult],
        disclosure: DisclosureClassification,
        validation: ValidationResult,
        age: timedelta,
    ) -> float:
        """
        Calculate confidence score with source reliability weighting.

        Confidence calculation:
        1. Base: disclosure.confidence (0.0-1.0)
        2. Weight by source reliability: multiply by avg source reliability
        3. Boost for multiple sources: +10% (2), +20% (3+)
        4. Boost for high-quality sources: +15% if any high-quality
        5. Boost for age: +10% (3+ days), +20% (7+ days)
        6. Penalty for mailing lists only: -20%
        7. Cap at 1.0

        Args:
            discoveries: List of discoveries
            disclosure: Disclosure classification
            validation: Validation result
            age: Age of oldest discovery

        Returns:
            Confidence score (0.0-1.0)
        """
        # Base confidence from disclosure classification
        confidence = disclosure.confidence

        # Calculate average source reliability
        reliabilities = [
            self.reliability_tracker.get_source_reliability(d.source_type)
            for d in discoveries
        ]
        avg_reliability = sum(reliabilities) / len(reliabilities)

        # Weight by source reliability
        confidence *= avg_reliability

        # Boost for multiple sources
        num_sources = len(discoveries)
        if num_sources >= 3:
            confidence *= 1.20  # +20% for 3+ sources
        elif num_sources >= 2:
            confidence *= 1.10  # +10% for 2 sources

        # Boost for high-quality sources
        has_high_quality = any(
            self.reliability_tracker.is_high_quality_source(d.source_type)
            for d in discoveries
        )
        if has_high_quality:
            confidence *= 1.15  # +15% boost

        # Boost for age (older ghosts are more confident)
        age_days = age.total_seconds() / 86400
        if age_days >= 7:
            confidence *= 1.20  # +20% for 7+ days
        elif age_days >= 3:
            confidence *= 1.10  # +10% for 3+ days

        # Penalty for mailing lists only
        all_mailing_lists = all(
            "mailing" in d.source_type.lower() for d in discoveries
        )
        if all_mailing_lists:
            confidence *= 0.80  # -20% penalty

        # Cap at 1.0
        confidence = min(1.0, confidence)

        return confidence

    def _generate_reasoning(
        self,
        is_ghost: bool,
        disclosure: DisclosureClassification,
        validation: ValidationResult,
        grace_period_remaining: timedelta | None,
        confidence: float,
        num_sources: int,
        age: timedelta,
    ) -> str:
        """
        Generate human-readable reasoning for the ghost classification.

        Args:
            is_ghost: Whether CVE is classified as a ghost
            disclosure: Disclosure classification
            validation: Validation result
            grace_period_remaining: Time remaining in grace period
            confidence: Calculated confidence score
            num_sources: Number of discovery sources
            age: Age of oldest discovery

        Returns:
            Reasoning string explaining the classification
        """
        parts = []

        if is_ghost:
            # Explain why it's a ghost
            parts.append(
                f"Ghost CVE detected: publicly disclosed but {validation.status.value} in registry"
            )

            if num_sources > 1:
                parts.append(f"Found in {num_sources} independent sources")

            age_hours = age.total_seconds() / 3600
            if age_hours >= 168:  # 7 days
                parts.append(f"Disclosed {age_hours/24:.1f} days ago (well past grace period)")
            elif age_hours >= 24:
                parts.append(f"Disclosed {age_hours/24:.1f} days ago (past grace period)")
            else:
                parts.append(f"Disclosed {age_hours:.1f} hours ago (past {self.grace_period_hours}hr grace period)")

            parts.append(f"Confidence: {confidence:.0%}")

        else:
            # Explain why it's NOT a ghost
            if disclosure.status != DisclosureStatus.PUBLIC:
                parts.append(f"Not public disclosure ({disclosure.status.value})")

            elif validation.status not in (CVEStatus.RESERVED, CVEStatus.NOT_FOUND):
                parts.append(f"CVE is {validation.status.value} in registry")

            elif grace_period_remaining is not None:
                remaining_hours = grace_period_remaining.total_seconds() / 3600
                parts.append(
                    f"Within {self.grace_period_hours}hr grace period "
                    f"({remaining_hours:.1f}hr remaining)"
                )

            elif confidence < self.confidence_threshold:
                parts.append(
                    f"Confidence too low ({confidence:.0%} < {self.confidence_threshold:.0%} threshold)"
                )

            else:
                parts.append("Does not meet ghost criteria")

        reasoning = ". ".join(parts)
        if reasoning and not reasoning.endswith("."):
            reasoning += "."

        return reasoning
