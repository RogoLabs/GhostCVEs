"""
Root Cause Detector - Stage 5 of 6-stage pipeline.

Determines why a CVE is a Ghost with priority-based classification:

Detection Priority Order:
1. FAKE_CVE: ID > 100k, all same digit pattern, invalid year, only unreliable sources
2. EMBARGO: Keywords (embargo, coordinated disclosure, upcoming, scheduled for, will be disclosed, patch pending)
3. CNA_DELAY: CNA avg_publication_lag_days > 14
4. VENDOR_FAILURE: Vendor source (MSRC, PSIRT, Security Advisory, Security Bulletin) + RESERVED
5. SYSTEM_LAG: NOT_FOUND + grace_period_remaining not None
6. UNKNOWN: Default

Author: rogolabs.net
"""

import logging
from typing import Optional, List

from src.discovery.base import DiscoveryResult
from src.models.dataclasses import (
    DisclosureClassification,
    GhostAnalysis,
    CNAMetadata,
)
from src.models.enums import GhostRootCause, CVEStatus

logger = logging.getLogger(__name__)


class RootCauseDetector:
    """
    Stage 5: Root cause detection for ghost CVEs.

    Determines the underlying reason why a CVE is classified as a ghost,
    using priority-based detection logic to classify into one of six categories.

    Attributes:
        embargo_keywords: Keywords indicating embargo/coordinated disclosure
        vendor_source_patterns: Patterns indicating vendor sources
    """

    # Keywords that indicate embargo/coordinated disclosure
    EMBARGO_KEYWORDS = {
        "embargo",
        "coordinated disclosure",
        "upcoming",
        "scheduled for",
        "will be disclosed",
        "patch pending",
    }

    # Source name patterns indicating vendor sources
    VENDOR_SOURCE_PATTERNS = {
        "msrc",
        "psirt",
        "security advisory",
        "security bulletin",
    }

    def __init__(self):
        """Initialize the root cause detector."""
        logger.info("RootCauseDetector initialized")

    def detect(
        self,
        discovery: DiscoveryResult,
        disclosure: DisclosureClassification,
        ghost_analysis: GhostAnalysis,
        validation,  # ValidationResult with .status (CVEStatus) attribute
        additional_discoveries: Optional[List[DiscoveryResult]] = None,
        cna_name: Optional[str] = None,
        cna_registry: Optional[dict[str, CNAMetadata]] = None,
    ) -> Optional[GhostRootCause]:
        """
        Detect the root cause of a ghost CVE.

        Args:
            discovery: Primary discovery result
            disclosure: Disclosure classification
            ghost_analysis: Ghost analysis results
            validation: Validation result
            additional_discoveries: Optional list of additional discoveries for this CVE
            cna_name: Optional CNA name for CNA_DELAY detection
            cna_registry: Optional CNA registry for CNA_DELAY detection

        Returns:
            GhostRootCause enum value if ghost, None if not ghost

        Raises:
            ValueError: If CVE IDs don't match across inputs
        """
        # Non-ghosts have no root cause
        if not ghost_analysis.is_ghost:
            logger.debug(f"CVE {ghost_analysis.cve_id} is not a ghost, returning None")
            return None

        cve_id = ghost_analysis.cve_id

        # Verify CVE IDs match
        if discovery.cve_id != cve_id:
            raise ValueError(
                f"CVE ID mismatch: discovery has {discovery.cve_id}, "
                f"analysis has {cve_id}"
            )

        logger.debug(f"Detecting root cause for ghost CVE: {cve_id}")

        # Collect all discoveries for comprehensive analysis
        all_discoveries = [discovery]
        if additional_discoveries:
            all_discoveries.extend(additional_discoveries)

        # Detection priority order
        # 1. Check FAKE_CVE
        if self._is_fake_cve(cve_id, all_discoveries):
            logger.debug(f"{cve_id}: Detected FAKE_CVE")
            return GhostRootCause.FAKE_CVE

        # 2. Check EMBARGO
        if self._is_embargo(discovery, cve_id):
            logger.debug(f"{cve_id}: Detected EMBARGO")
            return GhostRootCause.EMBARGO

        # 3. Check CNA_DELAY
        if cna_name and cna_registry:
            if self._is_cna_delay(cna_name, cna_registry):
                logger.debug(f"{cve_id}: Detected CNA_DELAY")
                return GhostRootCause.CNA_DELAY

        # 4. Check VENDOR_FAILURE
        if self._is_vendor_failure(discovery, validation):
            logger.debug(f"{cve_id}: Detected VENDOR_FAILURE")
            return GhostRootCause.VENDOR_FAILURE

        # 5. Check SYSTEM_LAG
        if self._is_system_lag(validation, ghost_analysis):
            logger.debug(f"{cve_id}: Detected SYSTEM_LAG")
            return GhostRootCause.SYSTEM_LAG

        # 6. Default to UNKNOWN
        logger.debug(f"{cve_id}: Defaulting to UNKNOWN")
        return GhostRootCause.UNKNOWN

    def _is_fake_cve(
        self, cve_id: str, discoveries: List[DiscoveryResult]
    ) -> bool:
        """
        Check if CVE matches FAKE_CVE pattern.

        FAKE_CVE = ID > 100k OR all-same-digit (4+) OR invalid year OR only low-quality sources

        Args:
            cve_id: CVE identifier
            discoveries: List of discoveries for this CVE

        Returns:
            True if matches FAKE_CVE pattern
        """
        # Extract ID number from CVE ID
        try:
            parts = cve_id.split("-")
            if len(parts) != 3:
                return False
            id_num = int(parts[2])
            year = int(parts[1])
        except (ValueError, IndexError):
            return False

        # Check 1: ID > 100,000 (implausibly high)
        if id_num > 100000:
            logger.debug(f"{cve_id}: FAKE_CVE - ID exceeds 100k ({id_num})")
            return True

        # Check 2: All same digit pattern (length >= 4)
        id_str = parts[2]
        if len(set(id_str)) == 1 and len(id_str) >= 4:
            logger.debug(f"{cve_id}: FAKE_CVE - All same digit pattern ({id_str})")
            return True

        # Check 3: Invalid year (future or before CVE system)
        from datetime import datetime
        current_year = datetime.utcnow().year
        if year > current_year or year < 1999:
            logger.debug(f"{cve_id}: FAKE_CVE - Invalid year ({year})")
            return True

        # Check 4: Only low-quality/unreliable sources
        # Low-quality source types
        low_quality_types = {
            "social_media",
            "forum",
            "chat",
            "reddit",
            "twitter",
            "blog",
            "mailing_list",
        }

        all_low_quality = all(
            any(low_quality in d.source_type.lower() for low_quality in low_quality_types)
            for d in discoveries
        )

        if all_low_quality and len(discoveries) > 0:
            # Only flag as FAKE if combined with suspicious patterns
            avg_confidence = sum(d.confidence for d in discoveries) / len(discoveries)
            if avg_confidence < 0.50:
                logger.debug(
                    f"{cve_id}: FAKE_CVE - Only low-quality sources "
                    f"(avg confidence: {avg_confidence:.2f})"
                )
                return True

        return False

    def _is_embargo(self, discovery: DiscoveryResult, cve_id: str) -> bool:
        """
        Check if CVE matches EMBARGO pattern.

        EMBARGO = Keywords in context or source_name:
        - embargo
        - coordinated disclosure
        - upcoming (especially in ZDI)
        - scheduled for
        - will be disclosed
        - patch pending

        Args:
            discovery: Discovery result
            cve_id: CVE identifier

        Returns:
            True if matches EMBARGO pattern
        """
        # Combine context and source_name for search
        text_to_search = ""
        if discovery.context:
            text_to_search += discovery.context.lower()
        text_to_search += " " + discovery.source_name.lower()

        # Check for embargo keywords
        for keyword in self.EMBARGO_KEYWORDS:
            if keyword in text_to_search:
                logger.debug(f"{cve_id}: EMBARGO - Found keyword: '{keyword}'")
                return True

        return False

    def _is_cna_delay(self, cna_name: str, cna_registry: dict[str, CNAMetadata]) -> bool:
        """
        Check if CVE matches CNA_DELAY pattern.

        CNA_DELAY = CNA avg_publication_lag_days > 14

        Args:
            cna_name: Name of the CNA
            cna_registry: Registry of CNA metadata

        Returns:
            True if CNA has high publication lag
        """
        if cna_name not in cna_registry:
            return False

        cna_metadata = cna_registry[cna_name]
        if cna_metadata.avg_publication_lag_days > 14.0:
            logger.debug(
                f"{cna_name}: CNA_DELAY - Lag {cna_metadata.avg_publication_lag_days:.1f}d > 14d"
            )
            return True

        return False

    def _is_vendor_failure(
        self, discovery: DiscoveryResult, validation
    ) -> bool:
        """
        Check if CVE matches VENDOR_FAILURE pattern.

        VENDOR_FAILURE = Vendor source (MSRC, PSIRT, Security Advisory, Security Bulletin) + RESERVED

        Args:
            discovery: Discovery result
            validation: Validation result with .status (CVEStatus) attribute

        Returns:
            True if matches VENDOR_FAILURE pattern
        """
        # Must be RESERVED (not NOT_FOUND, PUBLISHED, etc.)
        if validation.status != CVEStatus.RESERVED:
            return False

        # Check if source_name contains vendor patterns
        source_name_lower = discovery.source_name.lower()
        for pattern in self.VENDOR_SOURCE_PATTERNS:
            if pattern in source_name_lower:
                logger.debug(
                    f"VENDOR_FAILURE - Found vendor pattern '{pattern}' in '{discovery.source_name}'"
                )
                return True

        return False

    def _is_system_lag(
        self, validation, ghost_analysis: GhostAnalysis
    ) -> bool:
        """
        Check if CVE matches SYSTEM_LAG pattern.

        SYSTEM_LAG = NOT_FOUND + grace_period_remaining not None

        Args:
            validation: Validation result with .status (CVEStatus) attribute
            ghost_analysis: Ghost analysis results

        Returns:
            True if matches SYSTEM_LAG pattern
        """
        # Must be NOT_FOUND (not RESERVED or other statuses)
        if validation.status != CVEStatus.NOT_FOUND:
            return False

        # Must have grace period remaining (i.e., recently discovered)
        if ghost_analysis.grace_period_remaining is None:
            return False

        logger.debug(
            f"SYSTEM_LAG - NOT_FOUND with grace period remaining "
            f"({ghost_analysis.grace_period_remaining.total_seconds() / 3600:.1f}h)"
        )
        return True
