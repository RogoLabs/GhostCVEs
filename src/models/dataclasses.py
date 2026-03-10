"""
Dataclasses for world-class ghost detection pipeline.

Defines the data structures passed between pipeline stages and representing
pipeline outputs. These are the "contracts" between stages in the 6-stage pipeline.

Author: rogolabs.net
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from src.models.enums import (
    DisclosureStatus,
    DisclosureType,
    GhostRootCause,
)
from src.discovery.base import DiscoveryResult


@dataclass
class DisclosureClassification:
    """
    Stage 2 output: Disclosure classification results.

    Represents the analysis of whether a CVE mention constitutes true
    public disclosure. Public = CVE + description OR CVE in patch notes.

    Attributes:
        status: DisclosureStatus (PUBLIC, MENTIONED_ONLY, UNCERTAIN)
        disclosure_type: DisclosureType (ADVISORY, PATCH_NOTES, EXPLOIT, etc.)
        confidence: Confidence score (0.0-1.0) of disclosure classification
        reasoning: Explanation of why this status was assigned
    """

    status: DisclosureStatus
    disclosure_type: DisclosureType
    confidence: float
    reasoning: str

    def __post_init__(self) -> None:
        """Validate dataclass fields."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")
        if not isinstance(self.status, DisclosureStatus):
            raise TypeError(f"status must be DisclosureStatus, got {type(self.status)}")
        if not isinstance(self.disclosure_type, DisclosureType):
            raise TypeError(f"disclosure_type must be DisclosureType, got {type(self.disclosure_type)}")


@dataclass
class GhostAnalysis:
    """
    Stage 4 output: Ghost analysis and classification.

    Represents the determination of whether a CVE is a Ghost, with confidence
    scoring and grace period tracking. Ghost = PUBLIC disclosure AND
    (RESERVED or NOT_FOUND) AND past 6-hour grace period AND confidence >= 0.60.

    Attributes:
        cve_id: The CVE identifier
        is_ghost: Whether this CVE is classified as a Ghost
        confidence: Confidence score (0.0-1.0) that is_ghost is correct
        disclosure_status: The disclosure status from Stage 2
        grace_period_remaining: Time left in grace period (None if past)
        source_confidence_avg: Average confidence across all sources (0.0-1.0)
        reasoning: Explanation of ghost classification and confidence
    """

    cve_id: str
    is_ghost: bool
    confidence: float
    disclosure_status: DisclosureStatus
    grace_period_remaining: Optional[timedelta]
    source_confidence_avg: float
    reasoning: str

    def __post_init__(self) -> None:
        """Validate dataclass fields."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")
        if not 0.0 <= self.source_confidence_avg <= 1.0:
            raise ValueError(f"source_confidence_avg must be 0.0-1.0, got {self.source_confidence_avg}")
        if not isinstance(self.disclosure_status, DisclosureStatus):
            raise TypeError(f"disclosure_status must be DisclosureStatus, got {type(self.disclosure_status)}")
        if self.grace_period_remaining is not None and not isinstance(self.grace_period_remaining, timedelta):
            raise TypeError(f"grace_period_remaining must be timedelta or None, got {type(self.grace_period_remaining)}")


@dataclass
class CNAMetadata:
    """
    CNA (CVE Numbering Authority) tracking and metadata.

    Stores information about CNA performance patterns, reliability scores,
    and ID allocation ranges. Used by root cause detector and learning system.

    Attributes:
        cna_name: Name of the CNA (e.g., "mitre", "microsoft")
        avg_publication_lag_days: Average days from disclosure to CVE publication
        reliability_score: Reliability score (0.0-1.0) based on performance history
        total_cves_tracked: Total number of CVEs tracked for this CNA
        id_ranges: Dictionary mapping year to (start, end) CVE ID ranges for this CNA
                   Format: {2000: (2000, 2999), 3000: (3000, 3999), ...}
    """

    cna_name: str
    avg_publication_lag_days: float
    reliability_score: float
    total_cves_tracked: int
    id_ranges: dict[int, tuple[int, int]]

    def __post_init__(self) -> None:
        """Validate dataclass fields."""
        if not 0.0 <= self.reliability_score <= 1.0:
            raise ValueError(f"reliability_score must be 0.0-1.0, got {self.reliability_score}")
        if self.avg_publication_lag_days < 0.0:
            raise ValueError(f"avg_publication_lag_days must be >= 0, got {self.avg_publication_lag_days}")
        if self.total_cves_tracked < 0:
            raise ValueError(f"total_cves_tracked must be >= 0, got {self.total_cves_tracked}")

        # Validate id_ranges structure
        for key, value in self.id_ranges.items():
            if not isinstance(key, int):
                raise TypeError(f"id_ranges keys must be int, got {type(key)}")
            if not isinstance(value, tuple) or len(value) != 2:
                raise TypeError(f"id_ranges values must be 2-tuples, got {value}")
            start, end = value
            if not isinstance(start, int) or not isinstance(end, int):
                raise TypeError(f"id_ranges tuple values must be int, got ({type(start)}, {type(end)})")
            if start > end:
                raise ValueError(f"id_ranges start must be <= end, got ({start}, {end})")


@dataclass
class ProcessedCVE:
    """
    Complete pipeline output: Full CVE analysis result.

    Combines results from all pipeline stages into a single comprehensive
    object representing the complete analysis of a CVE. This is what gets
    stored in the database and reported to users.

    Attributes:
        discovery: Stage 1 result - the CVE discovery information
        disclosure: Stage 2 result - disclosure classification
        ghost_analysis: Stage 4 result - ghost determination and confidence
        root_cause: Stage 5 result - if is_ghost, the reason why (optional)
    """

    discovery: DiscoveryResult
    disclosure: DisclosureClassification
    ghost_analysis: GhostAnalysis
    root_cause: Optional[GhostRootCause]

    def __post_init__(self) -> None:
        """Validate dataclass fields."""
        if not isinstance(self.discovery, DiscoveryResult):
            raise TypeError(f"discovery must be DiscoveryResult, got {type(self.discovery)}")
        if not isinstance(self.disclosure, DisclosureClassification):
            raise TypeError(f"disclosure must be DisclosureClassification, got {type(self.disclosure)}")
        if not isinstance(self.ghost_analysis, GhostAnalysis):
            raise TypeError(f"ghost_analysis must be GhostAnalysis, got {type(self.ghost_analysis)}")
        if self.root_cause is not None and not isinstance(self.root_cause, GhostRootCause):
            raise TypeError(f"root_cause must be GhostRootCause or None, got {type(self.root_cause)}")

    @property
    def cve_id(self) -> str:
        """Get the CVE ID from the discovery result."""
        return self.discovery.cve_id

    @property
    def is_ghost(self) -> bool:
        """Get whether this CVE is classified as a ghost."""
        return self.ghost_analysis.is_ghost
