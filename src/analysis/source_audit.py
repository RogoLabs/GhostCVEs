"""
Source Audit System
===================

Analyzes discovery source performance, reliability, and coverage to inform
optimization decisions.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class SourceMetrics:
    """Performance and reliability metrics for a discovery source."""

    source_name: str
    total_discoveries: int
    ghost_detection_rate: float      # % that became true ghosts
    false_positive_rate: float        # % already PUBLISHED
    avg_time_to_resolution: float     # Days to publication
    reliability_score: float          # Weighted composite score
    last_successful_fetch: datetime
    fetch_failure_rate: float         # % of failed fetches
    avg_fetch_time: float             # Seconds per fetch
    unique_cves_found: int            # CVEs only this source found


def calculate_reliability_score(
    ghost_detection_rate: float,
    false_positive_rate: float,
    fetch_reliability: float,
    unique_discoveries_ratio: float
) -> float:
    """
    Calculate weighted reliability score from component metrics.

    Weights:
    - Ghost detection rate: 40% (most important - finding real ghosts)
    - False positive rate: 30% (inverted - lower is better)
    - Fetch reliability: 20% (source uptime/availability)
    - Unique discoveries: 10% (value of unique CVEs)

    Args:
        ghost_detection_rate: Ratio of discoveries that became true ghosts (0.0-1.0)
        false_positive_rate: Ratio of discoveries already PUBLISHED (0.0-1.0)
        fetch_reliability: Ratio of successful fetches (0.0-1.0)
        unique_discoveries_ratio: Ratio of unique CVEs vs total (0.0-1.0)

    Returns:
        Composite reliability score (0.0-1.0)

    Examples:
        >>> calculate_reliability_score(0.80, 0.10, 0.95, 0.20)
        0.80
        >>> calculate_reliability_score(0.50, 0.40, 0.80, 0.05)
        0.55
    """
    # Invert false positive rate (lower is better)
    fp_score = 1.0 - false_positive_rate

    # Weighted average
    score = (
        ghost_detection_rate * 0.4 +
        fp_score * 0.3 +
        fetch_reliability * 0.2 +
        unique_discoveries_ratio * 0.1
    )

    return score


def identify_redundant_sources(
    source_a_cves: set[str],
    source_b_cves: set[str],
    overlap_threshold: float = 0.80
) -> tuple[bool, float]:
    """
    Determine if two sources are redundant based on CVE overlap.

    Args:
        source_a_cves: Set of CVE IDs discovered by source A
        source_b_cves: Set of CVE IDs discovered by source B
        overlap_threshold: Minimum Jaccard similarity to consider redundant

    Returns:
        Tuple of (is_redundant, jaccard_similarity)

    Examples:
        >>> identify_redundant_sources(
        ...     {"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"},
        ...     {"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0004"},
        ...     0.50
        ... )
        (True, 0.5)
    """
    if not source_a_cves or not source_b_cves:
        return (False, 0.0)

    # Calculate Jaccard similarity: |A ∩ B| / |A ∪ B|
    intersection = source_a_cves & source_b_cves
    union = source_a_cves | source_b_cves

    similarity = len(intersection) / len(union) if union else 0.0

    is_redundant = similarity >= overlap_threshold

    return (is_redundant, similarity)


# Placeholder for SourceAuditor class (will be implemented in Task 2)
class SourceAuditor:
    """Placeholder for SourceAuditor class - to be implemented in Task 2."""
    pass
