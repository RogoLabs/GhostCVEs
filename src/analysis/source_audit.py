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


class SourceAuditor:
    """
    Audits discovery sources for performance and reliability.

    Analyzes historical data from database to calculate metrics for each source:
    - Ghost detection rate (true positives)
    - False positive rate (already published CVEs)
    - Average time to resolution
    - Fetch reliability
    - Unique discovery value
    """

    def __init__(self, database_manager):
        """
        Initialize auditor with database access.

        Args:
            database_manager: DatabaseManager instance for data access
        """
        self.db = database_manager

    def collect_source_metrics(self, source_name: str) -> SourceMetrics:
        """
        Collect comprehensive metrics for a single source.

        Args:
            source_name: Name of the source to audit

        Returns:
            SourceMetrics with calculated values
        """
        logger.info(f"Collecting metrics for source: {source_name}")

        # Get all discoveries from this source
        discoveries = self.db.get_source_discoveries(source_name)
        total_discoveries = len(discoveries)

        if total_discoveries == 0:
            logger.warning(f"No discoveries found for source: {source_name}")
            return self._empty_metrics(source_name)

        # Calculate ghost detection rate
        ghost_count = sum(1 for d in discoveries if d.get("is_ghost"))
        ghost_detection_rate = ghost_count / total_discoveries if total_discoveries > 0 else 0.0

        # Calculate false positive rate (CVEs that were already PUBLISHED)
        published_count = sum(1 for d in discoveries if d.get("registry_status") == "PUBLISHED")
        false_positive_rate = published_count / total_discoveries if total_discoveries > 0 else 0.0

        # Get resolution history for this source
        resolutions = self.db.get_source_resolution_history(source_name)

        # Calculate average time to resolution
        if resolutions:
            avg_resolution_days = sum(r["resolution_days"] for r in resolutions) / len(resolutions)
        else:
            avg_resolution_days = 0.0

        # Calculate fetch reliability (placeholder - would need fetch history tracking)
        fetch_reliability = 0.95  # Default, will be improved with monitoring
        fetch_failure_rate = 0.05

        # Get unique CVEs (found only by this source)
        all_cves = {d["cve_id"] for d in discoveries}
        other_sources_cves = self._get_cves_from_other_sources(source_name)
        unique_cves = all_cves - other_sources_cves
        unique_count = len(unique_cves)
        unique_ratio = unique_count / total_discoveries if total_discoveries > 0 else 0.0

        # Calculate reliability score
        reliability_score = calculate_reliability_score(
            ghost_detection_rate=ghost_detection_rate,
            false_positive_rate=false_positive_rate,
            fetch_reliability=fetch_reliability,
            unique_discoveries_ratio=unique_ratio
        )

        # Get last successful fetch timestamp
        last_fetch = max(
            (datetime.fromisoformat(d["discovered_at"]) for d in discoveries),
            default=datetime.now()
        )

        return SourceMetrics(
            source_name=source_name,
            total_discoveries=total_discoveries,
            ghost_detection_rate=ghost_detection_rate,
            false_positive_rate=false_positive_rate,
            avg_time_to_resolution=avg_resolution_days,
            reliability_score=reliability_score,
            last_successful_fetch=last_fetch,
            fetch_failure_rate=fetch_failure_rate,
            avg_fetch_time=2.0,  # Placeholder
            unique_cves_found=unique_count
        )

    def audit_all_sources(self) -> list[SourceMetrics]:
        """
        Audit all sources in the database.

        Returns:
            List of SourceMetrics for all sources, sorted by reliability score
        """
        logger.info("Starting audit of all sources")

        all_sources = self.db.get_all_sources()
        logger.info(f"Found {len(all_sources)} sources to audit")

        metrics_list = []
        for source_name in all_sources:
            try:
                metrics = self.collect_source_metrics(source_name)
                metrics_list.append(metrics)
            except Exception as e:
                logger.error(f"Error auditing source {source_name}: {e}")
                continue

        # Sort by reliability score (highest first)
        metrics_list.sort(key=lambda m: m.reliability_score, reverse=True)

        return metrics_list

    def _empty_metrics(self, source_name: str) -> SourceMetrics:
        """Return empty metrics for a source with no data."""
        return SourceMetrics(
            source_name=source_name,
            total_discoveries=0,
            ghost_detection_rate=0.0,
            false_positive_rate=0.0,
            avg_time_to_resolution=0.0,
            reliability_score=0.0,
            last_successful_fetch=datetime.now(),
            fetch_failure_rate=1.0,
            avg_fetch_time=0.0,
            unique_cves_found=0
        )

    def _get_cves_from_other_sources(self, exclude_source: str) -> set[str]:
        """Get set of all CVE IDs discovered by sources other than the specified one."""
        all_sources = self.db.get_all_sources()
        other_cves = set()

        for source in all_sources:
            if source != exclude_source:
                discoveries = self.db.get_source_discoveries(source)
                other_cves.update(d["cve_id"] for d in discoveries)

        return other_cves
