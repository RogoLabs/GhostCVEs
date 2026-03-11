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
    - Ghost detection rate: 60% (most important - finding real ghosts)
    - Unique discoveries: 30% (value of unique CVEs)
    - Fetch reliability: 10% (source uptime/availability)

    Note: false_positive_rate is collected but NOT used in scoring until we have
    proper resolution tracking. Finding published CVEs is normal for advisory sources.

    Args:
        ghost_detection_rate: Ratio of discoveries that became true ghosts (0.0-1.0)
        false_positive_rate: Ratio of discoveries already PUBLISHED (0.0-1.0) [not used]
        fetch_reliability: Ratio of successful fetches (0.0-1.0)
        unique_discoveries_ratio: Ratio of unique CVEs vs total (0.0-1.0)

    Returns:
        Composite reliability score (0.0-1.0)

    Examples:
        >>> calculate_reliability_score(0.20, 0.80, 0.95, 0.50)
        0.40
        >>> calculate_reliability_score(0.10, 0.90, 0.95, 0.20)
        0.17
    """
    # Weighted average (false_positive_rate intentionally excluded)
    score = (
        ghost_detection_rate * 0.6 +
        unique_discoveries_ratio * 0.3 +
        fetch_reliability * 0.1
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


def classify_source(
    reliability_score: float,
    total_discoveries: int,
    fetch_failure_rate: float
) -> str:
    """
    Classify source into Keep/Optimize/Remove based on metrics.

    Decision criteria:
    - Keep: reliability ≥0.30, moderate discoveries, low failure rate
    - Optimize: reliability ≥0.15, could be improved
    - Remove: reliability <0.15 or very high failure rate or no meaningful discoveries

    Note: Thresholds are calibrated for sources that primarily find published CVEs.
    Ghost detection rates of 10-20% are actually good for advisory sources.

    Args:
        reliability_score: Composite reliability score (0.0-1.0)
        total_discoveries: Total CVEs discovered
        fetch_failure_rate: Ratio of failed fetches (0.0-1.0)

    Returns:
        Classification: "Keep", "Optimize", or "Remove"
    """
    # Remove if no meaningful discoveries
    if total_discoveries < 5:
        return "Remove"

    # Remove if fetch failure rate too high
    if fetch_failure_rate > 0.20:
        return "Remove"

    # Classify by reliability score
    if reliability_score >= 0.30:
        return "Keep"
    elif reliability_score >= 0.15:
        return "Optimize"
    else:
        return "Remove"


def generate_audit_report(metrics_list: list[SourceMetrics]) -> str:
    """
    Generate comprehensive markdown audit report.

    Args:
        metrics_list: List of source metrics (should be sorted by reliability)

    Returns:
        Markdown formatted audit report
    """
    report_lines = [
        "# Source Audit Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Sources Audited:** {len(metrics_list)}",
        "",
        "## Executive Summary",
        ""
    ]

    # Count by classification
    classifications = [classify_source(m.reliability_score, m.total_discoveries, m.fetch_failure_rate)
                       for m in metrics_list]
    keep_count = classifications.count("Keep")
    optimize_count = classifications.count("Optimize")
    remove_count = classifications.count("Remove")

    report_lines.extend([
        f"- **Keep (High Quality):** {keep_count} sources",
        f"- **Optimize (Medium Quality):** {optimize_count} sources",
        f"- **Remove (Low Quality):** {remove_count} sources",
        "",
        "## Detailed Source Analysis",
        "",
        "| Source | Reliability | Discoveries | Ghosts | FP Rate | Unique | Recommendation |",
        "|--------|-------------|-------------|--------|---------|--------|----------------|"
    ])

    # Add each source
    for metrics in metrics_list:
        classification = classify_source(
            metrics.reliability_score,
            metrics.total_discoveries,
            metrics.fetch_failure_rate
        )

        # Format row
        row = (
            f"| {metrics.source_name} "
            f"| {metrics.reliability_score:.2f} "
            f"| {metrics.total_discoveries} "
            f"| {metrics.ghost_detection_rate:.1%} "
            f"| {metrics.false_positive_rate:.1%} "
            f"| {metrics.unique_cves_found} "
            f"| **{classification}** |"
        )
        report_lines.append(row)

    report_lines.extend([
        "",
        "## Recommendations",
        "",
        "### Sources to Keep",
        ""
    ])

    # List sources to keep
    keep_sources = [m for m in metrics_list if classify_source(m.reliability_score, m.total_discoveries, m.fetch_failure_rate) == "Keep"]
    if keep_sources:
        for metrics in keep_sources:
            report_lines.append(
                f"- **{metrics.source_name}**: "
                f"Reliability {metrics.reliability_score:.2f}, "
                f"{metrics.total_discoveries} discoveries"
            )
    else:
        report_lines.append("*No sources meet 'Keep' criteria*")

    report_lines.extend([
        "",
        "### Sources to Optimize",
        ""
    ])

    # List sources to optimize
    optimize_sources = [m for m in metrics_list if classify_source(m.reliability_score, m.total_discoveries, m.fetch_failure_rate) == "Optimize"]
    if optimize_sources:
        for metrics in optimize_sources:
            report_lines.append(
                f"- **{metrics.source_name}**: "
                f"Reliability {metrics.reliability_score:.2f}, "
                f"FP rate {metrics.false_positive_rate:.1%}"
            )
    else:
        report_lines.append("*No sources need optimization*")

    report_lines.extend([
        "",
        "### Sources to Remove",
        ""
    ])

    # List sources to remove
    remove_sources = [m for m in metrics_list if classify_source(m.reliability_score, m.total_discoveries, m.fetch_failure_rate) == "Remove"]
    if remove_sources:
        for metrics in remove_sources:
            reason = []
            if metrics.total_discoveries < 5:
                reason.append("few discoveries")
            if metrics.fetch_failure_rate > 0.20:
                reason.append("high failure rate")
            if metrics.reliability_score < 0.60:
                reason.append("low reliability")

            report_lines.append(
                f"- **{metrics.source_name}**: "
                f"Reliability {metrics.reliability_score:.2f} "
                f"({', '.join(reason)})"
            )
    else:
        report_lines.append("*No sources need removal*")

    return "\n".join(report_lines)
