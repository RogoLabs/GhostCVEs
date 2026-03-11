"""
Learning System - Stage 6 of 6-stage pipeline.

Machine learning component that learns from resolved ghosts to continuously
improve detection accuracy. Tracks source reliability and CNA publication patterns.

Key Features:
- Records resolution outcomes (true positive vs false positive)
- Calculates reliability from accuracy + speed bonus
- Triggers recalculation every 50 resolutions or 7 days
- Caches reliability scores for performance

Author: rogolabs.net
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)


class SourceReliabilityTracker:
    """
    Tracks and learns from source reliability over time.

    Records resolution outcomes for each source and calculates reliability scores
    based on accuracy (true positive rate) and speed (average days to resolution).

    Reliability Formula:
        reliability = accuracy + speed_bonus
        - accuracy = true_positives / total_outcomes
        - speed_bonus: <3 days = +0.10, <7 days = +0.05, else 0
        - capped at 1.0

    True Ghost vs False Positive:
        - True ghost: resolution_days > 1.0 (real publication delay)
        - False positive: resolution_days <= 1.0 (sync lag within grace period)

    Attributes:
        db_manager: Database manager for persistence
        _cache: Cache of source reliability scores
        _last_cache_refresh: Timestamp of last cache refresh
    """

    DEFAULT_RELIABILITY = 0.75
    RECALC_RESOLUTION_THRESHOLD = 50  # Recalculate after 50 resolutions
    RECALC_TIME_THRESHOLD_DAYS = 7.0  # Recalculate after 7 days
    CACHE_TTL_HOURS = 24  # Cache valid for 24 hours

    def __init__(self, db_manager):
        """
        Initialize the source reliability tracker.

        Args:
            db_manager: Database manager with source reliability methods
        """
        self.db_manager = db_manager
        self._cache: Dict[str, float] = {}
        self._last_cache_refresh: Optional[datetime] = None

        logger.info("SourceReliabilityTracker initialized")

    def record_resolution(
        self,
        source_name: str,
        resolution_days: float,
        timestamp: datetime
    ) -> None:
        """
        Record a resolution outcome for a source.

        Determines if this was a true positive (real ghost) or false positive
        (sync lag) based on resolution time.

        Args:
            source_name: Name of the discovery source
            resolution_days: Days between discovery and resolution
            timestamp: When the resolution was detected
        """
        # Determine if true positive or false positive
        # True ghost = resolution_days > 1.0 (real publication delay)
        # False positive = resolution_days <= 1.0 (sync lag within grace period)
        was_true_positive = resolution_days > 1.0

        logger.debug(
            f"Recording resolution for {source_name}: "
            f"{resolution_days:.1f} days, "
            f"{'TRUE' if was_true_positive else 'FALSE'} positive"
        )

        # Record in database
        self.db_manager.record_source_outcome(
            source_name=source_name,
            was_true_positive=was_true_positive,
            resolution_days=resolution_days,
            timestamp=timestamp
        )

    def get_reliability(self, source_name: str) -> float:
        """
        Get reliability score for a source.

        Returns cached value if available and fresh, otherwise queries database.

        Args:
            source_name: Name of the source

        Returns:
            Reliability score (0.0-1.0), or default if unknown
        """
        # Check if cache needs refresh
        if self._should_refresh_cache():
            self._refresh_cache()

        # Return from cache if available
        if source_name in self._cache:
            return self._cache[source_name]

        # Query database
        reliability = self.db_manager.get_source_reliability(source_name)

        if reliability is not None:
            # Cache it
            self._cache[source_name] = reliability
            return reliability

        # Unknown source, return default
        logger.debug(f"Unknown source {source_name}, returning default reliability")
        return self.DEFAULT_RELIABILITY

    def get_source_reliability(self, source_type: str) -> float:
        """
        Get reliability score for a source type (alias for get_reliability).

        This is an alias method for compatibility with GhostAnalyzer interface.

        Args:
            source_type: Type or name of the source

        Returns:
            Reliability score (0.0-1.0), or default if unknown
        """
        return self.get_reliability(source_type)

    def is_high_quality_source(self, source_type: str) -> bool:
        """
        Check if a source type is high quality (reliability >= 0.80).

        Args:
            source_type: Type or name of the source

        Returns:
            True if source has high reliability (>= 0.80)
        """
        reliability = self.get_reliability(source_type)
        return reliability >= 0.80

    def _calculate_reliability(self, outcomes: List[dict]) -> float:
        """
        Calculate reliability score from outcomes.

        Formula: accuracy + speed_bonus (capped at 1.0)
        - accuracy = true_positives / total
        - speed_bonus: avg < 3 days = +0.10, avg < 7 days = +0.05, else 0

        Args:
            outcomes: List of outcome dicts with keys:
                - was_true_positive (bool)
                - resolution_days (float)

        Returns:
            Reliability score (0.0-1.0)
        """
        if not outcomes:
            return self.DEFAULT_RELIABILITY

        # Calculate accuracy (true positive rate)
        total = len(outcomes)
        true_positives = sum(1 for o in outcomes if o["was_true_positive"])
        accuracy = true_positives / total

        # Calculate average resolution days (only for true positives)
        tp_outcomes = [o for o in outcomes if o["was_true_positive"]]
        if tp_outcomes:
            avg_days = sum(o["resolution_days"] for o in tp_outcomes) / len(tp_outcomes)
        else:
            # All false positives, use overall average
            avg_days = sum(o["resolution_days"] for o in outcomes) / total

        # Calculate speed bonus
        if avg_days < 3.0:
            speed_bonus = 0.10
        elif avg_days < 7.0:
            speed_bonus = 0.05
        else:
            speed_bonus = 0.0

        # Calculate final reliability (capped at 1.0)
        reliability = min(1.0, accuracy + speed_bonus)

        logger.debug(
            f"Calculated reliability: accuracy={accuracy:.2f}, "
            f"speed_bonus={speed_bonus:.2f}, "
            f"avg_days={avg_days:.1f}, "
            f"reliability={reliability:.2f}"
        )

        return reliability

    def _should_recalculate(self) -> bool:
        """
        Check if reliability scores should be recalculated.

        Triggers recalculation if:
        - 50+ resolutions since last recalc, OR
        - 7+ days since last recalc

        Returns:
            True if should recalculate
        """
        resolutions = self.db_manager.get_resolutions_since_last_recalc()
        days = self.db_manager.get_days_since_last_recalc()

        should_recalc = (
            resolutions >= self.RECALC_RESOLUTION_THRESHOLD or
            days >= self.RECALC_TIME_THRESHOLD_DAYS
        )

        if should_recalc:
            logger.info(
                f"Triggering recalculation: {resolutions} resolutions, "
                f"{days:.1f} days since last"
            )

        return should_recalc

    def recalculate_all(self) -> None:
        """
        Recalculate reliability scores for all sources.

        Queries all source outcomes from database, recalculates reliability
        for each source, and updates the database.
        """
        logger.info("Recalculating reliability for all sources")

        # Get all source names
        source_names = self.db_manager.get_all_source_names()

        for source_name in source_names:
            # Get outcomes for this source
            outcomes = self.db_manager.get_source_outcomes(source_name)

            if not outcomes:
                continue

            # Calculate new reliability
            reliability = self._calculate_reliability(outcomes)

            # Calculate stats
            total = len(outcomes)
            true_positives = sum(1 for o in outcomes if o["was_true_positive"])
            false_positives = total - true_positives

            # Calculate average days to publish (only true positives)
            tp_outcomes = [o for o in outcomes if o["was_true_positive"]]
            if tp_outcomes:
                avg_days = sum(o["resolution_days"] for o in tp_outcomes) / len(tp_outcomes)
            else:
                avg_days = None

            # Update database
            self.db_manager.update_source_reliability(
                source_name=source_name,
                reliability_score=reliability,
                total_discoveries=total,
                true_positives=true_positives,
                false_positives=false_positives,
                avg_days_to_publish=avg_days
            )

            logger.debug(
                f"Updated {source_name}: reliability={reliability:.2f}, "
                f"TP={true_positives}, FP={false_positives}"
            )

        # Mark recalculation timestamp
        self.db_manager.mark_recalculation(datetime.now(timezone.utc))

        # Clear cache to force refresh
        self._cache.clear()
        self._last_cache_refresh = None

        logger.info(f"Recalculation complete for {len(source_names)} sources")

    def _should_refresh_cache(self) -> bool:
        """
        Check if cache should be refreshed.

        Cache is refreshed if:
        - Never been refreshed, OR
        - More than CACHE_TTL_HOURS since last refresh

        Returns:
            True if cache should be refreshed
        """
        if self._last_cache_refresh is None:
            return True

        age = datetime.now(timezone.utc) - self._last_cache_refresh
        return age > timedelta(hours=self.CACHE_TTL_HOURS)

    def _refresh_cache(self) -> None:
        """
        Refresh the reliability cache from database.

        Loads all known sources and their reliability scores.
        """
        logger.debug("Refreshing reliability cache")

        self._cache.clear()

        # Get all source names
        source_names = self.db_manager.get_all_source_names()

        # Load reliability for each
        for source_name in source_names:
            reliability = self.db_manager.get_source_reliability(source_name)
            if reliability is not None:
                self._cache[source_name] = reliability

        self._last_cache_refresh = datetime.now(timezone.utc)

        logger.debug(f"Cache refreshed with {len(self._cache)} sources")


class CNARegistryLearning:
    """
    Tracks and learns from CNA publication patterns.

    This is a stub implementation for now. Full implementation would track:
    - Average publication lag per CNA
    - Ghost rate per CNA
    - ID allocation patterns
    - Reliability trends

    Attributes:
        db_manager: Database manager for persistence
    """

    def __init__(self, db_manager):
        """
        Initialize CNA registry learning.

        Args:
            db_manager: Database manager with CNA registry methods
        """
        self.db_manager = db_manager
        logger.info("CNARegistryLearning initialized (stub)")

    def update_cna_patterns(
        self,
        cna_name: str,
        resolution_days: float,
        was_ghost: bool
    ) -> None:
        """
        Update CNA publication patterns (stub).

        Args:
            cna_name: Name of the CNA
            resolution_days: Days to resolution
            was_ghost: Whether this was a true ghost
        """
        # Stub implementation - does nothing for now
        logger.debug(
            f"CNA pattern update (stub): {cna_name}, "
            f"{resolution_days:.1f} days, ghost={was_ghost}"
        )
        pass


class LearningSystem:
    """
    Orchestrates learning when ghosts are resolved.

    Coordinates source reliability tracking and CNA pattern learning.
    Triggers recalculation when thresholds are met.

    Attributes:
        db_manager: Database manager
        reliability_tracker: Source reliability tracker
        cna_learning: CNA registry learning
    """

    def __init__(self, db_manager):
        """
        Initialize the learning system.

        Args:
            db_manager: Database manager with learning methods
        """
        self.db_manager = db_manager
        self.reliability_tracker = SourceReliabilityTracker(db_manager)
        self.cna_learning = CNARegistryLearning(db_manager)

        logger.info("LearningSystem initialized")

    def learn_from_resolution(
        self,
        cve_id: str,
        resolved_date: datetime,
        was_true_ghost: bool,
        cna_name: Optional[str] = None,
        root_cause: Optional[str] = None,
        ghost_confidence: Optional[float] = None
    ) -> None:
        """
        Learn from a ghost resolution.

        Records the resolution outcome, updates source reliability,
        and triggers recalculation if thresholds are met.

        Args:
            cve_id: CVE identifier that was resolved
            resolved_date: When the CVE was published/resolved
            was_true_ghost: Whether this was a true ghost or false positive
            cna_name: Optional CNA name
            root_cause: Optional root cause classification
            ghost_confidence: Optional confidence score at peak
        """
        logger.info(
            f"Learning from resolution: {cve_id}, "
            f"true_ghost={was_true_ghost}"
        )

        # Get all sources for this CVE
        sources = self.db_manager.get_sources_for_cve(cve_id)

        if not sources:
            logger.warning(f"No sources found for {cve_id}, cannot learn")
            return

        # Get ghost record for first_seen date
        ghost = self.db_manager.get_ghost_by_id(cve_id)
        if not ghost:
            logger.warning(f"Ghost record not found for {cve_id}")
            return

        first_discovered = ghost.first_seen

        # Calculate resolution time
        resolution_time = resolved_date - first_discovered
        resolution_days = resolution_time.total_seconds() / 86400

        # Find earliest source (the one that gets credit)
        earliest_source = min(sources, key=lambda s: s.discovered_at)

        logger.debug(
            f"Resolution time: {resolution_days:.2f} days, "
            f"earliest source: {earliest_source.source_name}"
        )

        # Record resolution outcome for the earliest source
        self.reliability_tracker.record_resolution(
            source_name=earliest_source.source_name,
            resolution_days=resolution_days,
            timestamp=datetime.now(timezone.utc)
        )

        # Store resolution pattern in history
        self.db_manager.store_resolution_pattern(
            cve_id=cve_id,
            first_discovered=first_discovered,
            resolved_date=resolved_date,
            resolution_time_days=resolution_days,
            cna_name=cna_name,
            first_source_name=earliest_source.source_name,
            first_source_type=earliest_source.source_type,
            root_cause=root_cause,
            was_true_ghost=was_true_ghost,
            ghost_confidence_at_peak=ghost_confidence
        )

        # Update CNA patterns if CNA provided
        if cna_name:
            self.cna_learning.update_cna_patterns(
                cna_name=cna_name,
                resolution_days=resolution_days,
                was_ghost=was_true_ghost
            )

        # Check if we should recalculate
        if self.reliability_tracker._should_recalculate():
            logger.info("Triggering reliability recalculation")
            self.reliability_tracker.recalculate_all()

        logger.info(f"Learning complete for {cve_id}")
