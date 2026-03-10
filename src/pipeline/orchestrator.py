"""
Pipeline Orchestrator
=====================

Master orchestrator that coordinates all 6 stages of the Ghost CVE detection pipeline:
1. Discovery - Find CVE mentions across 23 sources
2. Disclosure Classification - Analyze public disclosure status
3. Multi-Source Validation - CVE.org API + local registries
4. Ghost Analysis - Apply 6-hour grace period and confidence threshold
5. Root Cause Detection - Determine why CVE is a ghost
6. Continuous Learning - Track resolutions and update reliability scores

This is the critical integration layer that ties all components together
into a cohesive world-class detection system.

Author: rogolabs.net
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from src.discovery.base import DiscoveryResult, BaseDiscovery
from src.models.dataclasses import (
    DisclosureClassification,
    GhostAnalysis,
)
from src.models.enums import CVEStatus, GhostRootCause
from src.pipeline.disclosure_classifier import DisclosureClassifier
from src.pipeline.ghost_analyzer import GhostAnalyzer
from src.pipeline.root_cause_detector import RootCauseDetector
from src.pipeline.learning_system import SourceReliabilityTracker
from src.registry.multi_source_validator import MultiSourceValidator
from src.registry.validator import ValidationResult
from src.storage.database import DatabaseManager
from src.storage.models import GhostCVE


logger = logging.getLogger(__name__)


@dataclass
class ProcessedCVE:
    """
    Result of processing a CVE through the 6-stage pipeline.

    Attributes:
        cve_id: The CVE identifier
        is_ghost: Whether this CVE is classified as a Ghost
        status: Current registry status
        first_seen: When this CVE was first discovered
        sources: List of source names that discovered this CVE
        confidence: Average confidence score across all sources
        disclosure: Disclosure classification result
        ghost_analysis: Ghost analysis result
        root_cause: Root cause if CVE is a ghost
        description: CVE description if available
    """
    cve_id: str
    is_ghost: bool
    status: str
    first_seen: datetime
    disclosure: DisclosureClassification
    ghost_analysis: GhostAnalysis
    sources: List[str] = field(default_factory=list)
    confidence: float = 1.0
    root_cause: Optional[GhostRootCause] = None
    description: Optional[str] = None


@dataclass
class PipelineStats:
    """
    Statistics from a pipeline run.

    Attributes:
        total_discoveries: Total number of CVE discoveries processed
        unique_cves: Number of unique CVE IDs found
        ghosts_found: Number of Ghost CVEs identified
        published_found: Number of published CVEs found
        sources_used: List of discovery source names used
        errors: Number of errors encountered
        duration_seconds: Total pipeline execution time
        started_at: Pipeline start timestamp
    """
    total_discoveries: int = 0
    unique_cves: int = 0
    ghosts_found: int = 0
    published_found: int = 0
    sources_used: List[str] = field(default_factory=list)
    errors: int = 0
    duration_seconds: float = 0.0
    started_at: Optional[datetime] = None


class PipelineOrchestrator:
    """
    Master orchestrator for the 6-stage Ghost CVE detection pipeline.

    Coordinates all stages from discovery through continuous learning:
    - Stage 1: Discovery (handled by discovery modules)
    - Stage 2: Disclosure Classification
    - Stage 3: Multi-Source Validation
    - Stage 4: Ghost Analysis
    - Stage 5: Root Cause Detection
    - Stage 6: Continuous Learning

    Attributes:
        db: Database manager for persistence
        disclosure_classifier: Stage 2 - Disclosure classification
        multi_source_validator: Stage 3 - Multi-source validation
        ghost_analyzer: Stage 4 - Ghost analysis with confidence scoring
        root_cause_detector: Stage 5 - Root cause detection
        learning_system: Stage 6 - Source reliability tracker
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        """
        Initialize the pipeline orchestrator with all V2 components.

        Args:
            db_manager: Database manager instance for persistence
        """
        self.db = db_manager
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Initialize V2 pipeline components
        self.disclosure_classifier = DisclosureClassifier()
        self.multi_source_validator = MultiSourceValidator()
        self.learning_system = SourceReliabilityTracker(db_manager)
        self.ghost_analyzer = GhostAnalyzer(reliability_tracker=self.learning_system)
        self.root_cause_detector = RootCauseDetector()

        # Track processed CVEs to avoid duplicates within a run
        self._processed_cves: dict[str, ProcessedCVE] = {}

        # Track discoveries per CVE for multi-source aggregation
        self._discoveries_by_cve: dict[str, List[DiscoveryResult]] = {}

    def ensure_resources(self) -> bool:
        """
        Ensure all required resources are available.

        Initializes database schema with V2 tables and ensures local
        registries are ready for multi-source validation.

        Returns:
            True if resources are ready, False otherwise
        """
        try:
            # Initialize database with V2 schema
            self.db.initialize()

            # Multi-source validator will initialize local registries lazily
            # on first validation attempt (with fallback to CVE.org API)
            self.logger.info("Resources initialized - multi-source validation ready")

            return True

        except Exception as e:
            self.logger.error(f"Failed to ensure resources: {e}")
            return False

    def process_discovery(
        self,
        discovery: DiscoveryResult,
    ) -> Optional[ProcessedCVE]:
        """
        Process a single discovery through the 6-stage pipeline.

        Stages:
        1. Discovery (already done by discovery module)
        2. Disclosure Classification - Analyze public disclosure status
        3. Multi-Source Validation - Check CVE.org API + local registries
        4. Ghost Analysis - Apply grace period and confidence threshold
        5. Root Cause Detection - Determine why CVE is a ghost
        6. Storage - Record in database with all metadata

        Args:
            discovery: Discovery result to process

        Returns:
            ProcessedCVE if successful, None if error occurred
        """
        try:
            self.logger.debug(f"Processing discovery: {discovery.cve_id}")

            # Track this discovery for multi-source aggregation
            if discovery.cve_id not in self._discoveries_by_cve:
                self._discoveries_by_cve[discovery.cve_id] = []
            self._discoveries_by_cve[discovery.cve_id].append(discovery)

            # Get all discoveries for this CVE
            all_discoveries = self._discoveries_by_cve[discovery.cve_id]

            # Stage 2: Disclosure Classification
            disclosure = self.disclosure_classifier.classify(discovery)
            self.logger.debug(
                f"Disclosure classification for {discovery.cve_id}: "
                f"status={disclosure.status.value}, confidence={disclosure.confidence:.2f}"
            )

            # Stage 3: Multi-Source Validation
            validation = self.multi_source_validator.validate(
                discovery.cve_id,
                found_in_wild=True
            )
            self.logger.debug(
                f"Validation result for {discovery.cve_id}: "
                f"status={validation.status.value}"
            )

            # Stage 4: Ghost Analysis
            ghost_analysis = self.ghost_analyzer.analyze(
                discoveries=all_discoveries,
                disclosure=disclosure,
                validation=validation,
            )
            self.logger.debug(
                f"Ghost analysis for {discovery.cve_id}: "
                f"is_ghost={ghost_analysis.is_ghost}, confidence={ghost_analysis.confidence:.2f}"
            )

            # Stage 5: Root Cause Detection (if ghost)
            root_cause = None
            if ghost_analysis.is_ghost:
                root_cause = self.root_cause_detector.detect(
                    discovery=discovery,
                    disclosure=disclosure,
                    ghost_analysis=ghost_analysis,
                    validation=validation,
                )
                self.logger.info(
                    f"Ghost CVE detected: {discovery.cve_id} "
                    f"(root_cause: {root_cause.value}, confidence: {ghost_analysis.confidence:.0%})"
                )

            # Stage 6: Store in database (part of learning system)
            # TODO: Replace this with proper V2 database storage
            ghost_cve = self.db.record_discovery(discovery, validation)

            # Create processed result
            processed = ProcessedCVE(
                cve_id=discovery.cve_id,
                is_ghost=ghost_analysis.is_ghost,
                status=validation.status.value,
                first_seen=ghost_cve.first_seen if ghost_cve else datetime.utcnow(),
                disclosure=disclosure,
                ghost_analysis=ghost_analysis,
                sources=[d.source_name for d in all_discoveries],
                confidence=ghost_analysis.confidence,
                root_cause=root_cause,
                description=validation.raw_response.get('description') if validation.raw_response else None,
            )

            return processed

        except Exception as e:
            self.logger.error(
                f"Error processing discovery {discovery.cve_id}: {e}",
                exc_info=True
            )
            return None

    def run_full_pipeline(
        self,
        discovery_sources: List[BaseDiscovery],
    ) -> PipelineStats:
        """
        Run the complete Ghost CVE detection pipeline.

        Executes all discovery sources, validates findings, and stores results.
        Provides comprehensive statistics about the run.

        Args:
            discovery_sources: List of discovery sources to run

        Returns:
            PipelineStats with execution statistics
        """
        start_time = datetime.utcnow()
        stats = PipelineStats(started_at=start_time)

        self.logger.info(
            f"Starting pipeline with {len(discovery_sources)} discovery sources"
        )

        # Reset processed CVEs tracker and discoveries aggregator
        self._processed_cves = {}
        self._discoveries_by_cve = {}

        # Track unique CVE IDs seen
        unique_cves_seen: set[str] = set()

        # Execute each discovery source
        for source in discovery_sources:
            try:
                self.logger.info(f"Running discovery source: {source.name}")
                stats.sources_used.append(source.name)

                # Run discovery
                discoveries = source.run()

                self.logger.info(
                    f"Discovery source '{source.name}' found {len(discoveries)} CVE mentions"
                )

                # Process each discovery
                for discovery in discoveries:
                    stats.total_discoveries += 1
                    unique_cves_seen.add(discovery.cve_id)

                    # Process through pipeline
                    processed = self.process_discovery(discovery)

                    if processed is None:
                        stats.errors += 1
                        continue

                    # Update statistics
                    if processed.is_ghost:
                        stats.ghosts_found += 1
                    else:
                        stats.published_found += 1

                    # Track processed CVE
                    if processed.cve_id in self._processed_cves:
                        # Add source to existing entry
                        existing = self._processed_cves[processed.cve_id]
                        if discovery.source_name not in existing.sources:
                            existing.sources.append(discovery.source_name)
                    else:
                        self._processed_cves[processed.cve_id] = processed

            except Exception as e:
                self.logger.error(
                    f"Error running discovery source '{source.name}': {e}",
                    exc_info=True
                )
                stats.errors += 1

        # Calculate final statistics
        stats.unique_cves = len(unique_cves_seen)
        end_time = datetime.utcnow()
        stats.duration_seconds = (end_time - start_time).total_seconds()

        # Log summary
        self.logger.info(
            f"Pipeline completed in {stats.duration_seconds:.2f}s: "
            f"{stats.total_discoveries} discoveries, "
            f"{stats.unique_cves} unique CVEs, "
            f"{stats.ghosts_found} ghosts found, "
            f"{stats.published_found} published CVEs, "
            f"{stats.errors} errors"
        )

        return stats

    def check_for_resolutions(self) -> int:
        """
        Check existing Ghost CVEs for resolution (RESERVED -> PUBLISHED).

        Part of Stage 6 (Continuous Learning): Scans all tracked Ghost CVEs,
        re-validates them, and records resolutions in the learning system
        to update source reliability scores.

        Returns:
            Number of Ghost CVEs that were resolved
        """
        self.logger.info("Checking for Ghost CVE resolutions...")

        try:
            # Get all current ghosts
            ghosts = self.db.get_ghost_cves(only_ghosts=True)

            if not ghosts:
                self.logger.info("No Ghost CVEs to check")
                return 0

            self.logger.info(f"Checking {len(ghosts)} Ghost CVEs for resolutions")

            resolved_count = 0

            # Check each ghost
            for ghost in ghosts:
                try:
                    # Re-validate the CVE with multi-source validation
                    validation = self.multi_source_validator.validate(
                        ghost.cve_id,
                        found_in_wild=True
                    )

                    # Check if status changed to PUBLISHED
                    if validation.status == CVEStatus.PUBLISHED and ghost.is_ghost:
                        self.logger.info(
                            f"Ghost CVE resolved: {ghost.cve_id} "
                            f"(RESERVED -> PUBLISHED)"
                        )

                        # Calculate resolution time
                        resolution_days = (datetime.utcnow() - ghost.first_seen).total_seconds() / 86400

                        # Record resolution in learning system for each source
                        sources = self.db.get_sources_for_cve(ghost.cve_id)
                        for source in sources:
                            self.learning_system.record_resolution(
                                source_name=source.source_name,
                                resolution_days=resolution_days,
                                timestamp=datetime.utcnow()
                            )
                            self.logger.debug(
                                f"Recorded resolution for source {source.source_name}: "
                                f"{resolution_days:.1f} days"
                            )

                        # Update the record
                        with self.db.get_session() as session:
                            ghost.registry_status = validation.status.value
                            ghost.is_ghost = False
                            ghost.last_checked = datetime.utcnow()

                            if validation.raw_response and 'description' in validation.raw_response:
                                ghost.description = validation.raw_response['description']

                            session.add(ghost)
                            session.commit()

                        resolved_count += 1

                    elif validation.status != CVEStatus.PUBLISHED:
                        # Still a ghost, just update last_checked
                        with self.db.get_session() as session:
                            ghost.last_checked = datetime.utcnow()
                            ghost.registry_status = validation.status.value
                            session.add(ghost)
                            session.commit()

                except Exception as e:
                    self.logger.error(
                        f"Error checking resolution for {ghost.cve_id}: {e}"
                    )

            # Recalculate source reliability scores after recording resolutions
            if resolved_count > 0:
                self.logger.info("Recalculating source reliability scores...")
                self.learning_system.recalculate_all_sources()
                self.logger.info(
                    f"Resolution check complete: {resolved_count} Ghost CVEs resolved"
                )
            else:
                self.logger.info("Resolution check complete: No resolutions found")

            return resolved_count

        except Exception as e:
            self.logger.error(f"Error during resolution check: {e}", exc_info=True)
            return 0

    def get_processed_cves(self) -> List[ProcessedCVE]:
        """
        Get list of CVEs processed in the current run.

        Returns:
            List of ProcessedCVE objects from the current run
        """
        return list(self._processed_cves.values())

    def get_pipeline_summary(self) -> dict:
        """
        Get a summary of the pipeline state.

        Returns:
            Dictionary with summary information
        """
        try:
            db_stats = self.db.get_statistics()

            return {
                "total_cves_tracked": db_stats.get("total_cves", 0),
                "total_ghosts": db_stats.get("total_ghosts", 0),
                "total_sources": db_stats.get("total_sources", 0),
                "oldest_ghost": db_stats.get("oldest_ghost"),
                "oldest_ghost_days": db_stats.get("oldest_ghost_days", 0),
                "status_breakdown": db_stats.get("status_breakdown", {}),
                "source_type_breakdown": db_stats.get("source_type_breakdown", {}),
            }
        except Exception as e:
            self.logger.error(f"Error getting pipeline summary: {e}")
            return {}
