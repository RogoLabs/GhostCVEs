"""
Pipeline Orchestrator
=====================

Master orchestrator that coordinates all stages of the Ghost CVE detection pipeline:
1. Discovery - Find CVE mentions in public sources
2. Validation - Check CVE status against registries
3. Storage - Record discoveries in database
4. Resolution Tracking - Monitor for RESERVED -> PUBLISHED transitions

This is the critical integration layer that ties all components together
into a cohesive detection system.

Author: rogolabs.net
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from src.discovery.base import DiscoveryResult, BaseDiscovery
from src.registry.validator import CVEValidator, ValidationResult, CVEStatus
from src.storage.database import DatabaseManager
from src.storage.models import GhostCVE


logger = logging.getLogger(__name__)


@dataclass
class ProcessedCVE:
    """
    Result of processing a CVE through the pipeline.

    Attributes:
        cve_id: The CVE identifier
        is_ghost: Whether this CVE is classified as a Ghost
        status: Current registry status
        first_seen: When this CVE was first discovered
        sources: List of source names that discovered this CVE
        confidence: Average confidence score
        description: CVE description if available
    """
    cve_id: str
    is_ghost: bool
    status: str
    first_seen: datetime
    sources: List[str] = field(default_factory=list)
    confidence: float = 1.0
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
    Master orchestrator for the Ghost CVE detection pipeline.

    Coordinates discovery sources, validation against registries,
    and storage in the database. Handles the complete flow from
    CVE discovery to Ghost classification and tracking.

    Attributes:
        db: Database manager for persistence
        validator: CVE validator for registry checks
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        """
        Initialize the pipeline orchestrator.

        Args:
            db_manager: Database manager instance for persistence
        """
        self.db = db_manager
        self.validator = CVEValidator(use_local=True)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Track processed CVEs to avoid duplicates within a run
        self._processed_cves: dict[str, ProcessedCVE] = {}

    def ensure_resources(self) -> bool:
        """
        Ensure all required resources are available.

        Initializes database schema and ensures local registries are ready.

        Returns:
            True if resources are ready, False otherwise
        """
        try:
            # Initialize database
            self.db.initialize()

            # Ensure local registries are available
            registries_ready = self.validator.ensure_local_registry()

            if not registries_ready:
                self.logger.warning(
                    "Local registries not available - validation will be limited"
                )

            return True

        except Exception as e:
            self.logger.error(f"Failed to ensure resources: {e}")
            return False

    def process_discovery(
        self,
        discovery: DiscoveryResult,
    ) -> Optional[ProcessedCVE]:
        """
        Process a single discovery through the pipeline.

        Validates the CVE against registries and stores it in the database.

        Args:
            discovery: Discovery result to process

        Returns:
            ProcessedCVE if successful, None if error occurred
        """
        try:
            self.logger.debug(f"Processing discovery: {discovery.cve_id}")

            # Stage 1: Validate against registries
            validation = self.validator.validate(
                discovery.cve_id,
                found_in_wild=True
            )

            self.logger.debug(
                f"Validation result for {discovery.cve_id}: "
                f"status={validation.status.value}, is_ghost={validation.is_ghost}"
            )

            # Stage 2: Store in database
            ghost_cve = self.db.record_discovery(discovery, validation)

            # Stage 3: Create processed result
            processed = ProcessedCVE(
                cve_id=ghost_cve.cve_id,
                is_ghost=ghost_cve.is_ghost,
                status=ghost_cve.registry_status,
                first_seen=ghost_cve.first_seen,
                sources=[discovery.source_name],
                confidence=discovery.confidence,
                description=validation.description,
            )

            # Log result
            if ghost_cve.is_ghost:
                self.logger.info(
                    f"Ghost CVE detected: {discovery.cve_id} "
                    f"(status: {validation.status.value})"
                )
            else:
                self.logger.debug(
                    f"Published CVE recorded: {discovery.cve_id}"
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

        # Reset processed CVEs tracker
        self._processed_cves = {}

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

        Scans all tracked Ghost CVEs and re-validates them to detect
        when they transition from RESERVED to PUBLISHED status.

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
                    # Re-validate the CVE
                    validation = self.validator.validate(
                        ghost.cve_id,
                        found_in_wild=True
                    )

                    # Check if status changed to PUBLISHED
                    if validation.status == CVEStatus.PUBLISHED and ghost.is_ghost:
                        self.logger.info(
                            f"Ghost CVE resolved: {ghost.cve_id} "
                            f"(RESERVED -> PUBLISHED)"
                        )

                        # Update the record
                        with self.db.get_session() as session:
                            ghost.registry_status = validation.status.value
                            ghost.is_ghost = False
                            ghost.last_checked = datetime.utcnow()

                            if validation.description:
                                ghost.description = validation.description

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

            if resolved_count > 0:
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
