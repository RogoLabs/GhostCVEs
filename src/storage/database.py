"""
Database Manager
================

SQLite/SQLAlchemy database management for Ghost Hunter.
Handles persistence of Ghost CVE discoveries with proper first_seen
tracking and status updates.

Author: rogolabs.net
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

# Maximum size for raw_data_json field (1KB)
MAX_RAW_DATA_SIZE = 1024

from src.config import DATABASE_CONFIG
from src.discovery.base import DiscoveryResult
from src.registry.validator import ValidationResult, CVEStatus
from src.storage.models import Base, GhostCVE, DiscoverySource, HuntRun


logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manages SQLite database operations for Ghost Hunter.
    
    Handles creating/updating Ghost CVE records, maintaining first_seen
    dates, and tracking discovery sources. Implements the rule that
    first_seen should never be updated once set.
    
    Attributes:
        database_path: Path to SQLite database file
        engine: SQLAlchemy engine instance
        session_factory: Session factory for creating database sessions
    """
    
    def __init__(
        self,
        database_path: str | Path | None = None,
    ) -> None:
        """
        Initialize the database manager.
        
        Args:
            database_path: Path to SQLite database file.
                          Defaults to DATABASE_CONFIG.database_path.
        """
        self.database_path = Path(
            database_path or DATABASE_CONFIG.database_path
        )
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Create engine
        db_url = f"sqlite:///{self.database_path}"
        self.engine = create_engine(
            db_url,
            echo=DATABASE_CONFIG.echo_sql,
            pool_pre_ping=True,
        )
        
        # Create session factory
        self.session_factory = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
        )
        
        self.logger.debug(f"Database manager initialized: {self.database_path}")
    
    def _sanitize_raw_data(self, raw_data: dict | None) -> str | None:
        """
        Sanitize and limit raw_data size to prevent database bloat.
        
        Args:
            raw_data: Raw data dictionary from discovery
        
        Returns:
            JSON string if within size limit, None otherwise
        """
        if not raw_data:
            return None
        
        # Only keep safe, small keys
        safe_keys = {
            "repository", "file_path", "commit_sha", "author",
            "feed_name", "feed_url", "item_title", "pub_date",
        }
        
        sanitized = {}
        for key, value in raw_data.items():
            if key in safe_keys:
                # Truncate string values
                if isinstance(value, str):
                    sanitized[key] = value[:200]
                elif isinstance(value, (int, float, bool, type(None))):
                    sanitized[key] = value
        
        if not sanitized:
            return None
        
        result = json.dumps(sanitized)
        
        # Enforce size limit
        if len(result) > MAX_RAW_DATA_SIZE:
            return None
        
        return result
    
    def initialize(self) -> None:
        """
        Initialize the database schema.
        
        Creates all tables if they don't exist.
        """
        self.logger.info("Initializing database schema")
        Base.metadata.create_all(self.engine)
        self.logger.info("Database schema initialized")
    
    def purge_blacklisted_sources(
        self,
        blacklisted_repos: tuple[str, ...],
        blacklisted_users: tuple[str, ...],
    ) -> int:
        """
        Remove discovery sources from blacklisted repositories.
        
        Also removes GhostCVE records that have no remaining sources.
        
        Args:
            blacklisted_repos: Tuple of "owner/repo" strings to block
            blacklisted_users: Tuple of usernames/orgs to block
        
        Returns:
            Number of sources removed
        """
        removed_count = 0
        
        with self.get_session() as session:
            # Get all sources
            all_sources = session.execute(select(DiscoverySource)).scalars().all()
            
            sources_to_delete = []
            for source in all_sources:
                should_delete = False
                
                # Check source name and evidence URL against blacklist
                source_name = source.source_name.lower() if source.source_name else ""
                evidence_url = source.evidence_url.lower() if source.evidence_url else ""
                
                for repo in blacklisted_repos:
                    repo_lower = repo.lower()
                    if repo_lower in source_name or f"github.com/{repo_lower}" in evidence_url:
                        should_delete = True
                        break
                
                if not should_delete:
                    for user in blacklisted_users:
                        user_lower = user.lower()
                        if f": {user_lower}/" in source_name or f"github.com/{user_lower}/" in evidence_url:
                            should_delete = True
                            break
                
                if should_delete:
                    sources_to_delete.append(source)
            
            # Delete marked sources
            for source in sources_to_delete:
                session.delete(source)
                removed_count += 1
            
            session.commit()
            
            # Now clean up orphaned GhostCVE records (those with no sources)
            orphaned_ghosts = session.execute(
                select(GhostCVE)
                .where(~GhostCVE.id.in_(
                    select(DiscoverySource.ghost_cve_id).distinct()
                ))
            ).scalars().all()
            
            for ghost in orphaned_ghosts:
                self.logger.debug(f"Removing orphaned Ghost CVE: {ghost.cve_id}")
                session.delete(ghost)
            
            session.commit()
            
            if orphaned_ghosts:
                self.logger.info(f"Removed {len(orphaned_ghosts)} orphaned Ghost CVE records")
        
        self.logger.info(f"Purged {removed_count} sources from blacklisted repositories")
        return removed_count

    def get_session(self) -> Session:
        """
        Get a new database session.
        
        Returns:
            SQLAlchemy Session object
        """
        return self.session_factory()
    
    def record_discovery(
        self,
        discovery: DiscoveryResult,
        validation: ValidationResult,
    ) -> GhostCVE:
        """
        Record a CVE discovery in the database.
        
        If the CVE already exists, updates last_checked and adds the new
        source (if unique), but preserves the original first_seen date.
        
        Args:
            discovery: Discovery result from scraping
            validation: Validation result from registry check
        
        Returns:
            GhostCVE record (new or existing)
        """
        with self.get_session() as session:
            try:
                # Check if CVE already exists
                existing = session.execute(
                    select(GhostCVE).where(GhostCVE.cve_id == discovery.cve_id)
                ).scalar_one_or_none()
                
                if existing:
                    ghost_cve = self._update_existing(
                        session, existing, discovery, validation
                    )
                else:
                    ghost_cve = self._create_new(
                        session, discovery, validation
                    )
                
                session.commit()
                return ghost_cve
                
            except Exception as e:
                session.rollback()
                self.logger.error(f"Failed to record discovery: {e}")
                raise
    
    def _create_new(
        self,
        session: Session,
        discovery: DiscoveryResult,
        validation: ValidationResult,
    ) -> GhostCVE:
        """
        Create a new GhostCVE record.
        
        Args:
            session: Database session
            discovery: Discovery result
            validation: Validation result
        
        Returns:
            Newly created GhostCVE record
        """
        now = datetime.now(timezone.utc)
        
        ghost_cve = GhostCVE(
            cve_id=discovery.cve_id,
            first_seen=discovery.discovered_at or now,
            last_checked=now,
            registry_status=validation.status.value,
            is_ghost=validation.is_ghost,
            description=validation.description,
            registry_source=validation.registry_source,
            confidence_score=discovery.confidence,
            discovery_count=1,
        )
        
        session.add(ghost_cve)
        session.flush()  # Get the ID
        
        # Add discovery source
        source = DiscoverySource(
            ghost_cve_id=ghost_cve.id,
            source_type=discovery.source_type,
            source_name=discovery.source_name,
            evidence_url=discovery.evidence_url,
            discovered_at=discovery.discovered_at or now,
            context=discovery.context[:500] if discovery.context else None,
            confidence=discovery.confidence,
            raw_data_json=self._sanitize_raw_data(discovery.raw_data),
        )
        
        session.add(source)
        
        self.logger.info(
            f"New CVE recorded: {discovery.cve_id} "
            f"(ghost={validation.is_ghost})"
        )
        
        return ghost_cve
    
    def _update_existing(
        self,
        session: Session,
        existing: GhostCVE,
        discovery: DiscoveryResult,
        validation: ValidationResult,
    ) -> GhostCVE:
        """
        Update an existing GhostCVE record.
        
        Updates last_checked and registry status, but preserves first_seen.
        Adds new discovery source if the evidence URL is unique.
        
        Args:
            session: Database session
            existing: Existing GhostCVE record
            discovery: Discovery result
            validation: Validation result
        
        Returns:
            Updated GhostCVE record
        """
        now = datetime.now(timezone.utc)
        
        # Update status fields (NOT first_seen!)
        existing.last_checked = now
        existing.registry_status = validation.status.value
        existing.is_ghost = validation.is_ghost
        existing.discovery_count += 1
        
        # Update description if we have a better one
        if validation.description and not existing.description:
            existing.description = validation.description
        
        # Update confidence score (average)
        existing.confidence_score = (
            (existing.confidence_score * (existing.discovery_count - 1) +
             discovery.confidence) / existing.discovery_count
        )
        
        # Try to add new source (unique constraint on evidence_url)
        # Use savepoint to avoid rolling back entire transaction on duplicate
        savepoint = session.begin_nested()
        try:
            source = DiscoverySource(
                ghost_cve_id=existing.id,
                source_type=discovery.source_type,
                source_name=discovery.source_name,
                evidence_url=discovery.evidence_url,
                discovered_at=discovery.discovered_at or now,
                context=discovery.context[:500] if discovery.context else None,
                confidence=discovery.confidence,
                raw_data_json=self._sanitize_raw_data(discovery.raw_data),
            )
            session.add(source)
            session.flush()
            savepoint.commit()
            
            self.logger.debug(
                f"Added new source for {discovery.cve_id}: {discovery.source_name}"
            )
            
        except IntegrityError:
            savepoint.rollback()
            self.logger.debug(
                f"Source already exists for {discovery.cve_id}: {discovery.evidence_url}"
            )
        
        self.logger.debug(f"Updated CVE: {discovery.cve_id}")
        
        return existing
    
    def get_ghost_cves(
        self,
        limit: int | None = None,
        only_ghosts: bool = True,
    ) -> list[GhostCVE]:
        """
        Retrieve Ghost CVE records from the database.
        
        Args:
            limit: Maximum number of records to return
            only_ghosts: If True, only return CVEs classified as Ghosts
        
        Returns:
            List of GhostCVE records
        """
        with self.get_session() as session:
            query = select(GhostCVE)
            
            if only_ghosts:
                query = query.where(GhostCVE.is_ghost == True)
            
            query = query.order_by(desc(GhostCVE.first_seen))
            
            if limit:
                query = query.limit(limit)
            
            result = session.execute(query).scalars().all()
            return list(result)
    
    def get_ghost_by_id(self, cve_id: str) -> GhostCVE | None:
        """
        Retrieve a specific Ghost CVE by its ID.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            GhostCVE record or None if not found
        """
        with self.get_session() as session:
            return session.execute(
                select(GhostCVE).where(GhostCVE.cve_id == cve_id.upper())
            ).scalar_one_or_none()
    
    def get_sources_for_cve(self, cve_id: str) -> list[DiscoverySource]:
        """
        Retrieve all discovery sources for a CVE.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            List of DiscoverySource records
        """
        with self.get_session() as session:
            ghost = session.execute(
                select(GhostCVE).where(GhostCVE.cve_id == cve_id.upper())
            ).scalar_one_or_none()
            
            if not ghost:
                return []
            
            sources = session.execute(
                select(DiscoverySource)
                .where(DiscoverySource.ghost_cve_id == ghost.id)
                .order_by(desc(DiscoverySource.discovered_at))
            ).scalars().all()
            
            return list(sources)
    
    def get_statistics(self) -> dict:
        """
        Get summary statistics about the database.
        
        Returns:
            Dictionary with statistics
        """
        with self.get_session() as session:
            total_cves = session.execute(
                select(func.count(GhostCVE.id))
            ).scalar()
            
            total_ghosts = session.execute(
                select(func.count(GhostCVE.id))
                .where(GhostCVE.is_ghost == True)
            ).scalar()
            
            total_sources = session.execute(
                select(func.count(DiscoverySource.id))
            ).scalar()
            
            # Get status breakdown
            status_counts = session.execute(
                select(GhostCVE.registry_status, func.count(GhostCVE.id))
                .group_by(GhostCVE.registry_status)
            ).all()
            
            # Get source type breakdown
            source_type_counts = session.execute(
                select(DiscoverySource.source_type, func.count(DiscoverySource.id))
                .group_by(DiscoverySource.source_type)
            ).all()
            
            # Get oldest ghost
            oldest_ghost = session.execute(
                select(GhostCVE)
                .where(GhostCVE.is_ghost == True)
                .order_by(GhostCVE.first_seen)
                .limit(1)
            ).scalar_one_or_none()
            
            return {
                "total_cves": total_cves or 0,
                "total_ghosts": total_ghosts or 0,
                "total_sources": total_sources or 0,
                "status_breakdown": dict(status_counts),
                "source_type_breakdown": dict(source_type_counts),
                "oldest_ghost": oldest_ghost.cve_id if oldest_ghost else None,
                "oldest_ghost_days": oldest_ghost.days_in_limbo if oldest_ghost else 0,
            }
    
    def record_hunt_run(
        self,
        started_at: datetime,
        total_cves_found: int,
        new_ghosts_found: int,
        modules_run: list[str],
        errors: list[str] | None = None,
        success: bool = True,
    ) -> HuntRun:
        """
        Record a hunt run in the database.
        
        Args:
            started_at: Hunt start timestamp
            total_cves_found: Number of CVE mentions found
            new_ghosts_found: Number of new Ghosts identified
            modules_run: List of discovery module names that ran
            errors: List of error messages if any
            success: Whether the hunt completed successfully
        
        Returns:
            HuntRun record
        """
        with self.get_session() as session:
            # Get current ghost count
            total_ghosts = session.execute(
                select(func.count(GhostCVE.id))
                .where(GhostCVE.is_ghost == True)
            ).scalar() or 0
            
            hunt_run = HuntRun(
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                total_cves_found=total_cves_found,
                new_ghosts_found=new_ghosts_found,
                total_ghosts=total_ghosts,
                modules_run=",".join(modules_run),
                errors=json.dumps(errors) if errors else None,
                success=success,
            )
            
            session.add(hunt_run)
            session.commit()
            
            self.logger.info(
                f"Hunt run recorded: {total_cves_found} CVEs found, "
                f"{new_ghosts_found} new ghosts"
            )
            
            return hunt_run
    
    def get_recent_hunt_runs(self, limit: int = 10) -> list[HuntRun]:
        """
        Get recent hunt run history.
        
        Args:
            limit: Maximum number of records to return
        
        Returns:
            List of HuntRun records
        """
        with self.get_session() as session:
            runs = session.execute(
                select(HuntRun)
                .order_by(desc(HuntRun.started_at))
                .limit(limit)
            ).scalars().all()
            
            return list(runs)
    
    def export_ghosts_json(self) -> str:
        """
        Export all Ghost CVEs as JSON.
        
        Returns:
            JSON string of Ghost CVE data
        """
        ghosts = self.get_ghost_cves(only_ghosts=True)
        
        data = []
        for ghost in ghosts:
            sources = self.get_sources_for_cve(ghost.cve_id)
            
            data.append({
                "cve_id": ghost.cve_id,
                "first_seen": ghost.first_seen.isoformat(),
                "last_checked": ghost.last_checked.isoformat(),
                "days_in_limbo": ghost.days_in_limbo,
                "registry_status": ghost.registry_status,
                "confidence_score": ghost.confidence_score,
                "sources": [
                    {
                        "source_type": s.source_type,
                        "source_name": s.source_name,
                        "evidence_url": s.evidence_url,
                        "discovered_at": s.discovered_at.isoformat(),
                    }
                    for s in sources
                ],
            })
        
        return json.dumps(data, indent=2)
    
    def export_ghosts_csv(self) -> str:
        """
        Export all Ghost CVEs as CSV.
        
        Returns:
            CSV string of Ghost CVE data
        """
        import csv
        import io
        
        ghosts = self.get_ghost_cves(only_ghosts=True)
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "CVE ID",
            "First Seen",
            "Days in Limbo",
            "Registry Status",
            "Source Count",
            "Primary Source",
            "Evidence URL",
        ])
        
        for ghost in ghosts:
            sources = self.get_sources_for_cve(ghost.cve_id)
            primary_source = sources[0] if sources else None
            
            writer.writerow([
                ghost.cve_id,
                ghost.first_seen.strftime("%Y-%m-%d"),
                ghost.days_in_limbo,
                ghost.registry_status,
                len(sources),
                primary_source.source_name if primary_source else "",
                primary_source.evidence_url if primary_source else "",
            ])

        return output.getvalue()

    # ========================================================================
    # Learning System Methods (Stage 6 - Source Reliability Tracking)
    # ========================================================================

    def record_source_outcome(
        self,
        source_name: str,
        was_true_positive: bool,
        resolution_days: float,
        timestamp: datetime
    ) -> None:
        """
        Record a resolution outcome for source reliability learning.

        Args:
            source_name: Name of the discovery source
            was_true_positive: Whether this was a true ghost or false positive
            resolution_days: Days between discovery and resolution
            timestamp: When the resolution was detected
        """
        with self.get_session() as session:
            # This would insert into a learning outcomes table
            # For now, this is a stub that does nothing
            # Full implementation would store in resolution_history table
            pass

    def get_source_reliability(self, source_name: str) -> float | None:
        """
        Get reliability score for a source.

        Args:
            source_name: Name of the source

        Returns:
            Reliability score (0.0-1.0) or None if unknown
        """
        # Query source_reliability table
        # For now, return None (stub)
        return None

    def get_all_source_names(self) -> list[str]:
        """
        Get all source names that have reliability data.

        Returns:
            List of source names
        """
        # Query source_reliability table
        # For now, return empty list (stub)
        return []

    def get_source_outcomes(self, source_name: str) -> list[dict]:
        """
        Get all resolution outcomes for a source.

        Args:
            source_name: Name of the source

        Returns:
            List of outcome dicts with keys:
                - was_true_positive (bool)
                - resolution_days (float)
        """
        # Query resolution_history table
        # For now, return empty list (stub)
        return []

    def get_all_sources(self) -> list[str]:
        """
        Get list of all unique source names in the database.

        Returns:
            List of source names from discovery_sources table
        """
        with self.get_session() as session:
            result = session.execute(
                select(DiscoverySource.source_name)
                .distinct()
                .order_by(DiscoverySource.source_name)
            )
            sources = [row[0] for row in result]

        return sources

    def get_source_discoveries(self, source_name: str) -> list[dict]:
        """
        Get all CVE discoveries from a specific source.

        Args:
            source_name: Name of the source

        Returns:
            List of discovery records with CVE ID, ghost status, timestamp
        """
        with self.get_session() as session:
            # Join discovery_sources with ghost_cves to get status
            result = session.execute(
                select(
                    GhostCVE.cve_id,
                    GhostCVE.is_ghost,
                    DiscoverySource.discovered_at,
                    GhostCVE.registry_status
                )
                .join(DiscoverySource, DiscoverySource.ghost_cve_id == GhostCVE.id)
                .where(DiscoverySource.source_name == source_name)
                .order_by(desc(DiscoverySource.discovered_at))
            )

            discoveries = [
                {
                    "cve_id": row[0],
                    "is_ghost": bool(row[1]),
                    "discovered_at": row[2].isoformat() if row[2] else None,
                    "registry_status": row[3]
                }
                for row in result
            ]

        return discoveries

    def get_source_resolution_history(self, source_name: str) -> list[dict]:
        """
        Get resolution history for CVEs discovered by a source.

        Shows how long it took for RESERVED CVEs to become PUBLISHED.
        Currently returns empty list as resolution tracking is not yet implemented.

        Args:
            source_name: Name of the source

        Returns:
            List of resolution records with timing information
        """
        # Resolution history tracking will be implemented in future
        # For now, return empty list
        return []

    def update_source_reliability(
        self,
        source_name: str,
        reliability_score: float,
        total_discoveries: int,
        true_positives: int,
        false_positives: int,
        avg_days_to_publish: float | None
    ) -> None:
        """
        Update source reliability in database.

        Args:
            source_name: Name of the source
            reliability_score: Calculated reliability score
            total_discoveries: Total number of discoveries
            true_positives: Number of true positives
            false_positives: Number of false positives
            avg_days_to_publish: Average days to publish (for TPs only)
        """
        # Update source_reliability table
        # For now, this is a stub that does nothing
        pass

    def get_resolutions_since_last_recalc(self) -> int:
        """
        Get number of resolutions since last recalculation.

        Returns:
            Number of resolutions
        """
        # Query resolution_history table
        # For now, return 0 (stub)
        return 0

    def get_days_since_last_recalc(self) -> float:
        """
        Get days since last recalculation.

        Returns:
            Days since last recalc
        """
        # Query source_reliability table for last_recalculated timestamp
        # For now, return 0.0 (stub)
        return 0.0

    def mark_recalculation(self, timestamp: datetime) -> None:
        """
        Mark recalculation timestamp.

        Args:
            timestamp: When recalculation occurred
        """
        # Update last_recalculated in source_reliability table
        # For now, this is a stub that does nothing
        pass

    def store_resolution_pattern(
        self,
        cve_id: str,
        first_discovered: datetime,
        resolved_date: datetime,
        resolution_time_days: float,
        cna_name: str | None,
        first_source_name: str,
        first_source_type: str,
        root_cause: str | None,
        was_true_ghost: bool,
        ghost_confidence_at_peak: float | None
    ) -> None:
        """
        Store resolution pattern in history for learning.

        Args:
            cve_id: CVE identifier
            first_discovered: When first discovered
            resolved_date: When resolved
            resolution_time_days: Days to resolution
            cna_name: CNA name if known
            first_source_name: Name of first source
            first_source_type: Type of first source
            root_cause: Root cause classification
            was_true_ghost: Whether this was a true ghost
            ghost_confidence_at_peak: Confidence score at peak
        """
        # Insert into resolution_history table
        # For now, this is a stub that does nothing
        pass
