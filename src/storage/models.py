"""
Database Models
===============

SQLAlchemy models for Ghost Hunter persistence layer.
Defines the schema for tracking Ghost CVEs and their discovery sources.

Author: rogolabs.net
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""
    pass


class GhostCVE(Base):
    """
    Model for tracking Ghost CVE discoveries.
    
    Stores CVE identifiers that have been found in public sources
    along with their validation status and discovery metadata.
    
    Attributes:
        id: Primary key
        cve_id: The CVE identifier (e.g., CVE-2025-12345)
        first_seen: Timestamp when this CVE was first discovered
        last_checked: Timestamp of most recent status check
        registry_status: Current status from official registry
        is_ghost: Whether this CVE is classified as a Ghost
        days_in_limbo: Number of days since first_seen (computed)
        description: CVE description if available from registry
        registry_source: Which registry provided the status
        confidence_score: Average confidence across all discoveries
        discovery_count: Number of times this CVE was discovered
        sources: Relationship to DiscoverySource records
    """
    
    __tablename__ = "ghost_cves"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    
    # Discovery timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_checked: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Registry validation
    registry_status: Mapped[str] = mapped_column(String(20), nullable=False)
    is_ghost: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # Additional metadata
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    registry_source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    discovery_count: Mapped[int] = mapped_column(Integer, default=1)
    
    # Relationships
    sources: Mapped[list["DiscoverySource"]] = relationship(
        "DiscoverySource",
        back_populates="ghost_cve",
        cascade="all, delete-orphan",
    )
    
    # Indexes
    __table_args__ = (
        Index("ix_ghost_cves_is_ghost", "is_ghost"),
        Index("ix_ghost_cves_first_seen", "first_seen"),
        Index("ix_ghost_cves_registry_status", "registry_status"),
    )
    
    @property
    def days_in_limbo(self) -> int:
        """
        Calculate days since first discovery.
        
        Returns:
            Number of days since first_seen
        """
        delta = datetime.now(timezone.utc) - self.first_seen
        return delta.days
    
    def __repr__(self) -> str:
        """String representation of GhostCVE."""
        return (
            f"GhostCVE("
            f"cve_id='{self.cve_id}', "
            f"is_ghost={self.is_ghost}, "
            f"status='{self.registry_status}', "
            f"days_in_limbo={self.days_in_limbo})"
        )


class DiscoverySource(Base):
    """
    Model for tracking individual discovery events.
    
    Records each instance where a CVE was found in a public source,
    maintaining a history of evidence URLs and discovery contexts.
    
    Attributes:
        id: Primary key
        ghost_cve_id: Foreign key to GhostCVE
        source_type: Classification of the source
        source_name: Human-readable source name
        evidence_url: Direct URL to the CVE mention
        discovered_at: Timestamp of discovery
        context: Surrounding text/context of the mention
        confidence: Confidence score for this discovery
        raw_data_json: JSON blob of raw discovery data
    """
    
    __tablename__ = "discovery_sources"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ghost_cve_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("ghost_cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # Source identification
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_name: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence_url: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Discovery metadata
    discovered_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    raw_data_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Relationships
    ghost_cve: Mapped["GhostCVE"] = relationship(
        "GhostCVE",
        back_populates="sources",
    )
    
    # Indexes and constraints
    __table_args__ = (
        Index("ix_discovery_sources_source_type", "source_type"),
        Index("ix_discovery_sources_discovered_at", "discovered_at"),
        UniqueConstraint(
            "ghost_cve_id", "evidence_url",
            name="uq_ghost_cve_evidence"
        ),
    )
    
    def __repr__(self) -> str:
        """String representation of DiscoverySource."""
        return (
            f"DiscoverySource("
            f"cve_id={self.ghost_cve_id}, "
            f"source='{self.source_name}', "
            f"type='{self.source_type}')"
        )


class HuntRun(Base):
    """
    Model for tracking hunt execution history.
    
    Records metadata about each hunt run including timing,
    results counts, and any errors encountered.
    
    Attributes:
        id: Primary key
        started_at: Hunt start timestamp
        completed_at: Hunt completion timestamp
        total_cves_found: Number of CVE mentions discovered
        new_ghosts_found: Number of new Ghost CVEs identified
        total_ghosts: Total Ghost CVEs after this run
        modules_run: Comma-separated list of discovery modules
        errors: JSON blob of any errors encountered
        success: Whether the hunt completed successfully
    """
    
    __tablename__ = "hunt_runs"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Results
    total_cves_found: Mapped[int] = mapped_column(Integer, default=0)
    new_ghosts_found: Mapped[int] = mapped_column(Integer, default=0)
    total_ghosts: Mapped[int] = mapped_column(Integer, default=0)
    
    # Execution details
    modules_run: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    errors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Index
    __table_args__ = (
        Index("ix_hunt_runs_started_at", "started_at"),
    )
    
    @property
    def duration_seconds(self) -> float | None:
        """
        Calculate hunt duration in seconds.
        
        Returns:
            Duration in seconds or None if not completed
        """
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()
    
    def __repr__(self) -> str:
        """String representation of HuntRun."""
        return (
            f"HuntRun("
            f"id={self.id}, "
            f"started_at='{self.started_at}', "
            f"ghosts_found={self.new_ghosts_found})"
        )
