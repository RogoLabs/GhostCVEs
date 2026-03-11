"""
Tests for Database Storage
==========================

Unit tests for the DatabaseManager and SQLAlchemy models.
"""

import pytest
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.storage.database import DatabaseManager
from src.storage.models import GhostCVE, DiscoverySource, HuntRun
from src.discovery.base import DiscoveryResult
from src.registry.validator import ValidationResult, CVEStatus


class TestDatabaseManager:
    """Tests for DatabaseManager class."""
    
    @pytest.fixture
    def db_path(self):
        """Create a temporary database path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            yield f.name
    
    @pytest.fixture
    def db_manager(self, db_path):
        """Create and initialize a DatabaseManager."""
        manager = DatabaseManager(db_path)
        manager.initialize()
        return manager
    
    def test_initialization(self, db_manager):
        """Test database initialization."""
        assert db_manager.database_path.exists()
    
    def test_record_new_discovery(self, db_manager):
        """Test recording a new CVE discovery."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo/commit/abc123",
            discovered_at=datetime.now(timezone.utc),
            confidence=0.95,
        )
        
        validation = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        ghost = db_manager.record_discovery(discovery, validation)
        
        assert ghost.cve_id == "CVE-2025-12345"
        assert ghost.is_ghost is True
        assert ghost.registry_status == "RESERVED"
    
    def test_first_seen_not_updated(self, db_manager):
        """Test that first_seen is preserved on re-discovery."""
        original_time = datetime.now(timezone.utc) - timedelta(days=5)
        
        # First discovery
        discovery1 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo/commit/abc123",
            discovered_at=original_time,
        )
        
        validation1 = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        ghost1 = db_manager.record_discovery(discovery1, validation1)
        first_seen_original = ghost1.first_seen
        
        # Second discovery (different source)
        discovery2 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="rss_feed",
            source_name="Security Blog",
            evidence_url="https://blog.example.com/cve-2025-12345",
            discovered_at=datetime.now(timezone.utc),
        )
        
        validation2 = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        ghost2 = db_manager.record_discovery(discovery2, validation2)
        
        # first_seen should NOT change
        assert ghost2.first_seen == first_seen_original
    
    def test_last_checked_updated(self, db_manager):
        """Test that last_checked is updated on re-discovery."""
        # First discovery
        discovery1 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo/commit/abc123",
        )
        
        validation1 = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        ghost1 = db_manager.record_discovery(discovery1, validation1)
        last_checked_original = ghost1.last_checked
        
        # Second discovery
        discovery2 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="rss_feed",
            source_name="Security Blog",
            evidence_url="https://blog.example.com/cve-2025-12345",
        )
        
        validation2 = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        ghost2 = db_manager.record_discovery(discovery2, validation2)
        
        # last_checked SHOULD be updated
        assert ghost2.last_checked >= last_checked_original
    
    def test_get_ghost_cves(self, db_manager):
        """Test retrieving Ghost CVEs."""
        # Create a ghost CVE
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        validation = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        db_manager.record_discovery(discovery, validation)
        
        # Retrieve ghosts
        ghosts = db_manager.get_ghost_cves(only_ghosts=True)
        
        assert len(ghosts) == 1
        assert ghosts[0].cve_id == "CVE-2025-12345"
    
    def test_get_statistics(self, db_manager):
        """Test getting database statistics."""
        # Create some test data
        for i in range(3):
            discovery = DiscoveryResult(
                cve_id=f"CVE-2025-{12345 + i}",
                source_type="github_commit",
                source_name="Test Repository",
                evidence_url=f"https://github.com/test/repo/{i}",
            )
            
            validation = ValidationResult(
                cve_id=f"CVE-2025-{12345 + i}",
                status=CVEStatus.RESERVED if i < 2 else CVEStatus.PUBLISHED,
                is_ghost=i < 2,
                registry_source="NVD",
            )
            
            db_manager.record_discovery(discovery, validation)
        
        stats = db_manager.get_statistics()
        
        assert stats["total_cves"] == 3
        assert stats["total_ghosts"] == 2
        assert stats["total_sources"] == 3
    
    def test_export_json(self, db_manager):
        """Test JSON export."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        validation = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        db_manager.record_discovery(discovery, validation)
        
        json_output = db_manager.export_ghosts_json()
        
        assert "CVE-2025-12345" in json_output
        assert "first_seen" in json_output
    
    def test_export_csv(self, db_manager):
        """Test CSV export."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        validation = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        db_manager.record_discovery(discovery, validation)
        
        csv_output = db_manager.export_ghosts_csv()
        
        assert "CVE ID" in csv_output  # Header
        assert "CVE-2025-12345" in csv_output


class TestGhostCVEModel:
    """Tests for GhostCVE model."""
    
    def test_days_in_limbo(self):
        """Test days_in_limbo calculation."""
        ghost = GhostCVE(
            cve_id="CVE-2025-12345",
            first_seen=datetime.now(timezone.utc) - timedelta(days=10),
            last_checked=datetime.now(timezone.utc),
            registry_status="RESERVED",
            is_ghost=True,
        )
        
        assert ghost.days_in_limbo == 10
    
    def test_repr(self):
        """Test string representation."""
        ghost = GhostCVE(
            cve_id="CVE-2025-12345",
            first_seen=datetime.now(timezone.utc),
            last_checked=datetime.now(timezone.utc),
            registry_status="RESERVED",
            is_ghost=True,
        )
        
        repr_str = repr(ghost)
        
        assert "CVE-2025-12345" in repr_str
        assert "is_ghost=True" in repr_str
