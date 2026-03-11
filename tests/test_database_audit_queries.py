"""Tests for database audit query methods."""
import pytest
from datetime import datetime, timedelta, timezone
from src.storage.database import DatabaseManager
from src.discovery.base import DiscoveryResult
from src.registry.validator import ValidationResult
from src.models.enums import CVEStatus


@pytest.fixture
def test_db(tmp_path):
    """Create test database with sample data."""
    db_path = tmp_path / "test_audit.db"
    db = DatabaseManager(str(db_path))
    db.initialize()

    # Insert test data using record_discovery
    # Source 1: test_rss_feed
    discovery1 = DiscoveryResult(
        cve_id="CVE-2025-0001",
        source_name="test_rss_feed",
        source_type="rss",
        discovered_at=datetime.now(timezone.utc) - timedelta(days=10),
        evidence_url="https://example.com/1",
        context="Test vulnerability 1",
        confidence=0.9,
        raw_data={}
    )
    validation1 = ValidationResult(
        cve_id="CVE-2025-0001",
        status=CVEStatus.RESERVED,
        is_ghost=True,
        registry_source="CVE.org",
        description="Reserved CVE",
        published_date=None,
        raw_response={}
    )
    db.record_discovery(discovery1, validation1)

    discovery2 = DiscoveryResult(
        cve_id="CVE-2025-0002",
        source_name="test_rss_feed",
        source_type="rss",
        discovered_at=datetime.now(timezone.utc) - timedelta(days=5),
        evidence_url="https://example.com/2",
        context="Test vulnerability 2",
        confidence=0.8,
        raw_data={}
    )
    validation2 = ValidationResult(
        cve_id="CVE-2025-0002",
        status=CVEStatus.PUBLISHED,
        is_ghost=False,
        registry_source="CVE.org",
        description="Published CVE",
        published_date=datetime.now(timezone.utc),
        raw_response={}
    )
    db.record_discovery(discovery2, validation2)

    # Source 2: test_api
    discovery3 = DiscoveryResult(
        cve_id="CVE-2025-0003",
        source_name="test_api",
        source_type="api",
        discovered_at=datetime.now(timezone.utc) - timedelta(days=3),
        evidence_url="https://api.example.com/3",
        context="API vulnerability",
        confidence=0.95,
        raw_data={}
    )
    validation3 = ValidationResult(
        cve_id="CVE-2025-0003",
        status=CVEStatus.RESERVED,
        is_ghost=True,
        registry_source="CVE.org",
        description="Reserved CVE from API",
        published_date=None,
        raw_response={}
    )
    db.record_discovery(discovery3, validation3)

    return db


def test_get_all_sources(test_db):
    """Test retrieving all unique source names."""
    sources = test_db.get_all_sources()

    assert isinstance(sources, list)
    assert len(sources) >= 2
    assert "test_rss_feed" in sources
    assert "test_api" in sources
    assert all(isinstance(s, str) for s in sources)


def test_get_source_discoveries(test_db):
    """Test retrieving discoveries for a specific source."""
    discoveries = test_db.get_source_discoveries("test_rss_feed")

    assert isinstance(discoveries, list)
    assert len(discoveries) == 2
    for d in discoveries:
        assert "cve_id" in d
        assert "is_ghost" in d
        assert "discovered_at" in d
        assert "registry_status" in d

    # Check specific CVEs are present
    cve_ids = [d["cve_id"] for d in discoveries]
    assert "CVE-2025-0001" in cve_ids
    assert "CVE-2025-0002" in cve_ids


def test_get_source_discoveries_empty(test_db):
    """Test retrieving discoveries for non-existent source."""
    discoveries = test_db.get_source_discoveries("non_existent_source")

    assert isinstance(discoveries, list)
    assert len(discoveries) == 0


def test_get_source_resolution_history(test_db):
    """Test retrieving resolution history for a source."""
    # First, we need to populate resolution history
    # For now, test that the method exists and returns empty list
    history = test_db.get_source_resolution_history("test_rss_feed")

    assert isinstance(history, list)
    # Will be empty until we implement resolution tracking
    for h in history:
        assert "cve_id" in h
        assert "resolution_days" in h
        assert "was_true_ghost" in h
