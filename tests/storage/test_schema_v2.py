# tests/storage/test_schema_v2.py
import sqlite3
import pytest
from pathlib import Path
from src.storage.schema_v2 import create_schema_v2


def test_creates_cves_table():
    """Test cves table creation with all required columns."""
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)

    create_schema_v2(conn)

    # Check table exists
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
    assert cursor.fetchone() is not None

    # Check columns
    cursor.execute("PRAGMA table_info(cves)")
    columns = {row[1] for row in cursor.fetchall()}

    required_columns = {
        'id', 'cve_id', 'first_discovered', 'discovery_method',
        'disclosure_status', 'disclosure_type', 'public_disclosure_date',
        'cve_status', 'validated_at', 'validation_source',
        'is_ghost', 'ghost_confidence', 'grace_period_expires', 'root_cause',
        'cna_name', 'cna_confidence',
        'description', 'published_date', 'last_modified', 'resolved_date',
        'days_since_disclosure', 'days_to_resolution',
        'created_at', 'updated_at'
    }

    assert required_columns.issubset(columns)
    conn.close()


def test_creates_discovery_sources_table():
    """Test discovery_sources table with foreign key."""
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)

    create_schema_v2(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='discovery_sources'")
    assert cursor.fetchone() is not None

    cursor.execute("PRAGMA table_info(discovery_sources)")
    columns = {row[1] for row in cursor.fetchall()}

    required = {'id', 'cve_id', 'source_name', 'source_type', 'evidence_url',
                'context', 'discovered_at', 'confidence'}
    assert required.issubset(columns)
    conn.close()


def test_creates_source_reliability_table():
    """Test source_reliability table for learning system."""
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)

    create_schema_v2(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='source_reliability'")
    assert cursor.fetchone() is not None

    cursor.execute("PRAGMA table_info(source_reliability)")
    columns = {row[1] for row in cursor.fetchall()}

    required = {'source_name', 'source_type', 'reliability_score',
                'total_discoveries', 'true_positives', 'false_positives',
                'avg_days_to_publish', 'median_days_to_publish',
                'fastest_publish_days', 'slowest_publish_days',
                'last_updated', 'last_recalculated'}
    assert required.issubset(columns)
    conn.close()


def test_creates_cna_registry_table():
    """Test CNA registry table."""
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)

    create_schema_v2(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cna_registry'")
    assert cursor.fetchone() is not None
    conn.close()


def test_creates_resolution_history_table():
    """Test resolution history for learning."""
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)

    create_schema_v2(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resolution_history'")
    assert cursor.fetchone() is not None
    conn.close()


def test_creates_validation_cache_table():
    """Test validation cache table."""
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)

    create_schema_v2(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='validation_cache'")
    assert cursor.fetchone() is not None
    conn.close()


def test_creates_all_indexes():
    """Test that required indexes are created."""
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)

    create_schema_v2(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = {row[0] for row in cursor.fetchall()}

    required_indexes = {
        'idx_cves_is_ghost',
        'idx_cves_cve_status',
        'idx_cves_grace_expires',
        'idx_sources_cve_id',
        'idx_sources_name',
        'idx_resolution_cna',
        'idx_resolution_time'
    }

    assert required_indexes.issubset(indexes)
    conn.close()
