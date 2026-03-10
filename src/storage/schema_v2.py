"""
Database Schema V2 for World-Class Ghost Detection.

Fresh schema with no backward compatibility.
Designed for 6-stage pipeline with learning system.
"""

import sqlite3
from typing import Optional


def create_schema_v2(conn: sqlite3.Connection) -> None:
    """
    Create fresh database schema V2.

    Args:
        conn: SQLite connection
    """
    cursor = conn.cursor()

    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON")

    # Table 1: cves (replaces ghost_cves)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY,
            cve_id TEXT UNIQUE NOT NULL,

            -- Discovery info
            first_discovered TEXT NOT NULL,
            discovery_method TEXT,

            -- Disclosure classification
            disclosure_status TEXT NOT NULL,
            disclosure_type TEXT,
            public_disclosure_date TEXT NOT NULL,

            -- Validation status
            cve_status TEXT NOT NULL,
            validated_at TEXT NOT NULL,
            validation_source TEXT,

            -- Ghost classification
            is_ghost BOOLEAN NOT NULL,
            ghost_confidence REAL,
            grace_period_expires TEXT,
            root_cause TEXT,

            -- CNA info
            cna_name TEXT,
            cna_confidence REAL,

            -- Metadata
            description TEXT,
            published_date TEXT,
            last_modified TEXT,
            resolved_date TEXT,

            -- Computed fields
            days_since_disclosure INTEGER,
            days_to_resolution INTEGER,

            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Indexes for cves table
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_is_ghost ON cves(is_ghost)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cve_status ON cves(cve_status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_grace_expires ON cves(grace_period_expires)")

    # Table 2: discovery_sources (simplified)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS discovery_sources (
            id INTEGER PRIMARY KEY,
            cve_id TEXT NOT NULL,
            source_name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            evidence_url TEXT,
            context TEXT,
            discovered_at TEXT NOT NULL,
            confidence REAL,

            FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
        )
    """)

    # Indexes for discovery_sources
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_cve_id ON discovery_sources(cve_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_name ON discovery_sources(source_name)")

    # Table 3: source_reliability (learning system)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS source_reliability (
            source_name TEXT PRIMARY KEY,
            source_type TEXT,

            -- Performance metrics
            reliability_score REAL DEFAULT 0.75,
            total_discoveries INTEGER DEFAULT 0,
            true_positives INTEGER DEFAULT 0,
            false_positives INTEGER DEFAULT 0,

            -- Timing stats
            avg_days_to_publish REAL,
            median_days_to_publish REAL,
            fastest_publish_days REAL,
            slowest_publish_days REAL,

            -- Learning
            last_updated TEXT,
            last_recalculated TEXT
        )
    """)

    # Table 4: cna_registry
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cna_registry (
            cna_name TEXT PRIMARY KEY,

            -- Identity
            official_name TEXT,
            cna_type TEXT,

            -- Performance metrics
            avg_publication_lag_days REAL,
            median_publication_lag_days REAL,
            reliability_score REAL DEFAULT 0.80,

            -- ID allocation patterns
            id_ranges TEXT,

            -- Stats
            total_cves_tracked INTEGER DEFAULT 0,
            total_ghosts INTEGER DEFAULT 0,
            ghost_rate REAL,

            last_updated TEXT
        )
    """)

    # Table 5: resolution_history (learning data)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS resolution_history (
            id INTEGER PRIMARY KEY,
            cve_id TEXT NOT NULL,

            -- Timeline
            first_discovered TEXT NOT NULL,
            resolved_date TEXT NOT NULL,
            resolution_time_days REAL NOT NULL,

            -- Context
            cna_name TEXT,
            first_source_name TEXT,
            first_source_type TEXT,
            root_cause TEXT,

            -- Classification
            was_true_ghost BOOLEAN,
            ghost_confidence_at_peak REAL,

            -- Learning data
            contributed_to_learning BOOLEAN DEFAULT TRUE,

            created_at TEXT NOT NULL,

            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        )
    """)

    # Indexes for resolution_history
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_resolution_cna ON resolution_history(cna_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_resolution_time ON resolution_history(resolution_time_days)")

    # Table 6: validation_cache
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS validation_cache (
            cve_id TEXT PRIMARY KEY,
            cve_status TEXT NOT NULL,
            validation_source TEXT NOT NULL,
            cached_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            raw_data TEXT
        )
    """)

    conn.commit()


def init_source_reliability_defaults(conn: sqlite3.Connection) -> None:
    """
    Initialize source reliability with expert defaults.

    Args:
        conn: SQLite connection
    """
    cursor = conn.cursor()

    defaults = [
        # High reliability (0.90-0.98)
        ("ZDI Advisories", "vulnerability_broker", 0.95),
        ("ZDI Upcoming", "vulnerability_broker", 0.95),
        ("Microsoft MSRC", "vendor_advisory", 0.95),
        ("Cisco PSIRT", "vendor_advisory", 0.94),
        ("Red Hat Security Advisories", "vendor_advisory", 0.93),
        ("Red Hat Security Data", "vendor_advisory", 0.93),
        ("Apple Security", "vendor_advisory", 0.93),
        ("GitHub Security Advisories", "api", 0.90),
        ("CVE.org Recent Changes", "registry", 1.0),
        ("ExploitDB", "exploit_database", 0.92),
        ("CISA Known Exploited Vulnerabilities", "government_advisory", 0.98),

        # Medium-high reliability (0.80-0.89)
        ("Debian Security Tracker", "distro_advisory", 0.88),
        ("Debian Security Announce", "distro_advisory", 0.88),
        ("Ubuntu Security Notices", "distro_advisory", 0.87),
        ("Adobe Security", "vendor_advisory", 0.85),
        ("Oracle Security", "vendor_advisory", 0.84),
        ("Google Security", "vendor_advisory", 0.88),

        # Medium reliability (0.70-0.79)
        ("OSS Security", "mailing_list", 0.75),
        ("Packet Storm", "mailing_list", 0.73),
        ("Chrome Releases", "vendor_advisory", 0.90),

        # Lower reliability (0.60-0.69)
        ("Full Disclosure", "mailing_list", 0.65),
    ]

    for source_name, source_type, score in defaults:
        cursor.execute("""
            INSERT OR IGNORE INTO source_reliability
            (source_name, source_type, reliability_score, total_discoveries, true_positives, false_positives)
            VALUES (?, ?, ?, 0, 0, 0)
        """, (source_name, source_type, score))

    conn.commit()


def init_cna_registry_defaults(conn: sqlite3.Connection) -> None:
    """
    Initialize CNA registry with known CNAs.

    Args:
        conn: SQLite connection
    """
    cursor = conn.cursor()

    known_cnas = [
        ("mitre", "MITRE Corporation", "coordinator", 3.0, 0.95),
        ("microsoft", "Microsoft Corporation", "vendor", 7.0, 0.90),
        ("redhat", "Red Hat, Inc.", "vendor", 5.0, 0.92),
        ("google", "Google LLC", "vendor", 6.0, 0.91),
        ("apple", "Apple Inc.", "vendor", 8.0, 0.89),
        ("cisco", "Cisco Systems, Inc.", "vendor", 7.5, 0.90),
    ]

    for cna_name, official_name, cna_type, avg_lag, reliability in known_cnas:
        cursor.execute("""
            INSERT OR IGNORE INTO cna_registry
            (cna_name, official_name, cna_type, avg_publication_lag_days, reliability_score,
             total_cves_tracked, total_ghosts, ghost_rate)
            VALUES (?, ?, ?, ?, ?, 0, 0, 0.0)
        """, (cna_name, official_name, cna_type, avg_lag, reliability))

    conn.commit()
