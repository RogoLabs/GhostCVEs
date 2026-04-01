"""
Database maintenance utilities for Ghost Hunter.

Handles database optimization, archiving, and cleanup operations.
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict


class DatabaseMaintenance:
    """Handles database optimization and archiving operations."""

    def __init__(self, db_path: str = "ghost_log.db"):
        """
        Initialize database maintenance.

        Args:
            db_path: Path to the SQLite database
        """
        self.db_path = db_path

    def vacuum(self) -> Dict[str, float]:
        """
        Optimize database with VACUUM and ANALYZE.

        This reclaims unused space, defragments the database,
        and updates statistics for the query optimizer.

        Returns:
            Dictionary with optimization statistics
        """
        if not Path(self.db_path).exists():
            return {
                "size_before": 0,
                "size_after": 0,
                "saved_bytes": 0,
                "saved_percent": 0,
            }

        # Get size before
        size_before = Path(self.db_path).stat().st_size

        # Run VACUUM and ANALYZE
        conn = sqlite3.connect(self.db_path)
        conn.execute("VACUUM")
        conn.execute("ANALYZE")
        conn.close()

        # Get size after
        size_after = Path(self.db_path).stat().st_size

        saved_bytes = size_before - size_after
        saved_percent = (saved_bytes / size_before * 100) if size_before > 0 else 0

        return {
            "size_before": size_before,
            "size_after": size_after,
            "saved_bytes": saved_bytes,
            "saved_percent": saved_percent,
        }

    def archive_old_sources(self, days: int = 90) -> int:
        """
        Archive discovery sources older than specified days.

        Moves old sources to an archive table and removes them
        from the main table to reduce database size.

        Args:
            days: Number of days to keep in main table

        Returns:
            Number of sources archived
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = datetime.utcnow() - timedelta(days=days)

        # Create archive table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovery_sources_archive (
                id INTEGER PRIMARY KEY,
                ghost_cve_id INTEGER,
                source_type VARCHAR(50),
                source_name VARCHAR(200),
                evidence_url TEXT,
                discovered_at DATETIME,
                context TEXT,
                confidence_score FLOAT,
                raw_data TEXT
            )
        """)

        # Copy old sources to archive (IGNORE duplicates from prior runs)
        cursor.execute(
            """
            INSERT OR IGNORE INTO discovery_sources_archive
            SELECT * FROM discovery_sources
            WHERE discovered_at < ?
        """,
            (cutoff,),
        )

        archived = cursor.rowcount

        # Delete old sources from main table
        cursor.execute(
            """
            DELETE FROM discovery_sources
            WHERE discovered_at < ?
        """,
            (cutoff,),
        )

        conn.commit()
        conn.close()

        return archived

    def cleanup_resolved_ghosts(self, days: int = 180) -> int:
        """
        Remove ghost CVEs that have been resolved (published) for a while.

        Args:
            days: Number of days after resolution to keep

        Returns:
            Number of CVEs cleaned up
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = datetime.utcnow() - timedelta(days=days)

        # Find resolved ghosts (no longer ghost status, old)
        cursor.execute(
            """
            DELETE FROM ghost_cves
            WHERE is_ghost = 0
            AND last_checked < ?
        """,
            (cutoff,),
        )

        cleaned = cursor.rowcount

        conn.commit()
        conn.close()

        return cleaned

    def get_statistics(self) -> Dict[str, any]:
        """
        Get comprehensive database statistics.

        Returns:
            Dictionary with various database metrics
        """
        if not Path(self.db_path).exists():
            return {
                "file_size_mb": 0,
                "total_cves": 0,
                "active_ghosts": 0,
                "total_sources": 0,
                "archived_sources": 0,
                "oldest_ghost_days": 0,
            }

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        # File size
        stats["file_size_mb"] = Path(self.db_path).stat().st_size / (1024 * 1024)

        # CVE counts
        cursor.execute("SELECT COUNT(*) FROM ghost_cves")
        stats["total_cves"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ghost_cves WHERE is_ghost = 1")
        stats["active_ghosts"] = cursor.fetchone()[0]

        # Source counts
        cursor.execute("SELECT COUNT(*) FROM discovery_sources")
        stats["total_sources"] = cursor.fetchone()[0]

        # Archived sources (if table exists)
        cursor.execute("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name='discovery_sources_archive'
        """)
        if cursor.fetchone()[0] > 0:
            cursor.execute("SELECT COUNT(*) FROM discovery_sources_archive")
            stats["archived_sources"] = cursor.fetchone()[0]
        else:
            stats["archived_sources"] = 0

        # Oldest ghost
        cursor.execute("""
            SELECT MIN(first_seen) FROM ghost_cves WHERE is_ghost = 1
        """)
        oldest = cursor.fetchone()[0]
        if oldest:
            oldest_date = datetime.fromisoformat(oldest.replace("Z", ""))
            stats["oldest_ghost_days"] = (datetime.utcnow() - oldest_date).days
        else:
            stats["oldest_ghost_days"] = 0

        conn.close()
        return stats

    def optimize_indexes(self) -> None:
        """Create or rebuild indexes for better query performance."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Index on CVE ID for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ghost_cves_cve_id
            ON ghost_cves(cve_id)
        """)

        # Index on ghost status for filtering
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ghost_cves_is_ghost
            ON ghost_cves(is_ghost)
        """)

        # Index on first_seen for sorting
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ghost_cves_first_seen
            ON ghost_cves(first_seen)
        """)

        # Index on source type for filtering
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_discovery_sources_type
            ON discovery_sources(source_type)
        """)

        # Index on discovered_at for archiving queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_discovery_sources_discovered_at
            ON discovery_sources(discovered_at)
        """)

        conn.commit()
        conn.close()

    def create_backup(self, backup_dir: str = "backups") -> Path:
        """
        Create a backup of the database.

        Args:
            backup_dir: Directory to store backups

        Returns:
            Path to the backup file
        """
        backup_path = Path(backup_dir)
        backup_path.mkdir(exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_path / f"ghost_log_{timestamp}.db"

        # Copy database
        import shutil

        shutil.copy2(self.db_path, backup_file)

        # Keep only last 5 backups
        backups = sorted(backup_path.glob("ghost_log_*.db"), reverse=True)
        for old_backup in backups[5:]:
            old_backup.unlink()

        return backup_file
