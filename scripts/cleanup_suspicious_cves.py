#!/usr/bin/env python3
"""
Clean up suspicious CVEs from the database.

This script helps remove CVEs that are likely false positives.
"""

import sys
import sqlite3
from datetime import datetime, timedelta


def cleanup_high_id_cves(db_path: str = "ghost_log.db", dry_run: bool = True):
    """
    Remove CVEs with suspiciously high IDs.

    Args:
        db_path: Path to database
        dry_run: If True, only report what would be removed
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("🔍 Finding CVEs with suspiciously high IDs...")
    print()

    # Find CVEs with IDs > 50000
    cursor.execute("""
        SELECT cve_id, registry_status, first_seen
        FROM ghost_cves
        WHERE CAST(SUBSTR(cve_id, 10) AS INTEGER) > 50000
        AND is_ghost = 1
        ORDER BY cve_id
    """)

    suspicious = cursor.fetchall()

    if not suspicious:
        print("✅ No suspicious high-ID CVEs found")
        conn.close()
        return 0

    print(f"Found {len(suspicious)} CVEs with IDs > 50,000:\n")

    for cve_id, status, first_seen in suspicious:
        id_num = int(cve_id.split("-")[2])
        print(f"  {cve_id:<20} (ID: {id_num:>6}) - Status: {status}")

        # Get sources
        cursor.execute("""
            SELECT source_name, evidence_url
            FROM discovery_sources ds
            JOIN ghost_cves gc ON ds.ghost_cve_id = gc.id
            WHERE gc.cve_id = ?
            LIMIT 2
        """, (cve_id,))

        sources = cursor.fetchall()
        for source_name, url in sources:
            print(f"    Source: {source_name}")
            print(f"    URL: {url}")

    print()

    if dry_run:
        print("🔸 DRY RUN - No changes made")
        print()
        print("To actually remove these CVEs, run:")
        print("  python scripts/cleanup_suspicious_cves.py --remove")
    else:
        print("⚠️  REMOVING suspicious CVEs...")

        # Remove them
        cursor.execute("""
            DELETE FROM ghost_cves
            WHERE CAST(SUBSTR(cve_id, 10) AS INTEGER) > 50000
            AND is_ghost = 1
        """)

        removed = cursor.rowcount
        conn.commit()

        print(f"✅ Removed {removed} suspicious CVEs")

    conn.close()
    return len(suspicious)


def cleanup_resolved_cves(db_path: str = "ghost_log.db", days: int = 30, dry_run: bool = True):
    """
    Remove CVEs that have been resolved (published) for a while.

    Args:
        db_path: Path to database
        days: Days after resolution to keep
        dry_run: If True, only report what would be removed
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cutoff = datetime.utcnow() - timedelta(days=days)

    print(f"\n🔍 Finding CVEs resolved more than {days} days ago...")
    print()

    cursor.execute("""
        SELECT cve_id, registry_status, last_checked
        FROM ghost_cves
        WHERE is_ghost = 0
        AND last_checked < ?
        ORDER BY last_checked
        LIMIT 20
    """, (cutoff,))

    resolved = cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*)
        FROM ghost_cves
        WHERE is_ghost = 0
        AND last_checked < ?
    """, (cutoff,))

    total_count = cursor.fetchone()[0]

    if total_count == 0:
        print(f"✅ No resolved CVEs older than {days} days")
        conn.close()
        return 0

    print(f"Found {total_count} resolved CVEs older than {days} days")
    print(f"Showing first 20:\n")

    for cve_id, status, last_checked in resolved:
        print(f"  {cve_id:<20} - Status: {status} - Last checked: {last_checked}")

    print()

    if dry_run:
        print("🔸 DRY RUN - No changes made")
        print()
        print("To actually remove these CVEs, run:")
        print("  python scripts/cleanup_suspicious_cves.py --remove --cleanup-resolved")
    else:
        print("⚠️  REMOVING resolved CVEs...")

        cursor.execute("""
            DELETE FROM ghost_cves
            WHERE is_ghost = 0
            AND last_checked < ?
        """, (cutoff,))

        removed = cursor.rowcount
        conn.commit()

        print(f"✅ Removed {removed} resolved CVEs")

    conn.close()
    return total_count


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Clean up suspicious CVEs")
    parser.add_argument("--remove", action="store_true", help="Actually remove CVEs (default is dry run)")
    parser.add_argument("--cleanup-resolved", action="store_true", help="Also cleanup resolved CVEs")
    parser.add_argument("--days", type=int, default=30, help="Days to keep resolved CVEs (default: 30)")

    args = parser.parse_args()

    print("🧹 Ghost CVE Cleanup Tool")
    print("=" * 80)

    if not args.remove:
        print("⚠️  DRY RUN MODE - No changes will be made")
        print("=" * 80)

    # Cleanup suspicious CVEs
    high_id_count = cleanup_high_id_cves(dry_run=not args.remove)

    # Cleanup resolved CVEs if requested
    if args.cleanup_resolved:
        resolved_count = cleanup_resolved_cves(days=args.days, dry_run=not args.remove)
    else:
        resolved_count = 0

    print()
    print("=" * 80)
    print("📋 Summary")
    print("=" * 80)
    print(f"  Suspicious CVEs (high IDs): {high_id_count}")

    if args.cleanup_resolved:
        print(f"  Resolved CVEs (old): {resolved_count}")

    if not args.remove:
        print()
        print("  To apply these changes, run with --remove flag")

    return 0


if __name__ == "__main__":
    sys.exit(main())
