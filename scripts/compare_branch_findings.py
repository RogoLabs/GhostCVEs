#!/usr/bin/env python3
"""
Compare Ghost CVE findings between two branches.

Usage:
    python scripts/compare_branch_findings.py <feature_db> <main_db>
"""

import sqlite3
import sys
from pathlib import Path
from typing import Dict, Set, List, Tuple


def get_ghost_cves(db_path: str) -> Set[str]:
    """Extract all ghost CVE IDs from database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT cve_id
        FROM ghost_cves
        WHERE is_ghost = 1
    """)

    cves = {row[0] for row in cursor.fetchall()}
    conn.close()

    return cves


def get_source_stats(db_path: str) -> Dict[str, Dict]:
    """Get discovery statistics by source."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            ds.source_name,
            COUNT(DISTINCT ds.ghost_cve_id) as total_discoveries,
            SUM(CASE WHEN gc.is_ghost = 1 THEN 1 ELSE 0 END) as ghost_count,
            COUNT(DISTINCT gc.cve_id) as unique_cves
        FROM discovery_sources ds
        JOIN ghost_cves gc ON ds.ghost_cve_id = gc.id
        GROUP BY ds.source_name
        ORDER BY ds.source_name
    """)

    stats = {}
    for row in cursor.fetchall():
        source_name, total, ghosts, unique = row
        stats[source_name] = {
            'total': total,
            'ghosts': ghosts,
            'unique': unique,
            'ghost_rate': ghosts / total if total > 0 else 0.0
        }

    conn.close()
    return stats


def get_all_sources(db_path: str) -> Set[str]:
    """Get all unique source names."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT source_name
        FROM discovery_sources
        ORDER BY source_name
    """)

    sources = {row[0] for row in cursor.fetchall()}
    conn.close()

    return sources


def compare_databases(feature_db: str, main_db: str) -> None:
    """Generate side-by-side comparison report."""
    print("# Branch Comparison Report\n")
    print(f"**Feature DB:** `{feature_db}`")
    print(f"**Main DB:** `{main_db}`\n")

    # Get ghost CVEs
    feature_ghosts = get_ghost_cves(feature_db)
    main_ghosts = get_ghost_cves(main_db)

    print("## Ghost CVE Summary\n")
    print(f"| Branch | Total Ghosts | New vs Other | Unique |")
    print(f"|--------|--------------|--------------|--------|")
    print(f"| Feature | {len(feature_ghosts)} | {len(feature_ghosts - main_ghosts)} | {len(feature_ghosts - main_ghosts)} |")
    print(f"| Main | {len(main_ghosts)} | {len(main_ghosts - feature_ghosts)} | {len(main_ghosts - feature_ghosts)} |")
    print()

    # Show unique ghosts in each branch
    if feature_ghosts - main_ghosts:
        print("### New Ghosts in Feature Branch\n")
        for cve in sorted(feature_ghosts - main_ghosts)[:20]:  # Show first 20
            print(f"- {cve}")
        if len(feature_ghosts - main_ghosts) > 20:
            print(f"- ... and {len(feature_ghosts - main_ghosts) - 20} more")
        print()

    if main_ghosts - feature_ghosts:
        print("### Ghosts Lost in Feature Branch\n")
        for cve in sorted(main_ghosts - feature_ghosts)[:20]:  # Show first 20
            print(f"- {cve}")
        if len(main_ghosts - feature_ghosts) > 20:
            print(f"- ... and {len(main_ghosts - feature_ghosts) - 20} more")
        print()

    # Get source stats
    feature_sources = get_all_sources(feature_db)
    main_sources = get_all_sources(main_db)

    print("## Source Changes\n")

    removed_sources = main_sources - feature_sources
    if removed_sources:
        print("### Removed Sources\n")
        for source in sorted(removed_sources):
            print(f"- {source}")
        print()

    added_sources = feature_sources - main_sources
    if added_sources:
        print("### Added Sources\n")
        for source in sorted(added_sources):
            print(f"- {source}")
        print()

    # Compare common sources
    common_sources = feature_sources & main_sources

    if common_sources:
        print("## Source Performance Comparison\n")

        feature_stats = get_source_stats(feature_db)
        main_stats = get_source_stats(main_db)

        print("| Source | Branch | Discoveries | Ghosts | Ghost Rate |")
        print("|--------|--------|-------------|--------|------------|")

        for source in sorted(common_sources):
            if source in feature_stats:
                fs = feature_stats[source]
                print(f"| {source} | Feature | {fs['total']} | {fs['ghosts']} | {fs['ghost_rate']:.1%} |")

            if source in main_stats:
                ms = main_stats[source]
                print(f"| {source} | Main | {ms['total']} | {ms['ghosts']} | {ms['ghost_rate']:.1%} |")

            print(f"| | **Δ** | {feature_stats[source]['total'] - main_stats[source]['total']:+d} | {feature_stats[source]['ghosts'] - main_stats[source]['ghosts']:+d} | {feature_stats[source]['ghost_rate'] - main_stats[source]['ghost_rate']:+.1%} |")


def main():
    if len(sys.argv) != 3:
        print("Usage: python scripts/compare_branch_findings.py <feature_db> <main_db>")
        sys.exit(1)

    feature_db = sys.argv[1]
    main_db = sys.argv[2]

    if not Path(feature_db).exists():
        print(f"Error: Feature database not found: {feature_db}")
        sys.exit(1)

    if not Path(main_db).exists():
        print(f"Error: Main database not found: {main_db}")
        sys.exit(1)

    compare_databases(feature_db, main_db)


if __name__ == "__main__":
    main()
