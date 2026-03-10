#!/usr/bin/env python3
"""
Generate dashboard data files for GitHub Pages.

Creates JSON data files used by the static dashboard.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from src.storage import DatabaseManager


def generate_latest_data(db: DatabaseManager, output_dir: Path) -> None:
    """Generate latest ghosts data file."""
    ghosts = db.get_ghost_cves(only_ghosts=True, limit=200)

    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": db.get_statistics(),
        "ghosts": []
    }

    for ghost in ghosts:
        sources = db.get_sources_for_cve(ghost.cve_id)

        ghost_data = {
            "cve_id": ghost.cve_id,
            "first_seen": ghost.first_seen.isoformat() + "Z" if ghost.first_seen else None,
            "last_checked": ghost.last_checked.isoformat() + "Z" if ghost.last_checked else None,
            "registry_status": ghost.registry_status,
            "days_in_limbo": ghost.days_in_limbo,
            "confidence_score": round(ghost.confidence_score, 2) if ghost.confidence_score else 0,
            "sources": [
                {
                    "name": s.source_name,
                    "type": s.source_type,
                    "url": s.evidence_url,
                    "discovered_at": s.discovered_at.isoformat() + "Z" if s.discovered_at else None
                }
                for s in sources[:5]  # Limit to first 5 sources
            ]
        }

        data["ghosts"].append(ghost_data)

    # Write to file
    with open(output_dir / "latest.json", "w") as f:
        json.dump(data, f, indent=2)

    print(f"✓ Generated latest.json with {len(data['ghosts'])} ghosts")


def generate_trends_data(db: DatabaseManager, output_dir: Path, days: int = 30) -> None:
    """Generate historical trend data."""
    ghosts = db.get_ghost_cves(only_ghosts=True)

    trends = []
    for i in range(days):
        date = datetime.utcnow() - timedelta(days=days - 1 - i)
        date_str = date.strftime("%Y-%m-%d")

        # Count ghosts that existed on this date
        count = len([
            g for g in ghosts
            if g.first_seen and g.first_seen.date() <= date.date()
        ])

        trends.append({
            "date": date_str,
            "count": count
        })

    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "timeline": trends
    }

    with open(output_dir / "trends.json", "w") as f:
        json.dump(data, f, indent=2)

    print(f"✓ Generated trends.json with {len(trends)} data points")


def generate_stats_data(db: DatabaseManager, output_dir: Path) -> None:
    """Generate detailed statistics."""
    stats = db.get_statistics()

    # Get additional stats
    ghosts = db.get_ghost_cves(only_ghosts=True)

    # Group by status
    status_breakdown = {}
    for ghost in ghosts:
        status = ghost.registry_status
        status_breakdown[status] = status_breakdown.get(status, 0) + 1

    # Group by source type
    source_breakdown = {}
    for ghost in ghosts[:100]:  # Sample first 100
        sources = db.get_sources_for_cve(ghost.cve_id)
        for source in sources:
            stype = source.source_type
            source_breakdown[stype] = source_breakdown.get(stype, 0) + 1

    # Age distribution
    age_distribution = {
        "0-7": 0,
        "8-30": 0,
        "31-90": 0,
        "90+": 0
    }

    for ghost in ghosts:
        days = ghost.days_in_limbo
        if days <= 7:
            age_distribution["0-7"] += 1
        elif days <= 30:
            age_distribution["8-30"] += 1
        elif days <= 90:
            age_distribution["31-90"] += 1
        else:
            age_distribution["90+"] += 1

    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": stats,
        "status_breakdown": status_breakdown,
        "source_breakdown": source_breakdown,
        "age_distribution": age_distribution
    }

    with open(output_dir / "stats.json", "w") as f:
        json.dump(data, f, indent=2)

    print(f"✓ Generated stats.json")


def main():
    """Main entry point."""
    # Setup paths
    output_dir = Path("docs/_data")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize database
    db = DatabaseManager()

    print("Generating dashboard data...")

    # Generate all data files
    generate_latest_data(db, output_dir)
    generate_trends_data(db, output_dir)
    generate_stats_data(db, output_dir)

    print("\n✓ All dashboard data generated successfully")


if __name__ == "__main__":
    main()
