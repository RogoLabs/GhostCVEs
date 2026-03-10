#!/usr/bin/env python3
"""
Audit CVE data accuracy.

Checks for potentially fake or suspicious CVE IDs in the database.
"""

import sys
from datetime import datetime
from src.storage import DatabaseManager
from src.config import validate_cve_id, CVEValidationConfig


def check_suspicious_patterns(db: DatabaseManager):
    """Check for suspicious CVE ID patterns."""
    print("🔍 Checking for Suspicious CVE Patterns\n")
    print("=" * 80)

    ghosts = db.get_ghost_cves(only_ghosts=True)

    issues = []

    for ghost in ghosts:
        cve_id = ghost.cve_id

        # Parse CVE
        try:
            parts = cve_id.split("-")
            year = int(parts[1])
            id_num = int(parts[2])

            # Check for suspiciously high IDs
            if year == 2025 and id_num > 50000:
                issues.append({
                    "cve_id": cve_id,
                    "issue": f"Very high ID for 2025: {id_num}",
                    "severity": "medium",
                    "first_seen": ghost.first_seen
                })

            elif year == 2026:
                # We're in March 2026, expect ~18k max
                current_month = datetime.utcnow().month
                max_expected = current_month * 6000
                if id_num > max_expected:
                    issues.append({
                        "cve_id": cve_id,
                        "issue": f"ID {id_num} exceeds expected max {max_expected} for March 2026",
                        "severity": "high",
                        "first_seen": ghost.first_seen
                    })

            # Check for sequential patterns (might indicate fake data)
            id_str = str(id_num)
            if len(set(id_str)) == 1 and len(id_str) >= 4:
                issues.append({
                    "cve_id": cve_id,
                    "issue": f"All same digit: {id_str}",
                    "severity": "high",
                    "first_seen": ghost.first_seen
                })

        except Exception as e:
            print(f"Error parsing {cve_id}: {e}")

    # Report issues
    if issues:
        print(f"\n⚠️  Found {len(issues)} suspicious CVEs:\n")

        for issue in sorted(issues, key=lambda x: x["severity"], reverse=True):
            severity_icon = "🔴" if issue["severity"] == "high" else "🟡"
            print(f"{severity_icon} {issue['cve_id']}")
            print(f"   Issue: {issue['issue']}")
            print(f"   First seen: {issue['first_seen'].strftime('%Y-%m-%d')}")

            # Get sources
            sources = db.get_sources_for_cve(issue['cve_id'])
            if sources:
                print(f"   Sources:")
                for source in sources[:3]:
                    print(f"     - {source.source_name}: {source.evidence_url}")
            print()
    else:
        print("\n✅ No suspicious patterns detected")

    return issues


def check_source_reliability(db: DatabaseManager):
    """Check which sources are producing the most unverifiable CVEs."""
    print("\n" + "=" * 80)
    print("📊 Source Reliability Analysis\n")

    ghosts = db.get_ghost_cves(only_ghosts=True)

    source_stats = {}

    for ghost in ghosts:
        sources = db.get_sources_for_cve(ghost.cve_id)
        for source in sources:
            source_name = source.source_name
            if source_name not in source_stats:
                source_stats[source_name] = {
                    "ghost_count": 0,
                    "examples": []
                }

            source_stats[source_name]["ghost_count"] += 1
            if len(source_stats[source_name]["examples"]) < 5:
                source_stats[source_name]["examples"].append(ghost.cve_id)

    # Sort by count
    sorted_sources = sorted(source_stats.items(), key=lambda x: x[1]["ghost_count"], reverse=True)

    print(f"{'Source':<40} {'Ghost CVEs':<12} {'Examples'}")
    print("-" * 80)

    for source_name, stats in sorted_sources:
        examples = ", ".join(stats["examples"][:3])
        print(f"{source_name:<40} {stats['ghost_count']:<12} {examples}")


def check_high_id_cves(db: DatabaseManager):
    """Check CVEs with unusually high IDs."""
    print("\n" + "=" * 80)
    print("🔢 High CVE ID Analysis\n")

    ghosts = db.get_ghost_cves(only_ghosts=True)

    high_id_cves = []

    for ghost in ghosts:
        try:
            parts = ghost.cve_id.split("-")
            year = int(parts[1])
            id_num = int(parts[2])

            # Flag if > 50k for any year
            if id_num > 50000:
                high_id_cves.append({
                    "cve_id": ghost.cve_id,
                    "year": year,
                    "id_num": id_num,
                    "first_seen": ghost.first_seen
                })
        except:
            pass

    if high_id_cves:
        print(f"Found {len(high_id_cves)} CVEs with IDs > 50,000:\n")

        for cve in sorted(high_id_cves, key=lambda x: x["id_num"], reverse=True):
            print(f"  {cve['cve_id']:<20} (ID: {cve['id_num']:>6}) - First seen: {cve['first_seen'].strftime('%Y-%m-%d')}")

            # Get sources
            sources = db.get_sources_for_cve(cve['cve_id'])
            if sources:
                for source in sources[:2]:
                    print(f"    Source: {source.source_name}")
                    print(f"    URL: {source.evidence_url}")
            print()
    else:
        print("✅ No CVEs with IDs > 50,000")


def suggest_validation_improvements():
    """Suggest improvements to validation config."""
    print("\n" + "=" * 80)
    print("💡 Suggested Validation Improvements\n")

    current_year = datetime.utcnow().year
    current_month = datetime.utcnow().month

    suggestions = [
        "1. Lower 2025 max_id_by_year from 70,000 to 60,000",
        f"2. For {current_year}, max should be {current_month * 5000} (month * 5000) not {current_month * 6000}",
        "3. Add stricter validation for CVE IDs > 50,000",
        "4. Flag CVEs for manual review if they:",
        "   - Have IDs in top 10% of year's range",
        "   - Come from sources with high ghost rate",
        "   - Haven't been verified within 60 days",
        "5. Consider requiring multiple independent sources for high-ID CVEs",
    ]

    for suggestion in suggestions:
        print(f"  {suggestion}")


def main():
    """Main entry point."""
    print("🔍 Ghost CVE Data Accuracy Audit")
    print("=" * 80)
    print()

    db = DatabaseManager()

    # Run checks
    issues = check_suspicious_patterns(db)
    check_source_reliability(db)
    check_high_id_cves(db)
    suggest_validation_improvements()

    print("\n" + "=" * 80)
    print("📋 Summary")
    print("=" * 80)

    stats = db.get_statistics()
    print(f"\nTotal Ghost CVEs: {stats.get('total_ghosts', 0)}")
    print(f"Suspicious patterns found: {len(issues)}")

    if issues:
        print("\n⚠️  ACTION REQUIRED:")
        print("   1. Review the suspicious CVEs listed above")
        print("   2. Verify sources manually")
        print("   3. Add to blacklist if confirmed fake (src/config.py)")
        print("   4. Adjust validation thresholds if needed")
    else:
        print("\n✅ No immediate action required")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    sys.exit(main() or 0)
