"""
Migration script for GhostCVEs V1 → V2.

Fresh start approach:
- Backup existing database
- Create new database with V2 schema
- Initialize defaults
- No data import (clean baseline)
"""

import shutil
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.schema_v2 import (
    create_schema_v2,
    init_source_reliability_defaults,
    init_cna_registry_defaults,
)
import sqlite3


def migrate():
    """Perform migration from V1 to V2."""

    print("=" * 80)
    print("🔄 GhostCVEs V1 → V2 Migration")
    print("=" * 80)
    print()

    db_path = Path("ghost_log.db")

    # Step 1: Backup existing database
    print("Step 1: Backing up existing database...")
    if db_path.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = Path(f"ghost_log.backup.{timestamp}.db")
        shutil.copy(db_path, backup_path)
        print(f"   ✓ Backed up to {backup_path}")
        print(f"   Size: {backup_path.stat().st_size / 1024 / 1024:.2f} MB")
    else:
        print("   ℹ No existing database found (fresh installation)")
        backup_path = None
    print()

    # Step 2: Remove old database
    print("Step 2: Removing old database...")
    if db_path.exists():
        db_path.unlink()
        print("   ✓ Removed old database")
    else:
        print("   ℹ No database to remove")
    print()

    # Step 3: Create fresh database with V2 schema
    print("Step 3: Creating fresh database with V2 schema...")
    conn = sqlite3.connect(str(db_path))
    create_schema_v2(conn)
    print("   ✓ Created new schema")
    print("   Tables: cves, discovery_sources, source_reliability,")
    print("           cna_registry, resolution_history, validation_cache")
    print()

    # Step 4: Initialize defaults
    print("Step 4: Initializing source reliability defaults...")
    init_source_reliability_defaults(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM source_reliability")
    source_count = cursor.fetchone()[0]
    print(f"   ✓ Initialized {source_count} sources")
    print()

    print("Step 5: Initializing CNA registry defaults...")
    init_cna_registry_defaults(conn)

    cursor.execute("SELECT COUNT(*) FROM cna_registry")
    cna_count = cursor.fetchone()[0]
    print(f"   ✓ Initialized {cna_count} CNAs")
    print()

    conn.close()

    # Summary
    print("=" * 80)
    print("✅ Migration Complete!")
    print("=" * 80)
    print()
    print("Summary:")
    print(f"  • Old database: {'backed up' if backup_path else 'none'}")
    if backup_path:
        print(f"  • Backup location: {backup_path}")
    print(f"  • New database: {db_path}")
    print(f"  • Schema version: V2")
    print(f"  • Sources initialized: {source_count}")
    print(f"  • CNAs initialized: {cna_count}")
    print()
    print("Next steps:")
    print("  1. Run first hunt: python main.py --hunt")
    print("  2. Monitor results: python main.py --dashboard")
    print("  3. Check for improvements in ghost detection accuracy")
    print()
    print("Why fresh start?")
    print("  • Old data had 40-60% false positive rate")
    print("  • Would contaminate learning system")
    print("  • Clean baseline for measuring improvements")
    if backup_path:
        print(f"  • Historical data preserved in: {backup_path}")
    print()


if __name__ == "__main__":
    try:
        migrate()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Migration failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
