#!/usr/bin/env python3
"""
Fix timezone usage in test files.

Replaces deprecated datetime.utcnow() with datetime.now(timezone.utc).
Ensures timezone is imported from datetime module.
"""

import os
import re
from pathlib import Path

# Test files that need fixing
test_files = [
    "tests/pipeline/test_ghost_analyzer.py",
    "tests/pipeline/test_root_cause_detector.py",
    "tests/pipeline/test_learning_system.py",
    "tests/integration/test_pipeline_e2e.py",
    "tests/discovery/test_github_advisory_discovery.py",
    "tests/discovery/test_cve_org_monitor.py",
    "tests/test_storage.py",
    "tests/test_datetime_timezone_fix.py",
    "tests/registry/test_multi_source_validator.py",
    "tests/api/test_cve_org_client.py",
]


def fix_file(filepath: str) -> tuple[int, bool]:
    """
    Fix timezone usage in a test file.

    Returns:
        (replacements_made, import_added)
    """
    with open(filepath, 'r') as f:
        content = f.read()

    original_content = content
    replacements = 0
    import_added = False

    # Replace datetime.utcnow() with datetime.now(timezone.utc)
    content, count = re.subn(
        r'datetime\.utcnow\(\)',
        'datetime.now(timezone.utc)',
        content
    )
    replacements += count

    # Check if timezone is imported
    has_timezone_import = bool(re.search(r'from datetime import.*timezone', content))

    if replacements > 0 and not has_timezone_import:
        # Need to add timezone to imports
        # Look for datetime import line
        datetime_import_match = re.search(r'^from datetime import ([^\n]+)', content, re.MULTILINE)

        if datetime_import_match:
            # Add timezone to existing import
            existing_imports = datetime_import_match.group(1).strip()

            # Check if timezone already there (just not caught by simpler regex)
            if 'timezone' not in existing_imports:
                new_imports = existing_imports + ', timezone'
                content = content.replace(
                    f"from datetime import {existing_imports}",
                    f"from datetime import {new_imports}",
                    1  # Only first occurrence
                )
                import_added = True
        else:
            # No datetime import found - add one at the top after other imports
            # Find the last import line
            import_lines = list(re.finditer(r'^(?:from|import) .*$', content, re.MULTILINE))
            if import_lines:
                last_import = import_lines[-1]
                insert_pos = last_import.end()
                content = (
                    content[:insert_pos] +
                    '\nfrom datetime import timezone' +
                    content[insert_pos:]
                )
                import_added = True

    # Only write if changed
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)

    return replacements, import_added


def main():
    """Fix all test files."""
    print("Fixing timezone usage in test files...\n")

    total_replacements = 0
    total_imports = 0

    for filepath in test_files:
        if not Path(filepath).exists():
            print(f"⚠️  {filepath} not found, skipping")
            continue

        replacements, import_added = fix_file(filepath)
        total_replacements += replacements
        total_imports += import_added

        if replacements > 0:
            status = "✓" if replacements > 0 else "○"
            import_status = " (+import)" if import_added else ""
            print(f"{status} {filepath}: {replacements} replacements{import_status}")

    print(f"\n✓ Fixed {total_replacements} instances across {len(test_files)} files")
    print(f"✓ Added timezone imports to {total_imports} files")


if __name__ == "__main__":
    main()
