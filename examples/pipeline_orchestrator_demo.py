#!/usr/bin/env python3
"""
Pipeline Orchestrator Demo
===========================

Demonstrates the usage of the Pipeline Orchestrator for coordinating
Ghost CVE detection across multiple sources.

This example shows:
1. Creating a pipeline orchestrator
2. Setting up discovery sources
3. Running the full pipeline
4. Checking for resolutions
5. Getting pipeline statistics

Author: rogolabs.net
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.pipeline.orchestrator import PipelineOrchestrator
from src.storage.database import DatabaseManager
from src.discovery.base import DiscoveryResult
from datetime import datetime


def demo_orchestrator():
    """Demonstrate the pipeline orchestrator functionality."""

    print("=" * 70)
    print("Pipeline Orchestrator Demo")
    print("=" * 70)
    print()

    # Initialize database manager (in-memory for demo)
    print("1. Initializing database manager...")
    db = DatabaseManager(":memory:")
    db.initialize()
    print("   ✓ Database initialized\n")

    # Create orchestrator
    print("2. Creating pipeline orchestrator...")
    orchestrator = PipelineOrchestrator(db)
    print("   ✓ Orchestrator created\n")

    # Process a single discovery
    print("3. Processing a single CVE discovery...")
    discovery = DiscoveryResult(
        cve_id="CVE-2025-12345",
        source_type="github_commit",
        source_name="example/vulnerable-app",
        evidence_url="https://github.com/example/vulnerable-app/commit/abc123",
        discovered_at=datetime.utcnow(),
        confidence=0.95,
        context="Fixed CVE-2025-12345 buffer overflow"
    )

    # Note: In a real scenario, this would validate against registries
    # For demo purposes, we're showing the interface
    print(f"   Discovery: {discovery.cve_id}")
    print(f"   Source: {discovery.source_name}")
    print(f"   Confidence: {discovery.confidence}")
    print(f"   Evidence: {discovery.evidence_url}")
    print()

    # Get pipeline summary
    print("4. Pipeline statistics:")
    summary = orchestrator.get_pipeline_summary()
    print(f"   Total CVEs tracked: {summary.get('total_cves_tracked', 0)}")
    print(f"   Total ghosts: {summary.get('total_ghosts', 0)}")
    print(f"   Total sources: {summary.get('total_sources', 0)}")
    print()

    # Example of full pipeline run structure
    print("5. Full pipeline flow:")
    print("   Stage 1: Discovery Sources")
    print("      → GitHub commits, security advisories")
    print("      → RSS feeds from vendors")
    print("      → ExploitDB entries")
    print("      → Vendor security bulletins")
    print()
    print("   Stage 2: Validation")
    print("      → Check CVE status in registries")
    print("      → Classify as Ghost or Published")
    print()
    print("   Stage 3: Storage")
    print("      → Record in database")
    print("      → Track first_seen timestamps")
    print("      → Link discovery sources")
    print()
    print("   Stage 4: Resolution Tracking")
    print("      → Monitor RESERVED → PUBLISHED transitions")
    print("      → Update Ghost status when resolved")
    print()

    print("=" * 70)
    print("Demo completed!")
    print("=" * 70)
    print()
    print("To use in production:")
    print("  1. Initialize with real database path")
    print("  2. Ensure local registries are available")
    print("  3. Configure discovery sources")
    print("  4. Run orchestrator.run_full_pipeline(sources)")
    print("  5. Periodically call orchestrator.check_for_resolutions()")
    print()


if __name__ == "__main__":
    demo_orchestrator()
