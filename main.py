#!/usr/bin/env python3
"""
Ghost Hunter - CVE Intelligence Platform
=========================================

Main entry point for the Ghost Hunter application.
Identifies Ghost CVEs - vulnerability IDs mentioned in public sources
but still marked as RESERVED or missing in official registries.

Uses a 6-stage detection pipeline:
1. Discovery - Find CVE mentions across 23+ sources
2. Disclosure - Classify disclosure method
3. Validation - Multi-source registry validation
4. Ghost Analysis - Confidence scoring and classification
5. Root Cause - Detect why CVE is reserved
6. Learning - Track patterns and improve detection

Author: rogolabs.net
License: MIT

Usage:
    python main.py --hunt                  # Run 6-stage detection pipeline
    python main.py --check-resolutions     # Check for Ghost resolutions
    python main.py --report                # Generate reports from database
    python main.py --hunt --report         # Hunt then generate reports
    python main.py --dashboard             # Show Ghost CVE dashboard
"""

import argparse
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from src import __version__
from src.config import APP_SETTINGS, DATABASE_CONFIG, GITHUB_QUALITY_CONFIG
from src.discovery import GitHubDiscovery, RSSDiscovery, VendorDiscovery, ExploitDBDiscovery
from src.discovery.base import BaseDiscovery, DiscoveryResult
from src.pipeline.orchestrator import PipelineOrchestrator
from src.registry import CVEValidator
from src.storage import DatabaseManager
from src.ui import Dashboard, ReportGenerator


def setup_logging(log_level: str = "INFO", log_file: str | None = None) -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional log file path
    """
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=APP_SETTINGS.log_format,
        handlers=handlers,
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def create_discovery_modules(
    github_token: str | None = None,
) -> list[BaseDiscovery]:
    """
    Create and configure all discovery modules.
    
    Args:
        github_token: GitHub API token
    
    Returns:
        List of configured discovery modules
    """
    modules: list[BaseDiscovery] = []
    
    # GitHub Discovery (disabled by default - too much noise from fake repos)
    if GITHUB_QUALITY_CONFIG.enabled:
        modules.append(GitHubDiscovery(token=github_token))
    
    # RSS Discovery
    modules.append(RSSDiscovery())
    
    # Vendor Discovery
    modules.append(VendorDiscovery(github_token=github_token))
    
    return modules


def run_hunt(
    db_manager: DatabaseManager,
    dashboard: Dashboard,
    github_token: str | None = None,
    nvd_api_key: str | None = None,
    max_workers: int | None = None,
) -> dict:
    """
    Execute the Ghost Hunt process using the Pipeline Orchestrator.

    Runs all discovery modules through the 6-stage pipeline:
    1. Discovery - Find CVE mentions in public sources
    2. Disclosure - Classify disclosure method
    3. Validation - Multi-source validation
    4. Ghost Analysis - Confidence scoring
    5. Root Cause - Detect why it's a ghost
    6. Learning - Track patterns and improve

    Args:
        db_manager: Database manager instance
        dashboard: Dashboard for progress display
        github_token: GitHub API token
        nvd_api_key: NVD API key for higher rate limits
        max_workers: Maximum concurrent workers (legacy param, now handled internally)

    Returns:
        Dictionary with hunt results
    """
    logger = logging.getLogger(__name__)
    started_at = datetime.utcnow()

    # Initialize the pipeline orchestrator
    orchestrator = PipelineOrchestrator(db_manager)

    dashboard.console.print()
    dashboard.console.print("[bold cyan]🔍 Starting Ghost Hunt Pipeline...[/bold cyan]")
    dashboard.console.print()

    # Purge any previously collected data from blacklisted sources
    if GITHUB_QUALITY_CONFIG.blacklisted_repos or GITHUB_QUALITY_CONFIG.blacklisted_users:
        purged = db_manager.purge_blacklisted_sources(
            GITHUB_QUALITY_CONFIG.blacklisted_repos,
            GITHUB_QUALITY_CONFIG.blacklisted_users,
        )
        if purged > 0:
            dashboard.console.print(
                f"[dim]🗑️  Purged {purged} entries from blacklisted sources[/dim]"
            )

    # Ensure pipeline resources are ready
    dashboard.console.print("[dim]📦 Preparing pipeline resources...[/dim]")
    if orchestrator.ensure_resources():
        # Get registry info from multi-source validator
        repo_info = orchestrator.multi_source_validator.local_registry.get_repo_info()
        dashboard.console.print(
            f"[green]✓ Local CVE registry ready[/green] "
            f"[dim](last updated: {repo_info.get('last_updated', 'unknown')})[/dim]"
        )
        if orchestrator.multi_source_validator.nvd_local.is_available():
            nvd_info = orchestrator.multi_source_validator.nvd_local.get_info()
            dashboard.console.print(
                f"[green]✓ Local NVD data ready[/green] "
                f"[dim]({nvd_info.get('cve_count', 'unknown'):,} CVEs indexed)[/dim]"
            )
        dashboard.console.print("[green]✓ Pipeline orchestrator ready[/green]")
    else:
        dashboard.console.print(
            "[red]✗ Pipeline resources unavailable - validation will be limited[/red]"
        )
    dashboard.console.print()

    # Create discovery modules
    modules = create_discovery_modules(github_token)

    # Run the full pipeline
    dashboard.console.print("[bold]🚀 Executing 6-Stage Detection Pipeline[/bold]")
    dashboard.console.print()

    with dashboard.display_hunt_progress() as progress:
        pipeline_task = progress.add_task(
            "[cyan]Processing discoveries through pipeline...",
            total=len(modules),
        )

        # Execute pipeline (orchestrator handles all stages internally)
        stats = orchestrator.run_full_pipeline(modules)

        # Update progress (pipeline completed)
        progress.update(pipeline_task, completed=len(modules))

    dashboard.console.print()
    dashboard.console.print(
        f"[bold]📋 Processed {stats.total_discoveries} discoveries ({stats.unique_cves} unique CVEs)[/bold]"
    )
    dashboard.console.print()

    # Get final statistics
    db_stats = db_manager.get_statistics()

    # Record hunt run
    db_manager.record_hunt_run(
        started_at=started_at,
        total_cves_found=stats.unique_cves,
        new_ghosts_found=stats.ghosts_found,
        modules_run=stats.sources_used,
        errors=None if stats.errors == 0 else [f"{stats.errors} processing errors"],
        success=stats.errors == 0,
    )

    # Display results per module
    dashboard.console.print("[bold]📊 Pipeline Results:[/bold]")
    dashboard.console.print(f"  [cyan]Sources Used:[/cyan] {', '.join(stats.sources_used)}")
    dashboard.console.print(f"  [cyan]Total Discoveries:[/cyan] {stats.total_discoveries}")
    dashboard.console.print(f"  [cyan]Unique CVEs:[/cyan] {stats.unique_cves}")
    dashboard.console.print(f"  [cyan]Ghosts Found:[/cyan] {stats.ghosts_found}")
    dashboard.console.print(f"  [cyan]Published CVEs:[/cyan] {stats.published_found}")
    if stats.errors > 0:
        dashboard.console.print(f"  [yellow]Errors:[/yellow] {stats.errors}")
    dashboard.console.print()

    # Display hunt summary
    dashboard.display_hunt_summary(
        total_cves=stats.unique_cves,
        new_ghosts=stats.ghosts_found,
        total_ghosts=db_stats["total_ghosts"],
        duration_seconds=stats.duration_seconds,
    )

    # Check for resolutions after hunt
    dashboard.console.print()
    dashboard.console.print("[dim]🔄 Checking for Ghost CVE resolutions...[/dim]")
    resolved = orchestrator.check_for_resolutions()
    if resolved > 0:
        dashboard.console.print(
            f"[green]✓ {resolved} Ghost CVE(s) resolved (RESERVED → PUBLISHED)[/green]"
        )
    else:
        dashboard.console.print("[dim]No resolutions found[/dim]")

    return {
        "total_cves": stats.unique_cves,
        "new_ghosts": stats.ghosts_found,
        "total_ghosts": db_stats["total_ghosts"],
        "duration_seconds": stats.duration_seconds,
        "errors": [] if stats.errors == 0 else [f"{stats.errors} processing errors"],
        "resolved": resolved,
    }


def run_report(
    db_manager: DatabaseManager,
    dashboard: Dashboard,
    output_dir: str | None = None,
    format: str = "all",
) -> None:
    """
    Generate and display reports.
    
    Args:
        db_manager: Database manager instance
        dashboard: Dashboard for display
        output_dir: Directory for output files
        format: Report format (console, json, csv, markdown, all)
    """
    reporter = ReportGenerator(db_manager)
    
    dashboard.console.print()
    dashboard.console.print("[bold cyan]📝 Generating Reports...[/bold cyan]")
    dashboard.console.print()
    
    # Always show console report
    reporter.generate_console_report()
    
    # Generate file reports if requested
    if format in ("all", "json", "csv", "markdown"):
        dashboard.console.print()
        
        if format == "all":
            outputs = reporter.generate_all_reports(output_dir)
            for fmt, path in outputs.items():
                dashboard.display_success(f"{fmt.upper()} report: {path}")
        else:
            out_path = Path(output_dir) if output_dir else Path(APP_SETTINGS.output_dir)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format == "json":
                path = out_path / f"ghost_report_{timestamp}.json"
                reporter.generate_json_report(path)
            elif format == "csv":
                path = out_path / f"ghost_report_{timestamp}.csv"
                reporter.generate_csv_report(path)
            elif format == "markdown":
                path = out_path / f"ghost_report_{timestamp}.md"
                reporter.generate_markdown_report(path)
            
            dashboard.display_success(f"Report written to: {path}")
    
    # Display statistics
    dashboard.console.print()
    stats = db_manager.get_statistics()
    dashboard.display_statistics(stats)


def check_resolutions(db_manager: DatabaseManager, dashboard: Dashboard) -> None:
    """
    Check all Ghost CVEs for resolutions (RESERVED -> PUBLISHED transitions).

    Args:
        db_manager: Database manager instance
        dashboard: Dashboard for progress display
    """
    logger = logging.getLogger(__name__)

    # Initialize the pipeline orchestrator
    orchestrator = PipelineOrchestrator(db_manager)

    dashboard.console.print()
    dashboard.console.print("[bold cyan]🔄 Checking Ghost CVE Resolutions...[/bold cyan]")
    dashboard.console.print()

    # Ensure resources
    dashboard.console.print("[dim]📦 Preparing resources...[/dim]")
    if not orchestrator.ensure_resources():
        dashboard.display_error("Failed to prepare resources")
        return
    dashboard.console.print("[green]✓ Resources ready[/green]")
    dashboard.console.print()

    # Get ghost count
    ghosts = db_manager.get_ghost_cves(only_ghosts=True)
    if not ghosts:
        dashboard.display_info("No Ghost CVEs to check")
        return

    dashboard.console.print(f"[dim]Checking {len(ghosts)} Ghost CVEs...[/dim]")
    dashboard.console.print()

    # Check for resolutions
    with dashboard.display_hunt_progress() as progress:
        check_task = progress.add_task(
            "[cyan]Checking resolutions...",
            total=len(ghosts),
        )

        resolved = orchestrator.check_for_resolutions()

        progress.update(check_task, completed=len(ghosts))

    dashboard.console.print()
    if resolved > 0:
        dashboard.console.print(
            f"[bold green]✓ {resolved} Ghost CVE(s) resolved (RESERVED → PUBLISHED)[/bold green]"
        )
    else:
        dashboard.console.print("[bold]No resolutions found - all Ghosts still haunting![/bold]")

    # Show updated statistics
    dashboard.console.print()
    stats = db_manager.get_statistics()
    dashboard.display_statistics(stats)


def show_dashboard(db_manager: DatabaseManager, dashboard: Dashboard) -> None:
    """
    Display the Ghost CVE dashboard.

    Args:
        db_manager: Database manager instance
        dashboard: Dashboard instance
    """
    ghosts = db_manager.get_ghost_cves(only_ghosts=True, limit=20)

    if not ghosts:
        dashboard.display_info("No Ghost CVEs in database. Run --hunt to discover some!")
        return

    # Build sources map
    sources_map = {}
    for ghost in ghosts:
        sources_map[ghost.cve_id] = db_manager.get_sources_for_cve(ghost.cve_id)

    dashboard.display_ghost_table(ghosts, sources_map)

    stats = db_manager.get_statistics()
    dashboard.display_statistics(stats)


def main() -> int:
    """
    Main entry point for Ghost Hunter.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        description="Ghost Hunter - CVE Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --hunt                  Run CVE discovery pipeline
  python main.py --report                Generate reports
  python main.py --hunt --report         Hunt then report
  python main.py --dashboard             Show Ghost CVE dashboard
  python main.py --check-resolutions     Check for Ghost resolutions
        """,
    )
    
    parser.add_argument(
        "--hunt",
        action="store_true",
        help="Run CVE discovery and validation",
    )
    
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate reports from database",
    )
    
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Display Ghost CVE dashboard",
    )

    parser.add_argument(
        "--check-resolutions",
        action="store_true",
        help="Check for Ghost CVE resolutions (RESERVED → PUBLISHED)",
    )

    parser.add_argument(
        "--format",
        choices=["console", "json", "csv", "markdown", "all"],
        default="all",
        help="Report output format (default: all)",
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for reports",
    )
    
    parser.add_argument(
        "--database",
        type=str,
        default=None,
        help="Path to SQLite database file",
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Log file path",
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Maximum concurrent workers",
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip welcome banner",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"Ghost Hunter v{__version__}",
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger(__name__)
    
    # Get API tokens from environment
    github_token = os.environ.get("GITHUB_TOKEN")
    nvd_api_key = os.environ.get("NVD_API_KEY")
    
    # Initialize components
    dashboard = Dashboard(show_welcome=not args.no_banner)
    db_manager = DatabaseManager(args.database)
    
    # Initialize database
    db_manager.initialize()
    
    # Show welcome banner
    if not args.no_banner:
        dashboard.display_welcome()
    
    # Check for missing tokens
    if not github_token and (args.hunt or args.dashboard):
        dashboard.display_warning(
            "GITHUB_TOKEN not set. GitHub discovery will be limited."
        )
    
    try:
        # Default to dashboard if no mode specified
        if not any([args.hunt, args.report, args.dashboard, args.check_resolutions]):
            args.dashboard = True

        # Run requested modes
        if args.hunt:
            run_hunt(
                db_manager=db_manager,
                dashboard=dashboard,
                github_token=github_token,
                nvd_api_key=nvd_api_key,
                max_workers=args.workers,
            )

        if args.check_resolutions:
            check_resolutions(
                db_manager=db_manager,
                dashboard=dashboard,
            )

        if args.report:
            run_report(
                db_manager=db_manager,
                dashboard=dashboard,
                output_dir=args.output_dir,
                format=args.format,
            )

        if args.dashboard and not args.hunt and not args.report and not args.check_resolutions:
            show_dashboard(db_manager, dashboard)

        return 0
        
    except KeyboardInterrupt:
        dashboard.console.print()
        dashboard.display_warning("Hunt interrupted by user")
        return 130
        
    except Exception as e:
        logger.exception("Fatal error")
        dashboard.display_error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
