#!/usr/bin/env python3
"""
Ghost Hunter - CVE Intelligence Platform
=========================================

Main entry point for the Ghost Hunter application.
Identifies Ghost CVEs - vulnerability IDs mentioned in public sources
but still marked as RESERVED or missing in official registries.

Author: rogolabs.net
License: MIT

Usage:
    python main.py --hunt          # Run discovery and validation
    python main.py --report        # Generate reports from database
    python main.py --hunt --report # Run hunt then generate reports
"""

import argparse
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from src import __version__
from src.config import APP_SETTINGS, DATABASE_CONFIG
from src.discovery import GitHubDiscovery, RSSDiscovery, VendorDiscovery
from src.discovery.base import BaseDiscovery, DiscoveryResult
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
    
    # GitHub Discovery
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
    Execute the Ghost Hunt process.
    
    Runs all discovery modules in parallel, validates discovered CVEs
    against official registries, and stores results in the database.
    
    Args:
        db_manager: Database manager instance
        dashboard: Dashboard for progress display
        github_token: GitHub API token
        nvd_api_key: NVD API key for higher rate limits
        max_workers: Maximum concurrent workers
    
    Returns:
        Dictionary with hunt results
    """
    logger = logging.getLogger(__name__)
    started_at = datetime.utcnow()
    
    max_workers = max_workers or APP_SETTINGS.max_workers
    
    # Create discovery modules
    modules = create_discovery_modules(github_token)
    
    # Create validator with local registry
    validator = CVEValidator(nvd_api_key=nvd_api_key)
    
    dashboard.console.print()
    dashboard.console.print("[bold cyan]🔍 Starting Ghost Hunt...[/bold cyan]")
    dashboard.console.print()
    
    # Ensure local CVE registry is available (fast validation)
    dashboard.console.print("[dim]📦 Preparing local CVE registry...[/dim]")
    if validator.ensure_local_registry():
        repo_info = validator.local_registry.get_repo_info()
        dashboard.console.print(
            f"[green]✓ Local registry ready[/green] "
            f"[dim](last updated: {repo_info.get('last_updated', 'unknown')})[/dim]"
        )
    else:
        dashboard.console.print(
            "[yellow]⚠ Local registry unavailable, using API fallback (slower)[/yellow]"
        )
    dashboard.console.print()
    
    # Track results
    all_discoveries: list[DiscoveryResult] = []
    module_results: dict[str, tuple[int, int]] = {}  # module_name -> (cve_count, ghost_count)
    errors: list[str] = []
    
    # Run discovery modules in parallel
    with dashboard.display_hunt_progress() as progress:
        discovery_task = progress.add_task(
            "[cyan]Running discovery modules...",
            total=len(modules),
        )
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(module.run): module
                for module in modules
            }
            
            for future in as_completed(futures):
                module = futures[future]
                
                try:
                    results = future.result()
                    all_discoveries.extend(results)
                    module_results[module.name] = (len(results), 0)  # Ghost count updated later
                    
                except Exception as e:
                    error_msg = f"{module.name}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg, exc_info=True)
                    module_results[module.name] = (0, 0)
                
                progress.advance(discovery_task)
    
    # Deduplicate discoveries by CVE ID
    unique_cves: dict[str, DiscoveryResult] = {}
    for discovery in all_discoveries:
        if discovery.cve_id not in unique_cves:
            unique_cves[discovery.cve_id] = discovery
    
    dashboard.console.print()
    dashboard.console.print(
        f"[bold]📋 Found {len(unique_cves)} unique CVE mentions[/bold]"
    )
    dashboard.console.print()
    
    # Validate and store CVEs
    new_ghosts = 0
    validated_count = 0
    
    with dashboard.display_hunt_progress() as progress:
        validation_task = progress.add_task(
            "[cyan]Validating CVEs against registries...",
            total=len(unique_cves),
        )
        
        for cve_id, discovery in unique_cves.items():
            try:
                # Validate against registry
                validation = validator.validate(cve_id, found_in_wild=True)
                
                # Check if this is a new ghost
                existing = db_manager.get_ghost_by_id(cve_id)
                was_ghost = existing.is_ghost if existing else False
                
                # Record in database
                ghost_cve = db_manager.record_discovery(discovery, validation)
                
                if validation.is_ghost and not was_ghost:
                    new_ghosts += 1
                    logger.info(f"New Ghost CVE: {cve_id}")
                
                validated_count += 1
                
            except Exception as e:
                error_msg = f"Validation failed for {cve_id}: {str(e)}"
                errors.append(error_msg)
                logger.error(error_msg)
            
            progress.advance(validation_task)
    
    # Update module ghost counts
    for module_name in module_results:
        cve_count, _ = module_results[module_name]
        # This is approximate - actual ghost count per module would require more tracking
        module_results[module_name] = (cve_count, 0)
    
    # Get final statistics
    stats = db_manager.get_statistics()
    
    # Record hunt run
    modules_run = [m.name for m in modules]
    db_manager.record_hunt_run(
        started_at=started_at,
        total_cves_found=len(unique_cves),
        new_ghosts_found=new_ghosts,
        modules_run=modules_run,
        errors=errors if errors else None,
        success=len(errors) == 0,
    )
    
    # Display results per module
    dashboard.console.print()
    dashboard.console.print("[bold]📊 Discovery Module Results:[/bold]")
    for module_name, (cve_count, ghost_count) in module_results.items():
        dashboard.display_discovery_results(module_name, cve_count, ghost_count)
    
    # Display hunt summary
    duration = (datetime.utcnow() - started_at).total_seconds()
    dashboard.display_hunt_summary(
        total_cves=len(unique_cves),
        new_ghosts=new_ghosts,
        total_ghosts=stats["total_ghosts"],
        duration_seconds=duration,
    )
    
    if errors:
        dashboard.console.print()
        dashboard.display_warning(f"{len(errors)} errors occurred during hunt")
        for error in errors[:5]:  # Show first 5 errors
            dashboard.console.print(f"  [dim red]• {error}[/dim red]")
        if len(errors) > 5:
            dashboard.console.print(f"  [dim]... and {len(errors) - 5} more[/dim]")
    
    return {
        "total_cves": len(unique_cves),
        "new_ghosts": new_ghosts,
        "total_ghosts": stats["total_ghosts"],
        "duration_seconds": duration,
        "errors": errors,
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
  python main.py --hunt              Run CVE discovery
  python main.py --report            Generate reports
  python main.py --hunt --report     Hunt then report
  python main.py --dashboard         Show Ghost CVE dashboard
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
        if not any([args.hunt, args.report, args.dashboard]):
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
        
        if args.report:
            run_report(
                db_manager=db_manager,
                dashboard=dashboard,
                output_dir=args.output_dir,
                format=args.format,
            )
        
        if args.dashboard and not args.hunt and not args.report:
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
