"""
Terminal Dashboard
==================

Rich-based terminal dashboard for Ghost Hunter.
Provides real-time visualization of Ghost CVE discoveries.

Author: rogolabs.net
"""

import logging
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich import box

from src.config import APP_SETTINGS
from src.storage.models import GhostCVE, DiscoverySource


logger = logging.getLogger(__name__)


class Dashboard:
    """
    Rich terminal dashboard for Ghost Hunter.
    
    Provides visual display of Ghost CVE discoveries including
    tables, progress indicators, and statistics panels.
    
    Attributes:
        console: Rich Console instance
        show_welcome: Whether to display welcome banner
    """
    
    def __init__(self, show_welcome: bool = True) -> None:
        """
        Initialize the dashboard.
        
        Args:
            show_welcome: Whether to display welcome banner on start
        """
        self.console = Console()
        self.show_welcome = show_welcome
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def display_welcome(self) -> None:
        """Display the Ghost Hunter welcome banner."""
        banner = """
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
        """
        
        panel = Panel(
            Text(banner, style="bold cyan"),
            title="[bold white]rogolabs.net[/bold white]",
            subtitle="[dim]CVE Intelligence Platform[/dim]",
            border_style="cyan",
            box=box.DOUBLE,
        )
        
        self.console.print(panel)
        self.console.print()
    
    def display_ghost_table(
        self,
        ghosts: list[GhostCVE],
        sources_map: dict[str, list[DiscoverySource]] | None = None,
        title: str = "Ghost CVE Registry",
    ) -> None:
        """
        Display a table of Ghost CVEs.
        
        Args:
            ghosts: List of GhostCVE records to display
            sources_map: Optional mapping of CVE ID to discovery sources
            title: Table title
        """
        table = Table(
            title=f"[bold cyan]{title}[/bold cyan]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            border_style="blue",
            title_style="bold white",
        )
        
        # Define columns
        table.add_column("CVE ID", style="bold yellow", no_wrap=True)
        table.add_column("Days in Limbo", justify="center", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Source Type", style="green")
        table.add_column("Evidence URL", style="blue", overflow="fold")
        
        for ghost in ghosts:
            # Determine status style
            days = ghost.days_in_limbo
            if days >= APP_SETTINGS.limbo_critical_days:
                days_style = "bold red"
                days_text = f"🔴 {days}"
            elif days >= APP_SETTINGS.limbo_warning_days:
                days_style = "bold yellow"
                days_text = f"🟡 {days}"
            else:
                days_style = "green"
                days_text = f"🟢 {days}"
            
            # Get primary source
            sources = sources_map.get(ghost.cve_id, []) if sources_map else []
            primary_source = sources[0] if sources else None
            
            # Status styling
            status = ghost.registry_status
            if status == "RESERVED":
                status_text = Text("RESERVED", style="yellow")
            elif status == "NOT_FOUND":
                status_text = Text("NOT_FOUND", style="red")
            else:
                status_text = Text(status, style="dim")
            
            table.add_row(
                ghost.cve_id,
                Text(days_text, style=days_style),
                status_text,
                primary_source.source_type if primary_source else "-",
                primary_source.evidence_url[:60] + "..." if primary_source and len(primary_source.evidence_url) > 60 else (primary_source.evidence_url if primary_source else "-"),
            )
        
        self.console.print(table)
        self.console.print()
    
    def display_statistics(self, stats: dict) -> None:
        """
        Display statistics panel.
        
        Args:
            stats: Dictionary of statistics from DatabaseManager.get_statistics()
        """
        # Create statistics grid
        stats_table = Table(
            show_header=False,
            box=box.SIMPLE,
            padding=(0, 2),
        )
        
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value", justify="right", style="cyan")
        
        stats_table.add_row("Total CVEs Tracked", str(stats.get("total_cves", 0)))
        stats_table.add_row(
            "Active Ghosts",
            Text(str(stats.get("total_ghosts", 0)), style="bold red")
        )
        stats_table.add_row("Discovery Sources", str(stats.get("total_sources", 0)))
        
        if stats.get("oldest_ghost"):
            stats_table.add_row(
                "Oldest Ghost",
                f"{stats['oldest_ghost']} ({stats['oldest_ghost_days']} days)"
            )
        
        # Status breakdown
        status_breakdown = stats.get("status_breakdown", {})
        if status_breakdown:
            stats_table.add_row("", "")  # Spacer
            stats_table.add_row("[bold]Status Breakdown[/bold]", "")
            for status, count in status_breakdown.items():
                stats_table.add_row(f"  {status}", str(count))
        
        panel = Panel(
            stats_table,
            title="[bold white]📊 Statistics[/bold white]",
            border_style="green",
            box=box.ROUNDED,
        )
        
        self.console.print(panel)
        self.console.print()
    
    def display_hunt_progress(self) -> Progress:
        """
        Create and return a progress display for hunt operations.
        
        Returns:
            Rich Progress instance for tracking hunt progress
        """
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
        )
        
        return progress
    
    def display_discovery_results(
        self,
        module_name: str,
        cve_count: int,
        ghost_count: int,
    ) -> None:
        """
        Display discovery results for a module.
        
        Args:
            module_name: Name of the discovery module
            cve_count: Number of CVEs discovered
            ghost_count: Number of Ghosts identified
        """
        if ghost_count > 0:
            style = "bold red"
            icon = "👻"
        elif cve_count > 0:
            style = "green"
            icon = "✓"
        else:
            style = "dim"
            icon = "○"
        
        self.console.print(
            f"  {icon} [bold]{module_name}[/bold]: "
            f"[cyan]{cve_count}[/cyan] CVEs found, "
            f"[{style}]{ghost_count}[/{style}] Ghosts"
        )
    
    def display_hunt_summary(
        self,
        total_cves: int,
        new_ghosts: int,
        total_ghosts: int,
        duration_seconds: float,
    ) -> None:
        """
        Display hunt completion summary.
        
        Args:
            total_cves: Total CVE mentions discovered
            new_ghosts: Number of new Ghosts found
            total_ghosts: Total Ghosts in database
            duration_seconds: Hunt duration in seconds
        """
        summary = Table(
            show_header=False,
            box=box.SIMPLE,
            padding=(0, 2),
        )
        
        summary.add_column("Metric", style="bold")
        summary.add_column("Value", justify="right")
        
        summary.add_row(
            "CVE Mentions Found",
            Text(str(total_cves), style="cyan")
        )
        summary.add_row(
            "New Ghosts Identified",
            Text(str(new_ghosts), style="bold red" if new_ghosts > 0 else "green")
        )
        summary.add_row(
            "Total Ghosts in Registry",
            Text(str(total_ghosts), style="yellow")
        )
        summary.add_row(
            "Hunt Duration",
            f"{duration_seconds:.1f}s"
        )
        
        panel = Panel(
            summary,
            title="[bold white]🎯 Hunt Complete[/bold white]",
            border_style="green",
            box=box.DOUBLE,
        )
        
        self.console.print()
        self.console.print(panel)
    
    def display_error(self, message: str) -> None:
        """
        Display an error message.
        
        Args:
            message: Error message to display
        """
        self.console.print(
            Panel(
                Text(message, style="bold red"),
                title="[bold red]❌ Error[/bold red]",
                border_style="red",
            )
        )
    
    def display_warning(self, message: str) -> None:
        """
        Display a warning message.
        
        Args:
            message: Warning message to display
        """
        self.console.print(
            f"[bold yellow]⚠️  Warning:[/bold yellow] {message}"
        )
    
    def display_info(self, message: str) -> None:
        """
        Display an info message.
        
        Args:
            message: Info message to display
        """
        self.console.print(f"[blue]ℹ️  {message}[/blue]")
    
    def display_success(self, message: str) -> None:
        """
        Display a success message.
        
        Args:
            message: Success message to display
        """
        self.console.print(f"[bold green]✅ {message}[/bold green]")

    def display_source_health(self, health_monitor) -> None:
        """
        Display source health status dashboard.

        Shows health status for all discovery sources including:
        - Current status (HEALTHY/DEGRADED/FAILING)
        - Last successful fetch time
        - Consecutive failure count
        - 24-hour error rate
        - Response times

        Args:
            health_monitor: SourceHealthMonitor instance from orchestrator
        """
        from datetime import datetime, timezone
        from src.monitoring.source_health import HealthStatus

        # Create health status table
        table = Table(title="📊 Source Health Status", show_header=True, header_style="bold")
        table.add_column("Source", style="cyan", no_wrap=True, width=30)
        table.add_column("Status", justify="center", width=12)
        table.add_column("Last Success", justify="center", width=12)
        table.add_column("Failures", justify="right", width=10)
        table.add_column("Error Rate", justify="right", width=12)
        table.add_column("Avg Response", justify="right", width=13)

        all_health = health_monitor.get_all_health()

        if not all_health:
            self.console.print("\n[yellow]No source health data available yet.[/yellow]")
            self.console.print("[dim]Run a hunt first to populate health metrics.[/dim]\n")
            return

        # Sort by status (failing first) then by consecutive failures
        all_health.sort(key=lambda h: (
            0 if h.status == HealthStatus.FAILING else (1 if h.status == HealthStatus.DEGRADED else 2),
            -h.consecutive_failures
        ))

        for health in all_health:
            # Status with emoji and color
            if health.status == HealthStatus.HEALTHY:
                status = "[green]✓ Healthy[/green]"
            elif health.status == HealthStatus.DEGRADED:
                status = "[yellow]⚠ Degraded[/yellow]"
            else:
                status = "[red]✗ Failing[/red]"

            # Last success time (human-readable)
            if health.last_success:
                time_ago = datetime.now(timezone.utc) - health.last_success
                total_seconds = time_ago.total_seconds()
                if total_seconds < 60:
                    last_success = "just now"
                elif total_seconds < 3600:
                    last_success = f"{int(total_seconds / 60)}m ago"
                elif total_seconds < 86400:
                    last_success = f"{int(total_seconds / 3600)}h ago"
                else:
                    last_success = f"{time_ago.days}d ago"
            else:
                last_success = "[dim]Never[/dim]"

            # Format error rate with color
            error_rate_pct = health.error_rate_24h * 100
            if error_rate_pct < 5:
                error_rate = f"[green]{error_rate_pct:.1f}%[/green]"
            elif error_rate_pct < 25:
                error_rate = f"[yellow]{error_rate_pct:.1f}%[/yellow]"
            else:
                error_rate = f"[red]{error_rate_pct:.1f}%[/red]"

            # Format response time
            if health.avg_response_time > 0:
                avg_response = f"{health.avg_response_time:.2f}s"
            else:
                avg_response = "[dim]N/A[/dim]"

            table.add_row(
                health.source_name,
                status,
                last_success,
                str(health.consecutive_failures),
                error_rate,
                avg_response
            )

        self.console.print()
        self.console.print(table)

        # Summary statistics
        healthy_count = sum(1 for h in all_health if h.status == HealthStatus.HEALTHY)
        degraded_count = sum(1 for h in all_health if h.status == HealthStatus.DEGRADED)
        failing_count = sum(1 for h in all_health if h.status == HealthStatus.FAILING)
        total_count = len(all_health)

        self.console.print()
        self.console.print("[bold]Summary:[/bold]")
        self.console.print(f"  Total Sources: {total_count}")
        self.console.print(f"  Healthy: [green]{healthy_count}[/green] ({healthy_count/total_count*100:.1f}%)")
        self.console.print(f"  Degraded: [yellow]{degraded_count}[/yellow] ({degraded_count/total_count*100:.1f}%)")
        self.console.print(f"  Failing: [red]{failing_count}[/red] ({failing_count/total_count*100:.1f}%)")

        # Show failing sources with errors
        if failing_count > 0:
            self.console.print()
            self.console.print("[bold red]Failing Sources:[/bold red]")
            failing = health_monitor.get_failing_sources()
            for health in failing:
                self.console.print(f"  • {health.source_name}: {health.last_error}")

        # Show degraded sources
        if degraded_count > 0:
            self.console.print()
            self.console.print("[bold yellow]Degraded Sources:[/bold yellow]")
            degraded = health_monitor.get_degraded_sources()
            for health in degraded:
                error_msg = health.last_error if health.last_error else "Multiple failures"
                self.console.print(f"  • {health.source_name}: {error_msg}")

        self.console.print()
