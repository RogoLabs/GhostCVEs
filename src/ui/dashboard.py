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
