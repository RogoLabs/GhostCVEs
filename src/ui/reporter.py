"""
Report Generator
================

Generates formatted reports of Ghost CVE discoveries in
various output formats (console, JSON, CSV, Markdown).

Author: rogolabs.net
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich import box

from src.config import APP_SETTINGS
from src.storage.database import DatabaseManager
from src.storage.models import GhostCVE


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates reports of Ghost CVE discoveries.
    
    Supports multiple output formats and can write to files
    or display in the terminal.
    
    Attributes:
        db_manager: Database manager for data access
        console: Rich Console for terminal output
    """
    
    def __init__(self, db_manager: DatabaseManager) -> None:
        """
        Initialize the report generator.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.console = Console()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def generate_console_report(
        self,
        only_ghosts: bool = True,
        limit: int | None = None,
    ) -> None:
        """
        Generate and display a console report.
        
        Args:
            only_ghosts: Only include Ghost CVEs
            limit: Maximum number of entries
        """
        ghosts = self.db_manager.get_ghost_cves(
            limit=limit,
            only_ghosts=only_ghosts,
        )
        
        if not ghosts:
            self.console.print("[yellow]No Ghost CVEs found in database.[/yellow]")
            return
        
        # Create detailed table
        table = Table(
            title=f"[bold]Ghost CVE Report[/bold] - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        
        table.add_column("CVE ID", style="bold yellow", no_wrap=True)
        table.add_column("Source", style="cyan", max_width=30)
        table.add_column("First Seen", style="dim")
        table.add_column("Evidence", style="blue", max_width=50)
        
        for ghost in ghosts:
            sources = self.db_manager.get_sources_for_cve(ghost.cve_id)
            primary_source = sources[0] if sources else None
            
            # Get primary source name
            source_name = primary_source.source_name if primary_source else "Unknown"
            # Truncate long source names
            if len(source_name) > 30:
                source_name = source_name[:27] + "..."
            
            # Get evidence URL (truncated for display)
            evidence_url = ""
            if primary_source and primary_source.evidence_url:
                url = primary_source.evidence_url
                if len(url) > 50:
                    evidence_url = url[:47] + "..."
                else:
                    evidence_url = url
            
            table.add_row(
                ghost.cve_id,
                source_name,
                ghost.first_seen.strftime("%Y-%m-%d"),
                evidence_url,
            )
        
        self.console.print(table)
        
        # Print summary
        stats = self.db_manager.get_statistics()
        self.console.print()
        self.console.print(
            f"[bold]Summary:[/bold] {stats['total_ghosts']} active ghosts, "
            f"{stats['total_sources']} discovery sources"
        )
    
    def generate_json_report(
        self,
        output_path: Path | str | None = None,
        only_ghosts: bool = True,
    ) -> str:
        """
        Generate a JSON report.
        
        Args:
            output_path: Optional file path to write report
            only_ghosts: Only include Ghost CVEs
        
        Returns:
            JSON string of the report
        """
        ghosts = self.db_manager.get_ghost_cves(only_ghosts=only_ghosts)
        stats = self.db_manager.get_statistics()
        
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_ghosts": stats["total_ghosts"],
                "total_cves_tracked": stats["total_cves"],
                "total_sources": stats["total_sources"],
                "oldest_ghost": stats.get("oldest_ghost"),
                "oldest_ghost_days": stats.get("oldest_ghost_days", 0),
            },
            "ghosts": [],
        }
        
        for ghost in ghosts:
            sources = self.db_manager.get_sources_for_cve(ghost.cve_id)
            
            ghost_data = {
                "cve_id": ghost.cve_id,
                "first_seen": ghost.first_seen.isoformat(),
                "last_checked": ghost.last_checked.isoformat(),
                "days_in_limbo": ghost.days_in_limbo,
                "registry_status": ghost.registry_status,
                "registry_source": ghost.registry_source,
                "confidence_score": ghost.confidence_score,
                "description": ghost.description,
                "sources": [
                    {
                        "type": s.source_type,
                        "name": s.source_name,
                        "url": s.evidence_url,
                        "discovered_at": s.discovered_at.isoformat(),
                        "context": s.context,
                    }
                    for s in sources
                ],
            }
            
            report["ghosts"].append(ghost_data)
        
        json_str = json.dumps(report, indent=2)
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_str)
            self.logger.info(f"JSON report written to {output_path}")
        
        return json_str
    
    def generate_csv_report(
        self,
        output_path: Path | str | None = None,
        only_ghosts: bool = True,
    ) -> str:
        """
        Generate a CSV report.
        
        Args:
            output_path: Optional file path to write report
            only_ghosts: Only include Ghost CVEs
        
        Returns:
            CSV string of the report
        """
        csv_content = self.db_manager.export_ghosts_csv()
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(csv_content)
            self.logger.info(f"CSV report written to {output_path}")
        
        return csv_content
    
    def generate_markdown_report(
        self,
        output_path: Path | str | None = None,
        only_ghosts: bool = True,
    ) -> str:
        """
        Generate a Markdown report.
        
        Args:
            output_path: Optional file path to write report
            only_ghosts: Only include Ghost CVEs
        
        Returns:
            Markdown string of the report
        """
        ghosts = self.db_manager.get_ghost_cves(only_ghosts=only_ghosts)
        stats = self.db_manager.get_statistics()
        
        lines = [
            "# Ghost CVE Report",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Summary",
            "",
            f"- **Active Ghosts:** {stats['total_ghosts']}",
            f"- **Total CVEs Tracked:** {stats['total_cves']}",
            f"- **Discovery Sources:** {stats['total_sources']}",
        ]
        
        if stats.get("oldest_ghost"):
            lines.append(
                f"- **Oldest Ghost:** {stats['oldest_ghost']} "
                f"({stats['oldest_ghost_days']} days)"
            )
        
        lines.extend([
            "",
            "## Ghost CVE Registry",
            "",
            "| CVE ID | Source | First Seen | Evidence |",
            "|--------|--------|------------|----------|",
        ])
        
        for ghost in ghosts:
            sources = self.db_manager.get_sources_for_cve(ghost.cve_id)
            primary_source = sources[0] if sources else None
            
            source_name = primary_source.source_name if primary_source else "Unknown"
            evidence = ""
            if primary_source:
                evidence = f"[Link]({primary_source.evidence_url})"
            
            lines.append(
                f"| {ghost.cve_id} | {source_name} | "
                f"{ghost.first_seen.strftime('%Y-%m-%d')} | {evidence} |"
            )
        
        # Add detailed sections for critical ghosts
        critical_ghosts = [
            g for g in ghosts
            if g.days_in_limbo >= APP_SETTINGS.limbo_critical_days
        ]
        
        if critical_ghosts:
            lines.extend([
                "",
                "## Critical Ghosts (30+ Days)",
                "",
            ])
            
            for ghost in critical_ghosts:
                sources = self.db_manager.get_sources_for_cve(ghost.cve_id)
                
                lines.extend([
                    f"### {ghost.cve_id}",
                    "",
                    f"- **First Seen:** {ghost.first_seen.strftime('%Y-%m-%d')}",
                    f"- **Days in Limbo:** {ghost.days_in_limbo}",
                    "",
                    "**Discovery Sources:**",
                    "",
                ])
                
                for source in sources:
                    lines.append(
                        f"- [{source.source_name}]({source.evidence_url}) "
                        f"({source.discovered_at.strftime('%Y-%m-%d')})"
                    )
                
                lines.append("")
        
        lines.extend([
            "",
            "---",
            "",
            "*Generated by [Ghost Hunter](https://github.com/rogolabs/GhostCVEs) | rogolabs.net*",
        ])
        
        md_content = "\n".join(lines)
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(md_content)
            self.logger.info(f"Markdown report written to {output_path}")
        
        return md_content
    
    def _archive_old_reports(self, output_dir: Path) -> None:
        """
        Move existing reports to archive folder.
        
        Args:
            output_dir: Main reports directory
        """
        archive_dir = output_dir / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        
        # Move all existing report files to archive
        for pattern in ["ghost_report_*.json", "ghost_report_*.csv", "ghost_report_*.md"]:
            for old_report in output_dir.glob(pattern):
                # Don't move the main ghost_report.md
                if old_report.name == "ghost_report.md":
                    continue
                dest = archive_dir / old_report.name
                old_report.rename(dest)
                self.logger.debug(f"Archived {old_report.name}")
    
    def generate_all_reports(
        self,
        output_dir: Path | str | None = None,
    ) -> dict[str, Path]:
        """
        Generate reports in all supported formats.
        
        Args:
            output_dir: Directory to write reports.
                       Defaults to APP_SETTINGS.output_dir.
        
        Returns:
            Dictionary mapping format to output file path
        """
        output_dir = Path(output_dir or APP_SETTINGS.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Archive old reports first
        self._archive_old_reports(output_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        outputs = {}
        
        # JSON report (timestamped)
        json_path = output_dir / f"ghost_report_{timestamp}.json"
        self.generate_json_report(json_path)
        outputs["json"] = json_path
        
        # CSV report (timestamped)
        csv_path = output_dir / f"ghost_report_{timestamp}.csv"
        self.generate_csv_report(csv_path)
        outputs["csv"] = csv_path
        
        # Markdown report (timestamped)
        md_path = output_dir / f"ghost_report_{timestamp}.md"
        self.generate_markdown_report(md_path)
        outputs["markdown"] = md_path
        
        # Also write latest markdown as ghost_report.md
        latest_md_path = output_dir / "ghost_report.md"
        self.generate_markdown_report(latest_md_path)
        outputs["latest_markdown"] = latest_md_path
        
        self.logger.info(f"Generated reports in {output_dir}")
        
        return outputs
