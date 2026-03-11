"""
Local NVD Registry
==================

Fast CVE validation using a downloaded NVD JSON file.
Downloads the full NVD database from nvd.handsonhacking.org for local lookups.

Author: rogolabs.net
"""

import json
import logging
import os
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.config import REGISTRY_CONFIG


logger = logging.getLogger(__name__)


class NVDLocalRegistry:
    """
    Local NVD registry using downloaded nvd.json file.
    
    Provides fast lookups for CVE status without API rate limits.
    Downloads a complete NVD database for local validation.
    
    Attributes:
        data_dir: Base directory for data storage
        nvd_json_path: Path to the downloaded nvd.json file
        nvd_url: URL to download the NVD JSON from
    """
    
    def __init__(self, data_dir: str | Path = "data") -> None:
        """
        Initialize the local NVD registry.
        
        Args:
            data_dir: Base directory for data storage
        """
        self.data_dir = Path(data_dir)
        self.nvd_url = REGISTRY_CONFIG.nvd_local_url
        self.nvd_json_path = self.data_dir / REGISTRY_CONFIG.nvd_local_filename
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._cve_index: dict[str, dict] | None = None
        self._loaded = False
        self._last_loaded: datetime | None = None
    
    def ensure_nvd_data(self, force_download: bool = False, console=None) -> bool:
        """
        Ensure the NVD JSON file is downloaded and available.
        
        Args:
            force_download: If True, re-download even if file exists
            console: Optional rich console for progress display
        
        Returns:
            True if NVD data is ready, False on error
        """
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        if self.nvd_json_path.exists() and not force_download:
            self.logger.info(f"NVD JSON file exists at {self.nvd_json_path}")
            return self._load_nvd_data(console)
        else:
            if self._download_nvd_json(console):
                return self._load_nvd_data(console)
            return False
    
    def _download_nvd_json(self, console=None) -> bool:
        """
        Download the NVD JSON file from nvd.handsonhacking.org.
        
        This file is over 1GB, so we stream download with progress.
        
        Args:
            console: Optional rich console for progress display
        
        Returns:
            True if successful
        """
        self.logger.info(f"Downloading NVD JSON from {self.nvd_url}...")
        
        if console:
            console.print(f"[dim]📥 Downloading NVD database from {self.nvd_url}...[/dim]")
            console.print("[dim]   This file is over 1GB - please be patient...[/dim]")
        
        try:
            response = requests.get(
                self.nvd_url,
                stream=True,
                timeout=30,  # Connection timeout
            )
            response.raise_for_status()
            
            # Get total file size from headers
            total_size = int(response.headers.get('content-length', 0))
            
            # Download with progress
            downloaded = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            
            # Use temporary file to avoid partial downloads
            temp_path = self.nvd_json_path.with_suffix('.tmp')
            
            # Try using rich progress if console available
            if console:
                try:
                    from rich.progress import Progress, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
                    
                    with Progress(
                        "[progress.description]{task.description}",
                        BarColumn(),
                        DownloadColumn(),
                        TransferSpeedColumn(),
                        TimeRemainingColumn(),
                        console=console,
                    ) as progress:
                        task = progress.add_task(
                            "[cyan]Downloading nvd.json",
                            total=total_size if total_size else None,
                        )
                        
                        with open(temp_path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=chunk_size):
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    progress.update(task, completed=downloaded)
                except ImportError:
                    # Fallback if rich not available
                    self._download_with_basic_progress(response, temp_path, total_size, console)
            else:
                self._download_with_basic_progress(response, temp_path, total_size, console)
            
            # Move temp file to final location
            temp_path.rename(self.nvd_json_path)
            
            self.logger.info(f"NVD JSON downloaded successfully to {self.nvd_json_path}")
            if console:
                console.print(f"[green]✓ NVD database downloaded ({downloaded / (1024*1024):.1f} MB)[/green]")
            
            return True
            
        except requests.RequestException as e:
            self.logger.error(f"Download failed: {e}")
            if console:
                console.print(f"[red]✗ Download failed: {e}[/red]")
            return False
        except Exception as e:
            self.logger.error(f"Download error: {e}")
            if console:
                console.print(f"[red]✗ Download error: {e}[/red]")
            return False
    
    def _download_with_basic_progress(
        self,
        response: requests.Response,
        temp_path: Path,
        total_size: int,
        console=None,
    ) -> None:
        """
        Download with basic progress output (no rich).
        
        Args:
            response: Streaming response object
            temp_path: Temporary file path
            total_size: Total file size in bytes
            console: Optional console for output
        """
        downloaded = 0
        chunk_size = 1024 * 1024  # 1MB chunks
        last_percent = 0
        
        with open(temp_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    
                    if total_size > 0:
                        percent = int(downloaded * 100 / total_size)
                        if percent >= last_percent + 10:
                            last_percent = percent
                            self.logger.info(f"Download progress: {percent}%")
                            if console:
                                console.print(f"[dim]   {percent}% complete ({downloaded / (1024*1024):.0f} MB)[/dim]")
    
    def _load_nvd_data(self, console=None) -> bool:
        """
        Load the NVD JSON file into memory and build CVE index.
        
        Args:
            console: Optional console for status messages
        
        Returns:
            True if successful
        """
        if self._loaded:
            return True
        
        self.logger.info(f"Loading NVD JSON from {self.nvd_json_path}...")
        if console:
            console.print("[dim]📂 Loading NVD database into memory (this may take a moment)...[/dim]")
        
        try:
            # Check file size
            file_size = self.nvd_json_path.stat().st_size
            self.logger.info(f"NVD JSON file size: {file_size / (1024*1024):.1f} MB")
            
            with open(self.nvd_json_path, 'r', encoding='utf-8') as f:
                nvd_data = json.load(f)
            
            # Build index by CVE ID for O(1) lookups
            self._cve_index = {}
            
            # Handle different NVD JSON formats:
            # 1. nvd.handsonhacking.org format: flat array of {"cve": {...}} objects
            # 2. NVD API format: {"vulnerabilities": [{"cve": {...}}]}
            # 3. Legacy NVD format: {"CVE_Items": [...]}
            
            if isinstance(nvd_data, list):
                # Flat array format (nvd.handsonhacking.org)
                self.logger.info(f"Processing flat array format with {len(nvd_data)} entries")
                for item in nvd_data:
                    cve_data = item.get('cve', item)
                    cve_id = cve_data.get('id')
                    if cve_id:
                        self._cve_index[cve_id.upper()] = item
            elif isinstance(nvd_data, dict):
                # Try various dict formats
                vulnerabilities = nvd_data.get('vulnerabilities', [])
                if not vulnerabilities:
                    vulnerabilities = nvd_data.get('CVE_Items', [])
                
                if vulnerabilities:
                    self.logger.info(f"Processing vulnerabilities array with {len(vulnerabilities)} entries")
                    for vuln in vulnerabilities:
                        cve_data = vuln.get('cve', vuln)
                        cve_id = cve_data.get('id') or cve_data.get('CVE_data_meta', {}).get('ID')
                        if cve_id:
                            self._cve_index[cve_id.upper()] = vuln
                elif any(k.startswith('CVE-') for k in nvd_data.keys()):
                    # Dict keyed by CVE ID
                    self._cve_index = {k.upper(): v for k, v in nvd_data.items() if k.startswith('CVE-')}
            
            self._loaded = True
            self._last_loaded = datetime.now(timezone.utc)
            
            self.logger.info(f"Indexed {len(self._cve_index)} CVEs from NVD JSON")
            if console:
                console.print(f"[green]✓ NVD database loaded ({len(self._cve_index):,} CVEs indexed)[/green]")
            
            return True
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parse error: {e}")
            if console:
                console.print(f"[red]✗ Failed to parse NVD JSON: {e}[/red]")
            return False
        except Exception as e:
            self.logger.error(f"Error loading NVD data: {e}")
            if console:
                console.print(f"[red]✗ Error loading NVD data: {e}[/red]")
            return False
    
    def lookup(self, cve_id: str) -> dict | None:
        """
        Look up a CVE by ID in the local NVD data.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            CVE data dictionary or None if not found
        """
        if not self._loaded or self._cve_index is None:
            return None
        
        cve_id = cve_id.upper()
        return self._cve_index.get(cve_id)
    
    def get_status(self, cve_id: str) -> tuple[str, str | None]:
        """
        Get the status and description of a CVE from NVD.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Tuple of (status, description)
            Status is one of: PUBLISHED, RESERVED, REJECTED, NOT_FOUND
        """
        data = self.lookup(cve_id)
        
        if data is None:
            return ("NOT_FOUND", None)
        
        # Handle NVD 2.0 format
        cve_data = data.get('cve', data)
        
        # Check vulnStatus for RESERVED/REJECTED
        vuln_status = cve_data.get('vulnStatus', '').upper()
        
        # Extract description
        description = None
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value')
                break
        
        # Also try NVD 1.1 format
        if not description:
            cve_meta = cve_data.get('CVE_data_meta', {})
            desc_data = cve_data.get('description', {})
            desc_list = desc_data.get('description_data', [])
            for desc in desc_list:
                if desc.get('lang') == 'en':
                    description = desc.get('value')
                    break
        
        # Determine status
        if 'RESERVED' in vuln_status or 'AWAITING' in vuln_status:
            status = "RESERVED"
        elif 'REJECT' in vuln_status:
            status = "REJECTED"
        elif description and "** RESERVED **" in description:
            status = "RESERVED"
        elif description and "** REJECT **" in description:
            status = "REJECTED"
        else:
            status = "PUBLISHED"
        
        return (status, description)
    
    def get_published_date(self, cve_id: str) -> datetime | None:
        """
        Get the publication date of a CVE.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Publication datetime or None
        """
        data = self.lookup(cve_id)
        
        if data is None:
            return None
        
        cve_data = data.get('cve', data)
        date_str = cve_data.get('published')
        
        # Also try NVD 1.1 format
        if not date_str:
            date_str = cve_data.get('publishedDate')
        
        if date_str:
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except ValueError:
                try:
                    # Try alternative format
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%f')
                except ValueError:
                    return None
        
        return None
    
    def is_available(self) -> bool:
        """
        Check if the NVD data is loaded and available.
        
        Returns:
            True if NVD data is ready for lookups
        """
        return self._loaded and self._cve_index is not None
    
    def get_info(self) -> dict[str, Any]:
        """
        Get information about the local NVD data.
        
        Returns:
            Dictionary with NVD data metadata
        """
        if not self.nvd_json_path.exists():
            return {"status": "not_downloaded"}
        
        info: dict[str, Any] = {
            "status": "available" if self._loaded else "not_loaded",
            "path": str(self.nvd_json_path),
        }
        
        # Get file info
        try:
            stat = self.nvd_json_path.stat()
            info["file_size_mb"] = stat.st_size / (1024 * 1024)
            info["last_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        except Exception:
            pass
        
        if self._loaded and self._cve_index:
            info["cve_count"] = len(self._cve_index)
            info["loaded_at"] = self._last_loaded.isoformat() if self._last_loaded else None
        
        return info
    
    def needs_update(self, max_age_hours: int | None = None) -> bool:
        """
        Check if the NVD data file needs updating.
        
        Args:
            max_age_hours: Maximum age in hours before update is needed.
                          If None, uses config value.
        
        Returns:
            True if file is older than max_age_hours or doesn't exist
        """
        if max_age_hours is None:
            max_age_hours = REGISTRY_CONFIG.nvd_local_max_age_hours
            
        if not self.nvd_json_path.exists():
            return True
        
        try:
            stat = self.nvd_json_path.stat()
            file_age = datetime.now(timezone.utc) - datetime.fromtimestamp(stat.st_mtime)
            return file_age.total_seconds() > (max_age_hours * 3600)
        except Exception:
            return True
