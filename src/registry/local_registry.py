"""
Local CVE Registry
==================

Fast CVE validation using a local clone of the CVEProject/cvelistV5 repository.
This avoids rate-limited API calls and provides instant lookups.

Author: rogolabs.net
"""

import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.config import APP_SETTINGS


logger = logging.getLogger(__name__)


class LocalCVERegistry:
    """
    Local CVE registry using cloned CVEProject/cvelistV5 repository.
    
    Provides fast O(1) lookups for CVE status without API rate limits.
    The repository contains all CVE records in JSON 5.0 format.
    
    Attributes:
        data_dir: Base directory for data storage
        repo_path: Path to the cloned cvelistV5 repository
        repo_url: URL of the CVE repository
    """
    
    REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
    REPO_NAME = "cvelistV5"
    
    def __init__(self, data_dir: str | Path = "data") -> None:
        """
        Initialize the local CVE registry.
        
        Args:
            data_dir: Base directory for data storage
        """
        self.data_dir = Path(data_dir)
        self.repo_path = self.data_dir / self.REPO_NAME
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._cache: dict[str, dict] = {}
    
    def ensure_repo(self, shallow: bool = True) -> bool:
        """
        Ensure the CVE repository is cloned and up to date.
        
        Args:
            shallow: If True, use shallow clone (faster, less disk space)
        
        Returns:
            True if repo is ready, False on error
        """
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        if self.repo_path.exists():
            return self._update_repo()
        else:
            return self._clone_repo(shallow)
    
    def _clone_repo(self, shallow: bool = True) -> bool:
        """
        Clone the CVE repository.
        
        Args:
            shallow: If True, use shallow clone
        
        Returns:
            True if successful
        """
        self.logger.info(f"Cloning CVE repository to {self.repo_path}...")
        
        cmd = ["git", "clone"]
        if shallow:
            cmd.extend(["--depth", "1"])
        cmd.extend([self.REPO_URL, str(self.repo_path)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )
            
            if result.returncode != 0:
                self.logger.error(f"Clone failed: {result.stderr}")
                return False
            
            self.logger.info("CVE repository cloned successfully")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Clone timed out")
            return False
        except Exception as e:
            self.logger.error(f"Clone error: {e}")
            return False
    
    def _update_repo(self) -> bool:
        """
        Update the CVE repository with latest changes.
        
        Returns:
            True if successful
        """
        self.logger.info("Updating CVE repository...")
        
        try:
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                self.logger.warning(f"Pull failed: {result.stderr}")
                # Try fetch + reset for shallow clones
                subprocess.run(
                    ["git", "fetch", "--depth", "1"],
                    cwd=self.repo_path,
                    capture_output=True,
                    timeout=300,
                )
                subprocess.run(
                    ["git", "reset", "--hard", "origin/main"],
                    cwd=self.repo_path,
                    capture_output=True,
                    timeout=60,
                )
            
            self.logger.info("CVE repository updated")
            self._cache.clear()
            return True
            
        except Exception as e:
            self.logger.error(f"Update error: {e}")
            return False
    
    def _get_cve_path(self, cve_id: str) -> Path | None:
        """
        Get the file path for a CVE ID.
        
        CVE files are organized as:
        cves/{year}/{prefix}xxx/CVE-{year}-{id}.json
        
        Example: cves/2025/1xxx/CVE-2025-1234.json
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2025-12345)
        
        Returns:
            Path to CVE JSON file or None if invalid ID
        """
        cve_id = cve_id.upper()
        
        # Parse CVE ID
        parts = cve_id.split("-")
        if len(parts) != 3 or parts[0] != "CVE":
            return None
        
        year = parts[1]
        number = parts[2]
        
        # Calculate prefix bucket (e.g., 12345 -> 12xxx)
        if len(number) <= 4:
            prefix = f"{number[0]}xxx"
        else:
            prefix = f"{number[:-3]}xxx"
        
        # Build path
        cve_path = self.repo_path / "cves" / year / prefix / f"{cve_id}.json"
        
        return cve_path
    
    def lookup(self, cve_id: str) -> dict | None:
        """
        Look up a CVE by ID in the local repository.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            CVE data dictionary or None if not found
        """
        cve_id = cve_id.upper()
        
        # Check cache
        if cve_id in self._cache:
            return self._cache[cve_id]
        
        # Get file path
        cve_path = self._get_cve_path(cve_id)
        if cve_path is None:
            return None
        
        # Check if file exists
        if not cve_path.exists():
            return None
        
        # Load and parse JSON
        try:
            with open(cve_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Cache the result
            self._cache[cve_id] = data
            return data
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parse error for {cve_id}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error reading {cve_id}: {e}")
            return None
    
    def get_status(self, cve_id: str) -> tuple[str, str | None]:
        """
        Get the status and description of a CVE.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Tuple of (status, description)
            Status is one of: PUBLISHED, RESERVED, REJECTED, NOT_FOUND
        """
        data = self.lookup(cve_id)
        
        if data is None:
            return ("NOT_FOUND", None)
        
        # Extract state from cveMetadata
        metadata = data.get("cveMetadata", {})
        state = metadata.get("state", "UNKNOWN").upper()
        
        # Extract description
        description = None
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        descriptions = cna.get("descriptions", [])
        
        for desc in descriptions:
            if desc.get("lang", "").startswith("en"):
                description = desc.get("value")
                break
        
        # Check for RESERVED placeholder in description
        if description and "** RESERVED **" in description:
            state = "RESERVED"
        
        return (state, description)
    
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
        
        metadata = data.get("cveMetadata", {})
        date_str = metadata.get("datePublished")
        
        if date_str:
            try:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                return None
        
        return None
    
    def is_available(self) -> bool:
        """
        Check if the local registry is available.
        
        Returns:
            True if repo exists and contains CVE data
        """
        cves_dir = self.repo_path / "cves"
        return cves_dir.exists() and cves_dir.is_dir()
    
    def get_repo_info(self) -> dict:
        """
        Get information about the local repository.
        
        Returns:
            Dictionary with repo metadata
        """
        if not self.repo_path.exists():
            return {"status": "not_cloned"}
        
        info = {
            "status": "available",
            "path": str(self.repo_path),
        }
        
        # Get last commit info
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%H|%ci|%s"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                parts = result.stdout.strip().split("|", 2)
                if len(parts) == 3:
                    info["last_commit"] = parts[0][:8]
                    info["last_updated"] = parts[1]
                    info["commit_message"] = parts[2][:50]
                    
        except Exception:
            pass
        
        return info
