"""
CVE Registry Validator
======================

Validates CVE status against official registries. Uses a local clone of the
CVEProject/cvelistV5 repository for fast lookups. Falls back to API calls
only when local data is unavailable.

Author: rogolabs.net
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from src.config import (
    REGISTRY_CONFIG,
    APP_SETTINGS,
)
from src.discovery.base import RateLimiter
from src.models.enums import CVEStatus
from src.registry.local_registry import LocalCVERegistry
from src.registry.nvd_local import NVDLocalRegistry


logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """
    Result of CVE validation against registries.
    
    Attributes:
        cve_id: The CVE identifier that was validated
        status: Current CVE status from registry
        is_ghost: Whether this CVE qualifies as a Ghost CVE
        registry_source: Which registry provided the status
        description: CVE description if available
        published_date: Publication date if available
        last_modified: Last modification date if available
        raw_response: Raw API response for debugging
        validated_at: Timestamp of validation
    """
    cve_id: str
    status: CVEStatus
    is_ghost: bool
    registry_source: str
    description: str | None = None
    published_date: datetime | None = None
    last_modified: datetime | None = None
    raw_response: dict | None = None
    validated_at: datetime | None = None
    
    def __post_init__(self) -> None:
        """Set validation timestamp if not provided."""
        if self.validated_at is None:
            self.validated_at = datetime.utcnow()


class CVEValidator:
    """
    Validates CVE identifiers against official registries.
    
    Uses a local clone of CVEProject/cvelistV5 for fast lookups.
    Falls back to local NVD JSON file (downloaded from nvd.handsonhacking.org).
    A CVE is considered a "Ghost" if it's found in public sources but
    is either RESERVED or NOT_FOUND in official registries.
    
    Attributes:
        local_registry: Local CVE registry for fast lookups
        nvd_local: Local NVD JSON registry for validation
        session: Requests session for HTTP calls
        use_local: Whether to use local registry (default: True)
    """
    
    def __init__(
        self,
        nvd_api_key: str | None = None,
        data_dir: str | Path = "data",
        use_local: bool = True,
        console = None,
    ) -> None:
        """
        Initialize the CVE validator.
        
        Args:
            nvd_api_key: Deprecated - no longer used (local NVD file used instead).
            data_dir: Directory for local CVE repository clone and NVD JSON.
            use_local: Whether to use local registry (default: True).
            console: Optional rich console for progress display.
        """
        self.nvd_api_key = nvd_api_key  # Kept for compatibility but not used
        self.use_local = use_local
        self.session = self._create_session()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.console = console
        
        # Initialize local CVE registry (CVEProject/cvelistV5)
        self.local_registry = LocalCVERegistry(data_dir)
        self._local_available = False
        
        # Initialize local NVD registry (downloaded nvd.json)
        self.nvd_local = NVDLocalRegistry(data_dir)
        self._nvd_local_available = False
        
        # MITRE has more lenient rate limits (only used as final fallback)
        self.mitre_rate_limiter = RateLimiter(
            requests_per_window=30,
            window_seconds=60,
        )
        
        # Cache for recent validations
        self._cache: dict[str, ValidationResult] = {}
        self._cache_ttl_seconds = 3600  # 1 hour cache
    
    def ensure_local_registry(self) -> bool:
        """
        Ensure the local CVE registry and NVD data are available.
        
        Clones or updates the CVEProject/cvelistV5 repository.
        Downloads NVD JSON from nvd.handsonhacking.org if needed.
        
        Returns:
            True if at least one local registry is ready
        """
        if not self.use_local:
            return False
        
        self.logger.info("Ensuring local CVE registry is available...")
        self._local_available = self.local_registry.ensure_repo(shallow=True)
        
        if self._local_available:
            info = self.local_registry.get_repo_info()
            self.logger.info(
                f"Local CVE registry ready: {info.get('last_updated', 'unknown')}"
            )
        else:
            self.logger.warning("Local CVE registry not available")
        
        # Also ensure NVD local data is available
        self.logger.info("Ensuring local NVD data is available...")
        self._nvd_local_available = self.nvd_local.ensure_nvd_data(console=self.console)
        
        if self._nvd_local_available:
            info = self.nvd_local.get_info()
            self.logger.info(
                f"Local NVD data ready: {info.get('cve_count', 'unknown')} CVEs"
            )
        else:
            self.logger.warning("Local NVD data not available")
        
        if not self._local_available and not self._nvd_local_available:
            self.logger.error("No local registries available - validation will be limited")
        
        return self._local_available or self._nvd_local_available
    
    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests session.
        
        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        session.headers.update({
            "User-Agent": APP_SETTINGS.user_agent,
            "Accept": "application/json",
        })
        
        if self.nvd_api_key:
            session.headers["apiKey"] = self.nvd_api_key
        
        return session
    
    def validate(self, cve_id: str, found_in_wild: bool = True) -> ValidationResult:
        """
        Validate a CVE ID against local registries.
        
        Uses local CVE repository and NVD JSON for fast lookups.
        No external API calls are made - local sources are comprehensive.
        
        Args:
            cve_id: CVE identifier to validate (e.g., CVE-2025-12345)
            found_in_wild: Whether this CVE was found in public sources
        
        Returns:
            ValidationResult with status and Ghost classification
        """
        cve_id = cve_id.upper()
        
        # Check cache first
        cached = self._get_cached(cve_id)
        if cached is not None:
            self.logger.debug(f"Cache hit for {cve_id}")
            return cached
        
        self.logger.debug(f"Validating CVE: {cve_id}")
        
        # Try local CVE registry first (CVEProject/cvelistV5 - fast!)
        if self._local_available:
            result = self._validate_local(cve_id, found_in_wild)
            if result is not None:
                self._cache[cve_id] = result
                return result
        
        # Try local NVD data next (nvd.json - also fast!)
        if self._nvd_local_available:
            result = self._validate_nvd_local(cve_id, found_in_wild)
            self._cache[cve_id] = result
            return result
        
        # If no local sources available, return NOT_FOUND
        result = self._create_result(
            cve_id=cve_id,
            status=CVEStatus.NOT_FOUND,
            found_in_wild=found_in_wild,
            registry_source="NONE",
        )
        self._cache[cve_id] = result
        return result
    
    def _validate_local(
        self,
        cve_id: str,
        found_in_wild: bool,
    ) -> ValidationResult | None:
        """
        Validate CVE against local repository.
        
        Args:
            cve_id: CVE identifier
            found_in_wild: Whether CVE was found in public sources
        
        Returns:
            ValidationResult or None if not in local repo
        """
        status_str, description = self.local_registry.get_status(cve_id)
        published_date = self.local_registry.get_published_date(cve_id)
        
        # Map string status to enum
        status_map = {
            "PUBLISHED": CVEStatus.PUBLISHED,
            "RESERVED": CVEStatus.RESERVED,
            "REJECTED": CVEStatus.REJECTED,
            "NOT_FOUND": CVEStatus.NOT_FOUND,
        }
        
        status = status_map.get(status_str, CVEStatus.NOT_FOUND)
        
        # For NOT_FOUND, return None to trigger API fallback
        # (the CVE might be very new and not in our local clone yet)
        if status == CVEStatus.NOT_FOUND:
            return None
        
        return self._create_result(
            cve_id=cve_id,
            status=status,
            found_in_wild=found_in_wild,
            registry_source="LOCAL",
            description=description,
            published_date=published_date,
        )
    
    def _validate_nvd_local(
        self,
        cve_id: str,
        found_in_wild: bool,
    ) -> ValidationResult:
        """
        Validate CVE against local NVD JSON data.
        
        Args:
            cve_id: CVE identifier
            found_in_wild: Whether CVE was found in public sources
        
        Returns:
            ValidationResult from local NVD data
        """
        status_str, description = self.nvd_local.get_status(cve_id)
        published_date = self.nvd_local.get_published_date(cve_id)
        
        # Map string status to enum
        status_map = {
            "PUBLISHED": CVEStatus.PUBLISHED,
            "RESERVED": CVEStatus.RESERVED,
            "REJECTED": CVEStatus.REJECTED,
            "NOT_FOUND": CVEStatus.NOT_FOUND,
        }
        
        status = status_map.get(status_str, CVEStatus.NOT_FOUND)
        
        return self._create_result(
            cve_id=cve_id,
            status=status,
            found_in_wild=found_in_wild,
            registry_source="NVD_LOCAL",
            description=description,
            published_date=published_date,
        )
    
    def validate_batch(
        self,
        cve_ids: list[str],
        found_in_wild: bool = True,
    ) -> list[ValidationResult]:
        """
        Validate multiple CVE IDs.
        
        Args:
            cve_ids: List of CVE identifiers to validate
            found_in_wild: Whether these CVEs were found in public sources
        
        Returns:
            List of ValidationResult objects
        """
        results = []
        
        for cve_id in cve_ids:
            result = self.validate(cve_id, found_in_wild)
            results.append(result)
            
            # Small delay between requests to be respectful
            time.sleep(0.1)
        
        return results
    
    def _validate_nvd(
        self,
        cve_id: str,
        found_in_wild: bool,
    ) -> ValidationResult:
        """
        Validate CVE against NVD API 2.0.
        
        Args:
            cve_id: CVE identifier to validate
            found_in_wild: Whether this CVE was found in public sources
        
        Returns:
            ValidationResult from NVD
        """
        # Wait for rate limit
        wait_time = self.nvd_rate_limiter.acquire()
        if wait_time > 0:
            self.logger.debug(f"NVD rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
        
        url = f"{REGISTRY_CONFIG.nvd_api_base}?cveId={cve_id}"
        
        try:
            response = self.session.get(
                url,
                timeout=REGISTRY_CONFIG.timeout_seconds,
            )
            
            if response.status_code == 404:
                return self._create_result(
                    cve_id=cve_id,
                    status=CVEStatus.NOT_FOUND,
                    found_in_wild=found_in_wild,
                    registry_source="NVD",
                )
            
            if response.status_code == 403:
                self.logger.warning("NVD API rate limit exceeded")
                return self._create_result(
                    cve_id=cve_id,
                    status=CVEStatus.ERROR,
                    found_in_wild=found_in_wild,
                    registry_source="NVD",
                )
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_nvd_response(cve_id, data, found_in_wild)
            
        except requests.RequestException as e:
            self.logger.error(f"NVD API request failed for {cve_id}: {e}")
            return self._create_result(
                cve_id=cve_id,
                status=CVEStatus.ERROR,
                found_in_wild=found_in_wild,
                registry_source="NVD",
            )
    
    def _parse_nvd_response(
        self,
        cve_id: str,
        data: dict,
        found_in_wild: bool,
    ) -> ValidationResult:
        """
        Parse NVD API 2.0 response.
        
        Args:
            cve_id: CVE identifier
            data: NVD API response data
            found_in_wild: Whether CVE was found in public sources
        
        Returns:
            ValidationResult parsed from NVD data
        """
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return self._create_result(
                cve_id=cve_id,
                status=CVEStatus.NOT_FOUND,
                found_in_wild=found_in_wild,
                registry_source="NVD",
            )
        
        vuln = vulnerabilities[0]
        cve_data = vuln.get("cve", {})
        
        # Check vulnStatus field for RESERVED/REJECTED
        vuln_status = cve_data.get("vulnStatus", "").upper()
        
        # Parse dates
        published_date = None
        last_modified = None
        
        pub_str = cve_data.get("published")
        if pub_str:
            try:
                published_date = datetime.fromisoformat(
                    pub_str.replace("Z", "+00:00")
                )
            except ValueError:
                pass
        
        mod_str = cve_data.get("lastModified")
        if mod_str:
            try:
                last_modified = datetime.fromisoformat(
                    mod_str.replace("Z", "+00:00")
                )
            except ValueError:
                pass
        
        # Extract description
        description = None
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        
        # Determine status
        if "RESERVED" in vuln_status or "AWAITING" in vuln_status:
            status = CVEStatus.RESERVED
        elif "REJECT" in vuln_status:
            status = CVEStatus.REJECTED
        elif description and "** RESERVED **" in description:
            status = CVEStatus.RESERVED
        else:
            status = CVEStatus.PUBLISHED
        
        return self._create_result(
            cve_id=cve_id,
            status=status,
            found_in_wild=found_in_wild,
            registry_source="NVD",
            description=description,
            published_date=published_date,
            last_modified=last_modified,
            raw_response=data,
        )
    
    def _validate_mitre(
        self,
        cve_id: str,
        found_in_wild: bool,
    ) -> ValidationResult:
        """
        Validate CVE against MITRE CVE Services API.
        
        Args:
            cve_id: CVE identifier to validate
            found_in_wild: Whether this CVE was found in public sources
        
        Returns:
            ValidationResult from MITRE
        """
        # Wait for rate limit
        wait_time = self.mitre_rate_limiter.acquire()
        if wait_time > 0:
            self.logger.debug(f"MITRE rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
        
        url = f"{REGISTRY_CONFIG.cve_org_api_base}/{cve_id}"
        
        try:
            response = self.session.get(
                url,
                timeout=REGISTRY_CONFIG.timeout_seconds,
            )
            
            if response.status_code == 404:
                return self._create_result(
                    cve_id=cve_id,
                    status=CVEStatus.NOT_FOUND,
                    found_in_wild=found_in_wild,
                    registry_source="MITRE",
                )
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_mitre_response(cve_id, data, found_in_wild)
            
        except requests.RequestException as e:
            self.logger.error(f"MITRE API request failed for {cve_id}: {e}")
            return self._create_result(
                cve_id=cve_id,
                status=CVEStatus.ERROR,
                found_in_wild=found_in_wild,
                registry_source="MITRE",
            )
    
    def _parse_mitre_response(
        self,
        cve_id: str,
        data: dict,
        found_in_wild: bool,
    ) -> ValidationResult:
        """
        Parse MITRE CVE Services API response.
        
        Args:
            cve_id: CVE identifier
            data: MITRE API response data
            found_in_wild: Whether CVE was found in public sources
        
        Returns:
            ValidationResult parsed from MITRE data
        """
        # Check cveMetadata for state
        metadata = data.get("cveMetadata", {})
        state = metadata.get("state", "").upper()
        
        # Parse dates
        published_date = None
        date_published = metadata.get("datePublished")
        if date_published:
            try:
                published_date = datetime.fromisoformat(
                    date_published.replace("Z", "+00:00")
                )
            except ValueError:
                pass
        
        last_modified = None
        date_updated = metadata.get("dateUpdated")
        if date_updated:
            try:
                last_modified = datetime.fromisoformat(
                    date_updated.replace("Z", "+00:00")
                )
            except ValueError:
                pass
        
        # Extract description from containers
        description = None
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        descriptions = cna.get("descriptions", [])
        
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        
        # Determine status
        if state == "RESERVED":
            status = CVEStatus.RESERVED
        elif state == "REJECTED":
            status = CVEStatus.REJECTED
        elif state == "PUBLISHED":
            status = CVEStatus.PUBLISHED
        else:
            status = CVEStatus.NOT_FOUND
        
        return self._create_result(
            cve_id=cve_id,
            status=status,
            found_in_wild=found_in_wild,
            registry_source="MITRE",
            description=description,
            published_date=published_date,
            last_modified=last_modified,
            raw_response=data,
        )
    
    def _create_result(
        self,
        cve_id: str,
        status: CVEStatus,
        found_in_wild: bool,
        registry_source: str,
        description: str | None = None,
        published_date: datetime | None = None,
        last_modified: datetime | None = None,
        raw_response: dict | None = None,
    ) -> ValidationResult:
        """
        Create a ValidationResult with Ghost classification.
        
        A CVE is classified as a Ghost if:
        1. It was found in public sources (found_in_wild=True)
        2. Its status is RESERVED or NOT_FOUND
        
        Args:
            cve_id: CVE identifier
            status: Determined CVE status
            found_in_wild: Whether CVE was found in public sources
            registry_source: Which registry provided the status
            description: CVE description if available
            published_date: Publication date if available
            last_modified: Last modification date if available
            raw_response: Raw API response
        
        Returns:
            ValidationResult with is_ghost classification
        """
        # Determine if this is a Ghost CVE
        is_ghost = (
            found_in_wild and
            status in (CVEStatus.RESERVED, CVEStatus.NOT_FOUND)
        )
        
        if is_ghost:
            self.logger.warning(f"Ghost CVE detected: {cve_id} (status: {status.value})")
        
        return ValidationResult(
            cve_id=cve_id,
            status=status,
            is_ghost=is_ghost,
            registry_source=registry_source,
            description=description,
            published_date=published_date,
            last_modified=last_modified,
            raw_response=raw_response,
        )
    
    def _get_cached(self, cve_id: str) -> ValidationResult | None:
        """
        Get cached validation result if not expired.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Cached ValidationResult or None if not cached/expired
        """
        if cve_id not in self._cache:
            return None
        
        result = self._cache[cve_id]
        age = (datetime.utcnow() - result.validated_at).total_seconds()
        
        if age > self._cache_ttl_seconds:
            del self._cache[cve_id]
            return None
        
        return result
    
    def clear_cache(self) -> None:
        """Clear the validation cache."""
        self._cache.clear()
        self.logger.debug("Validation cache cleared")
    
    def is_ghost(self, cve_id: str) -> bool:
        """
        Quick check if a CVE is a Ghost.
        
        Args:
            cve_id: CVE identifier to check
        
        Returns:
            True if CVE is classified as a Ghost
        """
        result = self.validate(cve_id, found_in_wild=True)
        return result.is_ghost
