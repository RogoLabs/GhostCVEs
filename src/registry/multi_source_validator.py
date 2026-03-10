"""
Multi-Source Validator
======================

Orchestrates CVE validation across multiple sources with caching and graceful
fallback logic. Addresses Problem #3: "No multi-source validation."

Validation Priority (authoritative → fallback):
1. In-memory cache (1 hour TTL) - instant
2. CVE.org API (authoritative, real-time) - primary
3. Local CVElist V5 (fast, hours old) - first fallback
4. Local NVD JSON (comprehensive, days old) - final fallback

Fallback Logic:
- CVE.org PUBLISHED/RESERVED/REJECTED → return immediately (authoritative)
- CVE.org ERROR/timeout → fall back to local sources
- Local CVElist NOT_FOUND → fall back to NVD
- All sources fail → return NOT_FOUND with registry_source="NONE"

Cache Strategy:
- 1 hour TTL (reduces API calls, balances freshness)
- Keyed by CVE ID (case-insensitive)
- Stores ValidationResult objects
- Cleared on demand via clear_cache()

Author: rogolabs.net
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from src.api.cve_org_client import CVEOrgAPIClient
from src.registry.local_registry import LocalCVERegistry
from src.registry.nvd_local import NVDLocalRegistry
from src.registry.validator import ValidationResult, CVEStatus


logger = logging.getLogger(__name__)


class MultiSourceValidator:
    """
    Multi-source CVE validator with caching and fallback logic.

    Orchestrates validation across CVE.org API, local CVElist, and local NVD
    with intelligent fallback when primary sources are unavailable.

    Attributes:
        cve_org_client: CVE.org API client (primary source)
        local_registry: Local CVElist V5 registry (first fallback)
        nvd_local: Local NVD JSON registry (final fallback)
        cache_ttl_seconds: Cache time-to-live in seconds (default: 3600 = 1 hour)
    """

    def __init__(
        self,
        cve_org_client: Optional[CVEOrgAPIClient] = None,
        local_registry: Optional[LocalCVERegistry] = None,
        nvd_local: Optional[NVDLocalRegistry] = None,
        cache_ttl_seconds: int = 3600,
    ) -> None:
        """
        Initialize multi-source validator.

        Args:
            cve_org_client: CVE.org API client (created if None)
            local_registry: Local CVE registry (created if None)
            nvd_local: Local NVD registry (created if None)
            cache_ttl_seconds: Cache TTL in seconds (default: 3600 = 1 hour)
        """
        self.cve_org_client = cve_org_client or CVEOrgAPIClient()
        self.local_registry = local_registry or LocalCVERegistry()
        self.nvd_local = nvd_local or NVDLocalRegistry()

        self._cache: dict[str, ValidationResult] = {}
        self._cache_ttl_seconds = cache_ttl_seconds

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def validate(self, cve_id: str, found_in_wild: bool = True) -> ValidationResult:
        """
        Validate a CVE ID with multi-source fallback.

        Priority order:
        1. Check in-memory cache (1 hour TTL)
        2. Try CVE.org API (authoritative)
        3. Fall back to Local CVElist if CVE.org ERROR
        4. Fall back to Local NVD if CVElist NOT_FOUND
        5. Return NOT_FOUND if all sources fail

        Args:
            cve_id: CVE identifier to validate
            found_in_wild: Whether this CVE was found in public sources

        Returns:
            ValidationResult from first successful source
        """
        cve_id = cve_id.upper()
        self.logger.debug(f"Validating {cve_id} with multi-source fallback")

        # 1. Check cache first
        cached = self.get_cache(cve_id)
        if cached is not None:
            self.logger.debug(f"Cache hit for {cve_id}")
            return cached

        # 2. Try CVE.org API (primary source - authoritative)
        cve_org_result = self.cve_org_client.validate(cve_id, found_in_wild)

        # If CVE.org succeeded (not ERROR), use it and cache
        if cve_org_result.status != CVEStatus.ERROR:
            self.logger.debug(
                f"CVE.org returned {cve_org_result.status.value} for {cve_id}"
            )
            self.set_cache(cve_id, cve_org_result)
            return cve_org_result

        # 3. CVE.org failed, fall back to local sources
        self.logger.warning(f"CVE.org returned ERROR for {cve_id}, trying local sources")

        # Try Local CVElist V5
        if self.local_registry.is_available():
            local_result = self._try_local_registry(cve_id, found_in_wild)
            if local_result is not None and local_result.status != CVEStatus.NOT_FOUND:
                self.set_cache(cve_id, local_result)
                return local_result

        # 4. Try Local NVD (final fallback)
        if self.nvd_local.is_available():
            nvd_result = self._try_nvd_local(cve_id, found_in_wild)
            if nvd_result.status != CVEStatus.NOT_FOUND:
                self.set_cache(cve_id, nvd_result)
                return nvd_result

        # 5. All sources failed - return NOT_FOUND with source=NONE
        not_found_result = self._create_result(
            cve_id=cve_id,
            status=CVEStatus.NOT_FOUND,
            found_in_wild=found_in_wild,
            registry_source="NONE",
        )
        self.set_cache(cve_id, not_found_result)
        return not_found_result

    def _try_local_registry(
        self, cve_id: str, found_in_wild: bool
    ) -> Optional[ValidationResult]:
        """
        Try validating against local CVElist V5 registry.

        Args:
            cve_id: CVE identifier
            found_in_wild: Whether CVE was found in public sources

        Returns:
            ValidationResult or None if not available
        """
        try:
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

            if status == CVEStatus.NOT_FOUND:
                return None

            self.logger.debug(f"Local CVElist returned {status.value} for {cve_id}")

            return self._create_result(
                cve_id=cve_id,
                status=status,
                found_in_wild=found_in_wild,
                registry_source="LOCAL",
                description=description,
                published_date=published_date,
            )

        except Exception as e:
            self.logger.error(f"Error querying local registry for {cve_id}: {e}")
            return None

    def _try_nvd_local(self, cve_id: str, found_in_wild: bool) -> ValidationResult:
        """
        Try validating against local NVD JSON registry.

        Args:
            cve_id: CVE identifier
            found_in_wild: Whether CVE was found in public sources

        Returns:
            ValidationResult (always returns, may be NOT_FOUND)
        """
        try:
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

            self.logger.debug(f"Local NVD returned {status.value} for {cve_id}")

            return self._create_result(
                cve_id=cve_id,
                status=status,
                found_in_wild=found_in_wild,
                registry_source="NVD_LOCAL",
                description=description,
                published_date=published_date,
            )

        except Exception as e:
            self.logger.error(f"Error querying NVD local for {cve_id}: {e}")
            return self._create_result(
                cve_id=cve_id,
                status=CVEStatus.NOT_FOUND,
                found_in_wild=found_in_wild,
                registry_source="NVD_LOCAL",
            )

    def _create_result(
        self,
        cve_id: str,
        status: CVEStatus,
        found_in_wild: bool,
        registry_source: str,
        description: Optional[str] = None,
        published_date: Optional[datetime] = None,
    ) -> ValidationResult:
        """
        Create a ValidationResult with Ghost classification.

        A CVE is classified as a Ghost if:
        1. It was found in public sources (found_in_wild=True)
        2. Its status is RESERVED or NOT_FOUND
        3. Status is not ERROR

        Args:
            cve_id: CVE identifier
            status: Determined CVE status
            found_in_wild: Whether CVE was found in public sources
            registry_source: Which registry provided the status
            description: CVE description if available
            published_date: Publication date if available

        Returns:
            ValidationResult with is_ghost classification
        """
        # Determine if this is a Ghost CVE
        is_ghost = (
            found_in_wild
            and status in (CVEStatus.RESERVED, CVEStatus.NOT_FOUND)
            and status != CVEStatus.ERROR
        )

        if is_ghost:
            self.logger.warning(
                f"Ghost CVE detected: {cve_id} (status: {status.value}, source: {registry_source})"
            )

        return ValidationResult(
            cve_id=cve_id,
            status=status,
            is_ghost=is_ghost,
            registry_source=registry_source,
            description=description,
            published_date=published_date,
        )

    def validate_batch(
        self, cve_ids: list[str], found_in_wild: bool = True
    ) -> list[ValidationResult]:
        """
        Validate multiple CVE IDs in batch.

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

        self.logger.info(
            f"Batch validation complete: {len(results)} CVEs processed"
        )

        return results

    def get_cache(self, cve_id: str) -> Optional[ValidationResult]:
        """
        Get cached validation result if not expired.

        Args:
            cve_id: CVE identifier

        Returns:
            Cached ValidationResult or None if not cached/expired
        """
        cve_id = cve_id.upper()

        if cve_id not in self._cache:
            return None

        result = self._cache[cve_id]

        # Check if expired
        if result.validated_at is None:
            return None

        age = datetime.utcnow() - result.validated_at
        if age.total_seconds() > self._cache_ttl_seconds:
            # Expired - remove from cache
            del self._cache[cve_id]
            return None

        return result

    def set_cache(self, cve_id: str, result: ValidationResult) -> None:
        """
        Store validation result in cache.

        Args:
            cve_id: CVE identifier
            result: ValidationResult to cache
        """
        cve_id = cve_id.upper()
        self._cache[cve_id] = result

    def clear_cache(self) -> None:
        """Clear the entire validation cache."""
        self._cache.clear()
        self.logger.debug("Validation cache cleared")

    def __repr__(self) -> str:
        """String representation of the validator."""
        return (
            f"MultiSourceValidator(cache_size={len(self._cache)}, "
            f"ttl={self._cache_ttl_seconds}s)"
        )
