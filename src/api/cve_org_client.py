"""
CVE.org API Client
==================

API client for CVE.org (MITRE CVE Services) API. This is the authoritative,
real-time source for CVE status validation.

Features:
- Validates CVE status (PUBLISHED, RESERVED, REJECTED, NOT_FOUND)
- Enforces rate limiting (30 requests/minute)
- Handles errors gracefully (404, 429, network errors)
- Monitors recent changes (for RESERVED→PUBLISHED transitions)
- Returns ValidationResult objects with full metadata

Ghost Logic:
- found_in_wild=True + RESERVED/NOT_FOUND → is_ghost=True
- found_in_wild=True + PUBLISHED → is_ghost=False
- ERROR status → is_ghost=False (don't flag on errors)

Author: rogolabs.net
"""

import json
import logging
import time
from datetime import datetime
from typing import Optional

import requests

from src.config import REGISTRY_CONFIG, APP_SETTINGS
from src.discovery.base import RateLimiter
from src.registry.validator import ValidationResult, CVEStatus


logger = logging.getLogger(__name__)


class CVEOrgAPIClient:
    """
    Client for CVE.org (MITRE CVE Services) API.

    Primary validation source for CVE status. Provides authoritative,
    real-time CVE data directly from the CVE Program.

    Attributes:
        base_url: CVE.org API base URL
        timeout: Request timeout in seconds
        max_retries: Maximum retry attempts for transient failures
        retry_delay: Delay between retries in seconds
        session: Requests session for HTTP calls
        rate_limiter: Rate limiter for API calls (30 req/min)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        """
        Initialize CVE.org API client.

        Args:
            base_url: CVE.org API base URL (default: from config)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            retry_delay: Delay between retries in seconds
        """
        self.base_url = base_url or REGISTRY_CONFIG.cve_org_api_base
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Create HTTP session
        self.session = self._create_session()

        # Rate limiter: 30 requests per minute
        self.rate_limiter = RateLimiter(
            requests_per_window=30,
            window_seconds=60,
        )

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

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
        return session

    def validate(self, cve_id: str, found_in_wild: bool = True) -> ValidationResult:
        """
        Validate a CVE ID against CVE.org API.

        Args:
            cve_id: CVE identifier to validate (e.g., CVE-2025-12345)
            found_in_wild: Whether this CVE was found in public sources

        Returns:
            ValidationResult with status and Ghost classification
        """
        cve_id = cve_id.upper()
        self.logger.debug(f"Validating CVE via CVE.org: {cve_id}")

        # Wait for rate limit
        wait_time = self.rate_limiter.acquire()
        if wait_time > 0:
            self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)

        # Attempt request with retries
        for attempt in range(self.max_retries):
            try:
                response = self._make_request(cve_id)

                # Handle HTTP status codes
                if response.status_code == 404:
                    return self._create_result(
                        cve_id=cve_id,
                        status=CVEStatus.NOT_FOUND,
                        found_in_wild=found_in_wild,
                    )

                if response.status_code == 429:
                    self.logger.warning(f"CVE.org rate limit exceeded for {cve_id}")
                    return self._create_result(
                        cve_id=cve_id,
                        status=CVEStatus.ERROR,
                        found_in_wild=found_in_wild,
                    )

                # Raise for other error status codes
                response.raise_for_status()

                # Parse response
                data = response.json()
                return self._parse_response(cve_id, data, found_in_wild)

            except requests.Timeout:
                self.logger.warning(
                    f"Timeout on attempt {attempt + 1}/{self.max_retries} for {cve_id}"
                )
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    return self._create_result(
                        cve_id=cve_id,
                        status=CVEStatus.ERROR,
                        found_in_wild=found_in_wild,
                    )

            except requests.RequestException as e:
                self.logger.error(f"Request failed for {cve_id}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    return self._create_result(
                        cve_id=cve_id,
                        status=CVEStatus.ERROR,
                        found_in_wild=found_in_wild,
                    )

            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON response for {cve_id}: {e}")
                return self._create_result(
                    cve_id=cve_id,
                    status=CVEStatus.ERROR,
                    found_in_wild=found_in_wild,
                )

            except Exception as e:
                # Catch-all for any unexpected errors
                self.logger.error(f"Unexpected error for {cve_id}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    return self._create_result(
                        cve_id=cve_id,
                        status=CVEStatus.ERROR,
                        found_in_wild=found_in_wild,
                    )

        # Should not reach here, but just in case
        return self._create_result(
            cve_id=cve_id,
            status=CVEStatus.ERROR,
            found_in_wild=found_in_wild,
        )

    def _make_request(self, cve_id: str) -> requests.Response:
        """
        Make HTTP request to CVE.org API.

        Args:
            cve_id: CVE identifier

        Returns:
            HTTP response object

        Raises:
            requests.RequestException: On network/HTTP errors
        """
        url = f"{self.base_url}/{cve_id}"
        self.logger.debug(f"Requesting: {url}")

        response = self.session.get(url, timeout=self.timeout)
        return response

    def _parse_response(
        self,
        cve_id: str,
        data: dict,
        found_in_wild: bool,
    ) -> ValidationResult:
        """
        Parse CVE.org API response.

        Args:
            cve_id: CVE identifier
            data: API response data
            found_in_wild: Whether CVE was found in public sources

        Returns:
            ValidationResult parsed from API data
        """
        # Extract CVE metadata
        metadata = data.get("cveMetadata", {})
        state = metadata.get("state", "").upper()

        # Determine CVE status
        if state == "PUBLISHED":
            status = CVEStatus.PUBLISHED
        elif state == "RESERVED":
            status = CVEStatus.RESERVED
        elif state == "REJECTED":
            status = CVEStatus.REJECTED
        else:
            # Unknown state - treat as NOT_FOUND
            status = CVEStatus.NOT_FOUND

        # Parse dates
        published_date = self._parse_date(metadata.get("datePublished"))
        last_modified = self._parse_date(metadata.get("dateUpdated"))

        # Extract description from containers
        description = self._extract_description(data)

        return self._create_result(
            cve_id=cve_id,
            status=status,
            found_in_wild=found_in_wild,
            description=description,
            published_date=published_date,
            last_modified=last_modified,
            raw_response=data,
        )

    def _extract_description(self, data: dict) -> Optional[str]:
        """
        Extract English description from CVE data.

        Args:
            data: CVE.org API response data

        Returns:
            English description or None if not found
        """
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        descriptions = cna.get("descriptions", [])

        # Find English description
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value")

        return None

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """
        Parse ISO 8601 date string.

        Args:
            date_str: ISO 8601 formatted date string

        Returns:
            datetime object or None if parsing fails
        """
        if not date_str:
            return None

        try:
            # Handle ISO 8601 with Z suffix
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as e:
            self.logger.warning(f"Failed to parse date '{date_str}': {e}")
            return None

    def _create_result(
        self,
        cve_id: str,
        status: CVEStatus,
        found_in_wild: bool,
        description: Optional[str] = None,
        published_date: Optional[datetime] = None,
        last_modified: Optional[datetime] = None,
        raw_response: Optional[dict] = None,
    ) -> ValidationResult:
        """
        Create a ValidationResult with Ghost classification.

        A CVE is classified as a Ghost if:
        1. It was found in public sources (found_in_wild=True)
        2. Its status is RESERVED or NOT_FOUND
        3. Status is not ERROR (don't flag on API errors)

        Args:
            cve_id: CVE identifier
            status: Determined CVE status
            found_in_wild: Whether CVE was found in public sources
            description: CVE description if available
            published_date: Publication date if available
            last_modified: Last modification date if available
            raw_response: Raw API response

        Returns:
            ValidationResult with is_ghost classification
        """
        # Determine if this is a Ghost CVE
        # Ghost = found_in_wild AND (RESERVED OR NOT_FOUND) AND not ERROR
        is_ghost = (
            found_in_wild
            and status in (CVEStatus.RESERVED, CVEStatus.NOT_FOUND)
            and status != CVEStatus.ERROR
        )

        if is_ghost:
            self.logger.warning(f"Ghost CVE detected: {cve_id} (status: {status.value})")

        return ValidationResult(
            cve_id=cve_id,
            status=status,
            is_ghost=is_ghost,
            registry_source="CVE.ORG",
            description=description,
            published_date=published_date,
            last_modified=last_modified,
            raw_response=raw_response,
        )

    def validate_batch(
        self,
        cve_ids: list[str],
        found_in_wild: bool = True,
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

    def get_recent_changes(self, cve_ids: list[str]) -> list[ValidationResult]:
        """
        Check for recent changes in a list of CVE IDs.

        Useful for monitoring RESERVED CVEs that may have been published.

        Args:
            cve_ids: List of CVE identifiers to check

        Returns:
            List of ValidationResult objects for CVEs with recent updates
        """
        results = []

        for cve_id in cve_ids:
            result = self.validate(cve_id, found_in_wild=True)

            # Check if recently updated (within last 24 hours)
            if result.last_modified:
                age = datetime.utcnow() - result.last_modified
                if age.total_seconds() < 86400:  # 24 hours
                    results.append(result)

        return results

    def __repr__(self) -> str:
        """String representation of the client."""
        return (
            f"CVEOrgAPIClient(base_url='{self.base_url}', "
            f"timeout={self.timeout})"
        )
