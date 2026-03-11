"""
CVE.org Recent Changes Monitor Discovery Module
================================================

Discovers CVE mentions in CVE.org by monitoring recently published/updated CVEs.
Queries the CVE.org API for CVEs modified in the last 24 hours (or configurable
window) and focuses on PUBLISHED state CVEs.

This module provides perfect confidence (1.0) as CVE.org is the authoritative
registry maintained by MITRE.

Author: rogolabs.net
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Iterator
from urllib.parse import urlencode

import requests

from src.config import (
    APP_SETTINGS,
    REGISTRY_CONFIG,
    SourceType,
)
from src.discovery.base import (
    BaseDiscovery,
    DiscoveryResult,
    DiscoveryError,
    RateLimiter,
)


logger = logging.getLogger(__name__)


class CVEOrgMonitor(BaseDiscovery):
    """
    Discovery module for finding CVEs in CVE.org recent changes.

    Queries the CVE.org API to find CVE mentions in recently published/updated
    CVEs. Filters for PUBLISHED state and extracts CVE IDs with full metadata.

    Attributes:
        lookback_days: Number of days to look back for updated CVEs
        session: Requests session for HTTP calls
        rate_limiter: Rate limiter for API requests
    """

    API_BASE_URL = "https://cveawg.mitre.org/api/cve"
    CVE_ORG_URL = "https://www.cve.mitre.org/cgi-bin/cvename.cgi"
    DEFAULT_LOOKBACK_DAYS = 1
    MAX_PER_REQUEST = 500

    def __init__(
        self,
        enabled: bool = True,
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    ) -> None:
        """
        Initialize the CVE.org Recent Changes Monitor.

        Args:
            enabled: Whether this discovery module is active
            lookback_days: Number of days to look back for updated CVEs
        """
        super().__init__(
            name="CVE.org Recent Changes Monitor",
            source_type=SourceType.CVE_ORG,
            enabled=enabled,
        )

        self.lookback_days = lookback_days
        self.session = self._create_session()
        self.rate_limiter = RateLimiter(
            requests_per_window=30,  # CVE.org API rate limit
            window_seconds=60,
        )

    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests session.

        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": APP_SETTINGS.user_agent,
        })

        return session

    def _wait_for_rate_limit(self) -> None:
        """Wait if necessary to respect rate limits."""
        wait_time = self.rate_limiter.acquire()
        if wait_time > 0:
            self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)

    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Execute CVE.org discovery and yield results.

        Queries the CVE.org API for CVEs updated in the last N days and
        extracts CVE mentions from PUBLISHED entries.

        Yields:
            DiscoveryResult for each CVE found

        Raises:
            DiscoveryError: If the API query fails
        """
        try:
            cve_records = self._fetch_recent_cves()

            if not cve_records:
                return

            for record in cve_records:
                yield from self._process_cve_record(record)

        except Exception as e:
            self.logger.error(f"CVE.org discovery failed: {e}", exc_info=True)
            raise DiscoveryError(self.name, f"API query failed: {e}", e)

    def _fetch_recent_cves(self) -> list[dict]:
        """
        Fetch recently published/updated CVEs from CVE.org API.

        Returns:
            List of CVE records from the API
        """
        self._wait_for_rate_limit()

        # Calculate the date range
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=self.lookback_days)).isoformat()

        # Build query parameters
        # The CVE.org API can be queried for recently modified CVEs
        # We'll query for all CVEs and filter by date on our side
        params = {
            "changeStartDate": cutoff_date,
            "limit": self.MAX_PER_REQUEST,
        }

        url = f"{self.API_BASE_URL}?{urlencode(params)}"

        try:
            response = self.session.get(
                url,
                timeout=REGISTRY_CONFIG.timeout_seconds,
            )
            response.raise_for_status()

            data = response.json()
            cve_records = data.get("cveRecords", [])

            self.logger.debug(
                f"Fetched {len(cve_records)} CVE records from CVE.org"
            )
            return cve_records

        except requests.RequestException as e:
            self.logger.error(f"CVE.org API request failed: {e}")
            raise DiscoveryError(self.name, f"API request failed: {e}", e)

    def _process_cve_record(self, record: dict) -> Iterator[DiscoveryResult]:
        """
        Process a single CVE record and yield DiscoveryResult.

        Args:
            record: CVE record from CVE.org API

        Yields:
            DiscoveryResult for the CVE if it's in PUBLISHED state
        """
        cve_id = record.get("cveId", "")
        metadata = record.get("cveMetadata", {})
        state = metadata.get("state", "").upper()

        # Only process PUBLISHED CVEs
        if state != "PUBLISHED":
            self.logger.debug(f"Skipping {cve_id} with state {state}")
            return

        # Skip if no CVE ID
        if not cve_id:
            return

        # Parse timestamps
        date_updated = metadata.get("dateUpdated")
        date_published = metadata.get("datePublished")

        discovered_at = self._parse_datetime(date_updated or date_published)

        # Extract description
        description = self._extract_description(record)

        # Create context with description
        context = description if description else f"Published in CVE.org"

        # Create evidence URL pointing to CVE.org
        evidence_url = f"{self.CVE_ORG_URL}?name={cve_id}"

        # Prepare raw_data with important metadata
        raw_data = {
            "state": state,
            "datePublished": date_published,
            "dateUpdated": date_updated,
            "assignerOrgId": metadata.get("assignerOrgId"),
            "description": description,
        }

        yield DiscoveryResult(
            cve_id=cve_id,
            source_type=self.source_type,
            source_name=self.name,
            evidence_url=evidence_url,
            discovered_at=discovered_at,
            context=context,
            confidence=1.0,  # Perfect confidence - CVE.org is authoritative
            raw_data=raw_data,
        )

    def _extract_description(self, record: dict) -> str | None:
        """
        Extract description from CVE record.

        Args:
            record: CVE record from CVE.org API

        Returns:
            Description string or None if not available
        """
        containers = record.get("containers", {})
        cna = containers.get("cna", {})
        descriptions = cna.get("descriptions", [])

        if not descriptions:
            return None

        # Get the first English description
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")[:500]

        # Fall back to first description regardless of language
        if descriptions:
            return descriptions[0].get("value", "")[:500]

        return None

    def _parse_datetime(self, date_str: str | None) -> datetime:
        """
        Parse ISO 8601 datetime string.

        Args:
            date_str: ISO 8601 formatted datetime string

        Returns:
            datetime object or current UTC time if parsing fails
        """
        if not date_str:
            return datetime.now(timezone.utc)

        try:
            # Handle ISO format with Z suffix
            if date_str.endswith("Z"):
                return datetime.fromisoformat(date_str[:-1])
            return datetime.fromisoformat(date_str)
        except (ValueError, AttributeError):
            self.logger.debug(f"Could not parse datetime: {date_str}")
            return datetime.now(timezone.utc)
