"""
GitHub Security Advisories Discovery Module
=============================================

Discovers CVE mentions in GitHub Security Advisories Database via GraphQL API.
Queries advisories updated in the last 30 days and extracts CVE IDs, severity,
affected packages, and other metadata.

Author: rogolabs.net
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Iterator

import requests

from src.config import (
    APP_SETTINGS,
    SourceType,
)
from src.discovery.base import (
    BaseDiscovery,
    DiscoveryResult,
    DiscoveryError,
    RateLimiter,
)


logger = logging.getLogger(__name__)


class GitHubAdvisoryDiscovery(BaseDiscovery):
    """
    Discovery module for finding CVEs in GitHub Security Advisories.

    Queries the GitHub Security Advisories Database via GraphQL API
    to find CVE mentions in recently updated advisories. Extracts CVE IDs,
    severity levels, affected packages, and other metadata.

    Attributes:
        token: GitHub API token for authentication
        session: Requests session for HTTP calls
        rate_limiter: Rate limiter for API requests
    """

    GRAPHQL_ENDPOINT = "https://api.github.com/graphql"
    ADVISORY_BASE_URL = "https://github.com/advisories"
    DEFAULT_UPDATE_DAYS = 30

    def __init__(
        self,
        token: str | None = None,
        enabled: bool = True,
        update_days: int = DEFAULT_UPDATE_DAYS,
    ) -> None:
        """
        Initialize the GitHub Advisory discovery module.

        Args:
            token: GitHub API token. If not provided, attempts to read
                   from GITHUB_TOKEN environment variable.
            enabled: Whether this discovery module is active
            update_days: Number of days to look back for updated advisories

        Raises:
            DiscoveryError: If no token is available and API will be unusable
        """
        super().__init__(
            name="GitHub Security Advisories",
            source_type=SourceType.GITHUB_ADVISORY,
            enabled=enabled,
        )

        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.update_days = update_days

        if not self.token:
            self.logger.warning(
                "No GitHub token provided. GitHub advisory discovery will fail."
            )

        self.session = self._create_session()
        self.rate_limiter = RateLimiter(
            requests_per_window=10,  # GraphQL has different limits
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
            "Accept": "application/vnd.github.graphql-preview",
            "Content-Type": "application/json",
            "User-Agent": APP_SETTINGS.user_agent,
        })

        if self.token:
            session.headers["Authorization"] = f"Bearer {self.token}"

        return session

    def _wait_for_rate_limit(self) -> None:
        """Wait if necessary to respect rate limits."""
        wait_time = self.rate_limiter.acquire()
        if wait_time > 0:
            self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)

    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Execute GitHub advisory discovery and yield results.

        Queries the GitHub Security Advisories Database for advisories
        updated in the last N days and extracts CVE mentions.

        Yields:
            DiscoveryResult for each CVE found

        Raises:
            DiscoveryError: If the API query fails
        """
        try:
            response_data = self._query_graphql()

            if not response_data:
                return

            advisories = response_data.get("data", {}).get("securityAdvisories", {})
            edges = advisories.get("edges", [])

            for edge in edges:
                node = edge.get("node", {})
                yield from self._process_advisory(node)

        except Exception as e:
            self.logger.error(f"GitHub advisory discovery failed: {e}", exc_info=True)
            raise DiscoveryError(self.name, f"GraphQL query failed: {e}", e)

    def _query_graphql(self) -> dict:
        """
        Execute GraphQL query against GitHub API.

        Returns:
            Parsed JSON response from GraphQL query
        """
        self._wait_for_rate_limit()

        # Calculate the date range
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=self.update_days)).isoformat()

        query = """
        query GetSecurityAdvisories($first: Int = 100) {
            securityAdvisories(
                first: $first
                orderBy: {field: UPDATED_AT, direction: DESC}
            ) {
                edges {
                    node {
                        ghsaId
                        cveIds
                        summary
                        description
                        severity
                        publishedAt
                        updatedAt
                        vulnerabilities(first: 100) {
                            edges {
                                node {
                                    package {
                                        name
                                        ecosystem
                                    }
                                    vulnerableVersionRange
                                    firstPatchedVersion {
                                        identifier
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """

        payload = {
            "query": query,
            "variables": {"first": 100},
        }

        try:
            response = self.session.post(
                self.GRAPHQL_ENDPOINT,
                data=json.dumps(payload),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            self.logger.error(f"GraphQL API request failed: {e}")
            raise DiscoveryError(self.name, f"API request failed: {e}", e)

    def _process_advisory(self, advisory: dict) -> Iterator[DiscoveryResult]:
        """
        Process a single advisory and yield DiscoveryResult for each CVE.

        Args:
            advisory: Advisory node from GraphQL response

        Yields:
            DiscoveryResult for each CVE in the advisory
        """
        ghsa_id = advisory.get("ghsaId", "")
        cve_ids = advisory.get("cveIds", [])
        summary = advisory.get("summary", "")
        description = advisory.get("description", "")
        severity = advisory.get("severity", "UNKNOWN")
        published_at = advisory.get("publishedAt")
        updated_at = advisory.get("updatedAt")

        # Skip advisories without CVE IDs
        if not cve_ids:
            return

        # Extract affected packages
        affected_packages = self._extract_affected_packages(advisory)

        # Create context with package and severity info
        context = self._create_context(summary, severity, affected_packages)

        # Create evidence URL
        evidence_url = f"{self.ADVISORY_BASE_URL}/{ghsa_id}"

        # Parse publication date
        discovered_at = self._parse_datetime(updated_at or published_at)

        # Yield one result per CVE
        for cve_id in cve_ids:
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=self.source_type,
                source_name=self.name,
                evidence_url=evidence_url,
                discovered_at=discovered_at,
                context=context,
                confidence=0.90,  # High confidence - GitHub is authoritative
                raw_data={
                    "ghsa_id": ghsa_id,
                    "severity": severity,
                    "summary": summary,
                    "description": description[:500] if description else None,
                    "affected_packages": affected_packages,
                    "published_at": published_at,
                    "updated_at": updated_at,
                },
            )

    def _extract_affected_packages(self, advisory: dict) -> list[dict]:
        """
        Extract affected package information from advisory.

        Args:
            advisory: Advisory node from GraphQL response

        Returns:
            List of affected packages with ecosystem and version info
        """
        packages = []
        vulnerabilities = advisory.get("vulnerabilities", {})
        edges = vulnerabilities.get("edges", [])

        for edge in edges:
            node = edge.get("node", {})
            package_info = node.get("package", {})
            package_name = package_info.get("name", "")
            ecosystem = package_info.get("ecosystem", "")
            vulnerable_range = node.get("vulnerableVersionRange", "")
            patched_version = node.get("firstPatchedVersion", {})
            patched_id = patched_version.get("identifier") if patched_version else None

            packages.append({
                "name": package_name,
                "ecosystem": ecosystem,
                "vulnerable_range": vulnerable_range,
                "patched_version": patched_id,
            })

        return packages

    def _create_context(
        self,
        summary: str,
        severity: str,
        packages: list[dict],
    ) -> str:
        """
        Create a context string for the discovery result.

        Args:
            summary: Advisory summary
            severity: Severity level
            packages: List of affected packages

        Returns:
            Context string combining summary, severity, and packages
        """
        parts = [summary]

        if severity and severity != "UNKNOWN":
            parts.append(f"Severity: {severity}")

        if packages:
            package_names = [pkg["name"] for pkg in packages if pkg.get("name")]
            if package_names:
                parts.append(f"Affected packages: {', '.join(package_names)}")

        context = " | ".join(parts)
        return context[:500]  # Limit context length

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
