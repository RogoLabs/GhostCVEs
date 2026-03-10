"""
Base Vendor Scraper Module
===========================

Abstract base class for vendor security page scrapers.
Provides common functionality for HTTP fetching, CVE extraction,
and HTML parsing with rate limiting.

Author: rogolabs.net
"""

import logging
import re
import time
from abc import abstractmethod
from typing import Iterator
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

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


class BaseVendorScraper(BaseDiscovery):
    """
    Abstract base class for vendor security page scrapers.

    Provides common scraping functionality including HTTP fetching,
    CVE pattern extraction, HTML parsing, and rate limiting.
    Vendor-specific scrapers inherit from this class and implement
    the discover() method with their custom scraping logic.

    Attributes:
        base_url: Base URL of the vendor's security advisory page
        confidence: Confidence score for this vendor source (0.85-0.95)
        session: Requests session for HTTP calls
        rate_limiter: Rate limiter for HTTP requests
    """

    # CVE pattern: CVE-YYYY-NNNNN (case-insensitive)
    CVE_PATTERN = re.compile(
        r'\b(CVE-\d{4}-\d{4,})\b',
        re.IGNORECASE
    )

    def __init__(
        self,
        name: str,
        base_url: str,
        confidence: float,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the vendor scraper.

        Args:
            name: Human-readable name of the vendor
            base_url: Base URL of the vendor's security advisory page
            confidence: Confidence score (0.85-0.95 for vendor sources)
            enabled: Whether this scraper is active
        """
        super().__init__(
            name=name,
            source_type=SourceType.VENDOR_ADVISORY,
            enabled=enabled,
        )

        self.base_url = base_url
        self.confidence = confidence
        self.session = self._create_session()
        self.rate_limiter = RateLimiter(
            requests_per_window=10,  # Conservative rate limit
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
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "User-Agent": APP_SETTINGS.user_agent,
        })

        return session

    def _wait_for_rate_limit(self) -> None:
        """Wait if necessary to respect rate limits."""
        wait_time = self.rate_limiter.acquire()
        if wait_time > 0:
            self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)

    def _fetch_page(self, url: str) -> BeautifulSoup:
        """
        Fetch a web page and return parsed HTML.

        Args:
            url: URL to fetch

        Returns:
            BeautifulSoup object with parsed HTML

        Raises:
            DiscoveryError: If the request fails
        """
        self._wait_for_rate_limit()

        try:
            response = self.session.get(
                url,
                timeout=30,
                allow_redirects=True,
            )
            response.raise_for_status()

            return BeautifulSoup(response.text, 'html.parser')

        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch page {url}: {e}")
            raise DiscoveryError(
                self.name,
                f"Failed to fetch page: {e}",
                e
            )

    def _extract_cves(self, text: str) -> list[str]:
        """
        Extract CVE IDs from text using regex pattern.

        Args:
            text: Text to search for CVE IDs

        Returns:
            List of unique CVE IDs (normalized to uppercase)
        """
        matches = self.CVE_PATTERN.findall(text)

        # Normalize to uppercase and deduplicate
        cves = list(dict.fromkeys([cve.upper() for cve in matches]))

        return cves

    @abstractmethod
    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Execute the vendor-specific discovery process.

        This method must be implemented by subclasses to perform
        vendor-specific scraping logic.

        Yields:
            DiscoveryResult objects for each CVE mention found

        Raises:
            DiscoveryError: If the discovery process fails
        """
        pass

    def __repr__(self) -> str:
        """String representation of the vendor scraper."""
        return (
            f"{self.__class__.__name__}("
            f"name='{self.name}', "
            f"base_url='{self.base_url}', "
            f"confidence={self.confidence}, "
            f"enabled={self.enabled})"
        )
