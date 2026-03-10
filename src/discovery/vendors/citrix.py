"""
Citrix Security Advisory Scraper
==================================

Scrapes CVE mentions from Citrix security advisory pages.
Citrix frequently discloses vulnerabilities in their ADC, Gateway,
and other products through their support portal.

Author: rogolabs.net
"""

import logging
from typing import Iterator

from src.discovery.vendors.base import BaseVendorScraper
from src.discovery.base import DiscoveryResult, DiscoveryError


logger = logging.getLogger(__name__)


class CitrixScraper(BaseVendorScraper):
    """
    Scraper for Citrix security advisories.

    Monitors https://support.citrix.com/security for CVE disclosures
    in Citrix products (ADC, Gateway, Virtual Apps, etc.).

    Confidence: 0.90 (high - vendor is authoritative for their products)
    """

    def __init__(self, enabled: bool = True) -> None:
        """
        Initialize the Citrix scraper.

        Args:
            enabled: Whether this scraper is active
        """
        super().__init__(
            name="Citrix",
            base_url="https://support.citrix.com/security",
            confidence=0.90,
            enabled=enabled,
        )

    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Discover CVEs from Citrix security advisories.

        Scrapes the Citrix support security page and extracts CVE IDs
        from security bulletins and advisories.

        Yields:
            DiscoveryResult for each CVE found

        Raises:
            DiscoveryError: If scraping fails
        """
        try:
            # Fetch the main security page
            soup = self._fetch_page(self.base_url)

            # Extract all text content for CVE pattern matching
            page_text = soup.get_text()

            # Extract CVE IDs
            cves = self._extract_cves(page_text)

            self.logger.info(f"Found {len(cves)} CVEs on Citrix security page")

            # Create results for each CVE
            for cve_id in cves:
                # Try to find context around the CVE mention
                context = self._extract_context(soup, cve_id)

                yield DiscoveryResult(
                    cve_id=cve_id,
                    source_type=self.source_type,
                    source_name=self.name,
                    evidence_url=self.base_url,
                    confidence=self.confidence,
                    context=context,
                )

        except DiscoveryError:
            # Re-raise discovery errors
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in Citrix discovery: {e}")
            raise DiscoveryError(
                self.name,
                f"Unexpected error during discovery: {e}",
                e
            )

    def _extract_context(self, soup, cve_id: str) -> str:
        """
        Extract context around a CVE mention.

        Args:
            soup: BeautifulSoup object
            cve_id: CVE identifier to find context for

        Returns:
            Context string or None
        """
        try:
            # Find elements containing the CVE ID
            for element in soup.find_all(string=lambda text: text and cve_id in text):
                # Get parent element text (usually a heading or paragraph)
                parent = element.find_parent()
                if parent:
                    text = parent.get_text(strip=True)
                    # Limit context length
                    return text[:300] if len(text) > 300 else text

            return None
        except Exception:
            return None
