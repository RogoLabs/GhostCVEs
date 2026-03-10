"""
VMware Security Advisory Scraper
=================================

Scrapes CVE mentions from VMware security advisories.
VMware (now part of Broadcom) frequently discloses vulnerabilities
in vCenter, ESXi, and other virtualization products.

Author: rogolabs.net
"""

import logging
from typing import Iterator

from src.discovery.vendors.base import BaseVendorScraper
from src.discovery.base import DiscoveryResult, DiscoveryError


logger = logging.getLogger(__name__)


class VMwareScraper(BaseVendorScraper):
    """
    Scraper for VMware security advisories.

    Monitors https://www.vmware.com/security/advisories for CVE
    disclosures in vCenter Server, ESXi, Workstation, and other
    VMware products.

    Confidence: 0.93 (very high - major vendor with well-structured
                      advisory page, critical infrastructure products)
    """

    def __init__(self, enabled: bool = True) -> None:
        """
        Initialize the VMware scraper.

        Args:
            enabled: Whether this scraper is active
        """
        super().__init__(
            name="VMware",
            base_url="https://www.vmware.com/security/advisories",
            confidence=0.93,
            enabled=enabled,
        )

    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Discover CVEs from VMware security advisories.

        Scrapes the VMware security advisories page and extracts CVE IDs
        from published VMSA (VMware Security Advisories).

        Yields:
            DiscoveryResult for each CVE found

        Raises:
            DiscoveryError: If scraping fails
        """
        try:
            # Fetch the security advisories page
            soup = self._fetch_page(self.base_url)

            # Extract all text content for CVE pattern matching
            page_text = soup.get_text()

            # Extract CVE IDs
            cves = self._extract_cves(page_text)

            self.logger.info(f"Found {len(cves)} CVEs on VMware security advisories")

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
            self.logger.error(f"Unexpected error in VMware discovery: {e}")
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
                # Get parent element text (usually advisory content)
                parent = element.find_parent()
                if parent:
                    text = parent.get_text(strip=True)
                    # Limit context length
                    return text[:300] if len(text) > 300 else text

            return None
        except Exception:
            return None
