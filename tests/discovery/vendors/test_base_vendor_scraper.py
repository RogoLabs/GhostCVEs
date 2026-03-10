"""
Tests for Base Vendor Scraper Module
=====================================

Unit tests for the BaseVendorScraper abstract class that provides
common scraping functionality for vendor security pages.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from bs4 import BeautifulSoup
import requests

from src.discovery.vendors.base import BaseVendorScraper
from src.discovery.base import DiscoveryResult, DiscoveryError
from src.config import SourceType


class ConcreteVendorScraper(BaseVendorScraper):
    """Concrete implementation of BaseVendorScraper for testing."""

    def discover(self):
        """Simple implementation for testing."""
        html = self._fetch_page(self.base_url)
        cves = self._extract_cves(html.get_text())

        for cve_id in cves:
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=self.source_type,
                source_name=self.name,
                evidence_url=self.base_url,
                confidence=self.confidence,
                context="Test context",
            )


class TestBaseVendorScraper:
    """Tests for BaseVendorScraper class."""

    def test_initialization(self):
        """Test BaseVendorScraper initialization."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        assert scraper.name == "Test Vendor"
        assert scraper.source_type == SourceType.VENDOR_ADVISORY
        assert scraper.base_url == "https://example.com/security"
        assert scraper.confidence == 0.90
        assert scraper.enabled is True

    def test_initialization_disabled(self):
        """Test initialization with disabled flag."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
            enabled=False,
        )
        assert scraper.enabled is False

    def test_extract_cves_single(self):
        """Test extracting a single CVE from text."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        text = "This advisory addresses CVE-2025-12345 in our product."
        cves = scraper._extract_cves(text)

        assert len(cves) == 1
        assert cves[0] == "CVE-2025-12345"

    def test_extract_cves_multiple(self):
        """Test extracting multiple CVEs from text."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        text = """
        Security Advisory: CVE-2025-12345, CVE-2024-99999
        Additional issue: CVE-2025-11111
        """
        cves = scraper._extract_cves(text)

        assert len(cves) == 3
        assert "CVE-2025-12345" in cves
        assert "CVE-2024-99999" in cves
        assert "CVE-2025-11111" in cves

    def test_extract_cves_deduplication(self):
        """Test that duplicate CVEs are removed."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        text = """
        CVE-2025-12345 is critical.
        We repeat: CVE-2025-12345 must be patched.
        """
        cves = scraper._extract_cves(text)

        assert len(cves) == 1
        assert cves[0] == "CVE-2025-12345"

    def test_extract_cves_case_insensitive(self):
        """Test that CVE extraction is case-insensitive."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        text = "Issues: cve-2025-12345, CVE-2025-99999, Cve-2024-11111"
        cves = scraper._extract_cves(text)

        assert len(cves) == 3
        # All should be normalized to uppercase
        assert all(cve.startswith("CVE-") for cve in cves)

    def test_extract_cves_no_matches(self):
        """Test extracting CVEs from text with no matches."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        text = "This is just some regular text with no CVE mentions."
        cves = scraper._extract_cves(text)

        assert len(cves) == 0

    @patch('requests.Session.get')
    def test_fetch_page_success(self, mock_get):
        """Test successful page fetching."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>CVE-2025-12345</body></html>"
        mock_get.return_value = mock_response

        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        soup = scraper._fetch_page("https://example.com/security")

        assert isinstance(soup, BeautifulSoup)
        assert "CVE-2025-12345" in soup.get_text()
        mock_get.assert_called_once()

    @patch('requests.Session.get')
    def test_fetch_page_http_error(self, mock_get):
        """Test fetch_page handles HTTP errors."""
        mock_get.side_effect = requests.HTTPError("404 Not Found")

        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        with pytest.raises(DiscoveryError) as exc_info:
            scraper._fetch_page("https://example.com/security")

        assert "Failed to fetch page" in str(exc_info.value)

    @patch('requests.Session.get')
    def test_fetch_page_timeout(self, mock_get):
        """Test fetch_page handles timeout errors."""
        mock_get.side_effect = requests.Timeout("Request timed out")

        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        with pytest.raises(DiscoveryError) as exc_info:
            scraper._fetch_page("https://example.com/security")

        assert "Failed to fetch page" in str(exc_info.value)

    @patch('requests.Session.get')
    def test_rate_limiting(self, mock_get):
        """Test that rate limiting is applied."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_get.return_value = mock_response

        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        # Make multiple requests quickly
        with patch.object(scraper.rate_limiter, 'acquire', return_value=0.0) as mock_acquire:
            scraper._fetch_page("https://example.com/security")
            scraper._fetch_page("https://example.com/security")

            # Rate limiter should be called
            assert mock_acquire.call_count == 2

    @patch('requests.Session.get')
    def test_discover_integration(self, mock_get):
        """Test full discover flow with mocked HTTP."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <body>
            <h1>Security Advisories</h1>
            <p>CVE-2025-12345: Critical vulnerability</p>
            <p>CVE-2025-67890: High severity issue</p>
        </body>
        </html>
        """
        mock_get.return_value = mock_response

        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        results = list(scraper.discover())

        assert len(results) == 2
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-12345" in cve_ids
        assert "CVE-2025-67890" in cve_ids

        for result in results:
            assert result.source_type == SourceType.VENDOR_ADVISORY
            assert result.source_name == "Test Vendor"
            assert result.confidence == 0.90

    def test_session_configuration(self):
        """Test that session is properly configured with headers."""
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )

        assert hasattr(scraper, 'session')
        assert 'User-Agent' in scraper.session.headers
        assert 'Accept' in scraper.session.headers

    def test_confidence_score_range(self):
        """Test that confidence scores are in valid range."""
        # Test valid confidence
        scraper = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.90,
        )
        assert 0.0 <= scraper.confidence <= 1.0

        # Test boundary values
        scraper_low = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.85,
        )
        assert scraper_low.confidence == 0.85

        scraper_high = ConcreteVendorScraper(
            name="Test Vendor",
            base_url="https://example.com/security",
            confidence=0.95,
        )
        assert scraper_high.confidence == 0.95
