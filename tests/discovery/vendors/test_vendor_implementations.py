"""
Tests for Vendor Scraper Implementations
=========================================

Unit tests for the specific vendor scraper implementations:
- CitrixScraper
- IvantiScraper
- PaloAltoScraper
- FortinetScraper
- VMwareScraper
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from bs4 import BeautifulSoup

from src.discovery.vendors.citrix import CitrixScraper
from src.discovery.vendors.ivanti import IvantiScraper
from src.discovery.vendors.palo_alto import PaloAltoScraper
from src.discovery.vendors.fortinet import FortinetScraper
from src.discovery.vendors.vmware import VMwareScraper
from src.discovery.base import DiscoveryResult, DiscoveryError
from src.config import SourceType


class TestCitrixScraper:
    """Tests for CitrixScraper."""

    def test_initialization(self):
        """Test CitrixScraper initialization."""
        scraper = CitrixScraper()

        assert scraper.name == "Citrix"
        assert scraper.source_type == SourceType.VENDOR_ADVISORY
        assert scraper.base_url == "https://support.citrix.com/security"
        assert scraper.confidence == 0.90
        assert scraper.enabled is True

    def test_initialization_disabled(self):
        """Test initialization with disabled flag."""
        scraper = CitrixScraper(enabled=False)
        assert scraper.enabled is False

    @patch('requests.Session.get')
    def test_discover_citrix_advisories(self, mock_get):
        """Test discovering CVEs from Citrix security page."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <body>
            <div class="advisory">
                <h2>Critical Security Update - CVE-2025-12345</h2>
                <p>Citrix ADC vulnerability affecting versions 13.0 and 13.1</p>
            </div>
            <div class="advisory">
                <h2>Security Bulletin - CVE-2025-23456</h2>
                <p>Authentication bypass in Citrix Gateway</p>
            </div>
        </body>
        </html>
        """
        mock_get.return_value = mock_response

        scraper = CitrixScraper()
        results = list(scraper.discover())

        assert len(results) == 2
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-12345" in cve_ids
        assert "CVE-2025-23456" in cve_ids

        for result in results:
            assert result.source_type == SourceType.VENDOR_ADVISORY
            assert result.source_name == "Citrix"
            assert result.confidence == 0.90
            assert result.evidence_url.startswith("https://support.citrix.com")

    @patch('requests.Session.get')
    def test_discover_no_advisories(self, mock_get):
        """Test when no CVEs are found."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body><p>No security advisories</p></body></html>"
        mock_get.return_value = mock_response

        scraper = CitrixScraper()
        results = list(scraper.discover())

        assert len(results) == 0


class TestIvantiScraper:
    """Tests for IvantiScraper."""

    def test_initialization(self):
        """Test IvantiScraper initialization."""
        scraper = IvantiScraper()

        assert scraper.name == "Ivanti"
        assert scraper.source_type == SourceType.VENDOR_ADVISORY
        assert scraper.base_url == "https://forums.ivanti.com/s/topic/0TO2J000000AP7XWAY/security-advisories"
        assert scraper.confidence == 0.88
        assert scraper.enabled is True

    @patch('requests.Session.get')
    def test_discover_ivanti_advisories(self, mock_get):
        """Test discovering CVEs from Ivanti forums."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <body>
            <div class="topic">
                <h3>Security Advisory: CVE-2025-11234 - Ivanti Connect Secure</h3>
                <p>Critical vulnerability in authentication</p>
            </div>
            <div class="topic">
                <h3>CVE-2025-22456: Policy Secure Update</h3>
                <p>Remote code execution vulnerability</p>
            </div>
        </body>
        </html>
        """
        mock_get.return_value = mock_response

        scraper = IvantiScraper()
        results = list(scraper.discover())

        assert len(results) == 2
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-11234" in cve_ids
        assert "CVE-2025-22456" in cve_ids

        for result in results:
            assert result.source_name == "Ivanti"
            assert result.confidence == 0.88


class TestPaloAltoScraper:
    """Tests for PaloAltoScraper."""

    def test_initialization(self):
        """Test PaloAltoScraper initialization."""
        scraper = PaloAltoScraper()

        assert scraper.name == "Palo Alto Networks"
        assert scraper.source_type == SourceType.VENDOR_ADVISORY
        assert scraper.base_url == "https://security.paloaltonetworks.com/"
        assert scraper.confidence == 0.92
        assert scraper.enabled is True

    @patch('requests.Session.get')
    def test_discover_palo_alto_advisories(self, mock_get):
        """Test discovering CVEs from Palo Alto security advisories."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <body>
            <div class="security-advisory">
                <h2>PAN-SA-2025-0001</h2>
                <p>PAN-OS: CVE-2025-33789 Command Injection Vulnerability</p>
                <span>Severity: CRITICAL</span>
            </div>
            <div class="security-advisory">
                <h2>PAN-SA-2025-0002</h2>
                <p>GlobalProtect: CVE-2025-44567 Authentication Bypass</p>
                <span>Severity: HIGH</span>
            </div>
        </body>
        </html>
        """
        mock_get.return_value = mock_response

        scraper = PaloAltoScraper()
        results = list(scraper.discover())

        assert len(results) == 2
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-33789" in cve_ids
        assert "CVE-2025-44567" in cve_ids

        for result in results:
            assert result.source_name == "Palo Alto Networks"
            assert result.confidence == 0.92


class TestFortinetScraper:
    """Tests for FortinetScraper."""

    def test_initialization(self):
        """Test FortinetScraper initialization."""
        scraper = FortinetScraper()

        assert scraper.name == "Fortinet"
        assert scraper.source_type == SourceType.VENDOR_ADVISORY
        assert scraper.base_url == "https://www.fortiguard.com/psirt"
        assert scraper.confidence == 0.90
        assert scraper.enabled is True

    @patch('requests.Session.get')
    def test_discover_fortinet_advisories(self, mock_get):
        """Test discovering CVEs from FortiGuard PSIRT."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <body>
            <div class="psirt-advisory">
                <h3>FG-IR-25-001</h3>
                <p>FortiOS - CVE-2025-34567 Stack-based Buffer Overflow</p>
                <span class="severity">Critical</span>
            </div>
            <div class="psirt-advisory">
                <h3>FG-IR-25-002</h3>
                <p>FortiGate - Multiple vulnerabilities (CVE-2025-34568, CVE-2025-34569)</p>
                <span class="severity">High</span>
            </div>
        </body>
        </html>
        """
        mock_get.return_value = mock_response

        scraper = FortinetScraper()
        results = list(scraper.discover())

        assert len(results) == 3
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-34567" in cve_ids
        assert "CVE-2025-34568" in cve_ids
        assert "CVE-2025-34569" in cve_ids

        for result in results:
            assert result.source_name == "Fortinet"
            assert result.confidence == 0.90


class TestVMwareScraper:
    """Tests for VMwareScraper."""

    def test_initialization(self):
        """Test VMwareScraper initialization."""
        scraper = VMwareScraper()

        assert scraper.name == "VMware"
        assert scraper.source_type == SourceType.VENDOR_ADVISORY
        assert scraper.base_url == "https://www.vmware.com/security/advisories"
        assert scraper.confidence == 0.93
        assert scraper.enabled is True

    @patch('requests.Session.get')
    def test_discover_vmware_advisories(self, mock_get):
        """Test discovering CVEs from VMware security advisories."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <body>
            <div class="advisory-item">
                <h2>VMSA-2025-0001</h2>
                <p>VMware vCenter Server updates address critical security issues</p>
                <ul>
                    <li>CVE-2025-45678: Remote code execution</li>
                    <li>CVE-2025-45679: Privilege escalation</li>
                </ul>
            </div>
            <div class="advisory-item">
                <h2>VMSA-2025-0002</h2>
                <p>ESXi security update for CVE-2025-45680</p>
            </div>
        </body>
        </html>
        """
        mock_get.return_value = mock_response

        scraper = VMwareScraper()
        results = list(scraper.discover())

        assert len(results) == 3
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-45678" in cve_ids
        assert "CVE-2025-45679" in cve_ids
        assert "CVE-2025-45680" in cve_ids

        for result in results:
            assert result.source_name == "VMware"
            assert result.confidence == 0.93


class TestVendorScraperErrorHandling:
    """Test error handling across all vendor scrapers."""

    @patch('requests.Session.get')
    def test_http_error_handling(self, mock_get):
        """Test that all scrapers handle HTTP errors gracefully."""
        mock_get.side_effect = Exception("Connection failed")

        scrapers = [
            CitrixScraper(),
            IvantiScraper(),
            PaloAltoScraper(),
            FortinetScraper(),
            VMwareScraper(),
        ]

        for scraper in scrapers:
            with pytest.raises(DiscoveryError):
                list(scraper.discover())

    @patch('requests.Session.get')
    def test_empty_response_handling(self, mock_get):
        """Test that all scrapers handle empty responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = ""
        mock_get.return_value = mock_response

        scrapers = [
            CitrixScraper(),
            IvantiScraper(),
            PaloAltoScraper(),
            FortinetScraper(),
            VMwareScraper(),
        ]

        for scraper in scrapers:
            results = list(scraper.discover())
            assert len(results) == 0  # Empty response should yield no results


class TestVendorConfidenceScores:
    """Test that vendor confidence scores are appropriate."""

    def test_all_vendor_confidence_scores(self):
        """Test that all vendors have appropriate confidence scores."""
        vendors = [
            (CitrixScraper(), 0.90),
            (IvantiScraper(), 0.88),
            (PaloAltoScraper(), 0.92),
            (FortinetScraper(), 0.90),
            (VMwareScraper(), 0.93),
        ]

        for scraper, expected_confidence in vendors:
            assert scraper.confidence == expected_confidence
            # All vendor sources should be high confidence (0.85-0.95)
            assert 0.85 <= scraper.confidence <= 0.95
