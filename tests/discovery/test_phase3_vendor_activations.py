"""
Tests for Phase 3 vendor activations.

Verifies that all newly activated vendors (specialized scrapers + VendorDiscovery
endpoints) are properly configured and functional.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from src.discovery.vendors import (
    CitrixScraper,
    IvantiScraper,
    PaloAltoScraper,
    FortinetScraper,
    VMwareScraper,
)
from src.discovery.vendor_discovery import VendorDiscovery
from src.config import SourceType


class TestSpecializedVendorScrapers:
    """Tests for the 5 specialized vendor scrapers added in Phase 3."""

    def test_all_scrapers_initialized(self):
        """Test that all 5 specialized scrapers can be initialized."""
        scrapers = [
            CitrixScraper(),
            IvantiScraper(),
            PaloAltoScraper(),
            FortinetScraper(),
            VMwareScraper(),
        ]

        for scraper in scrapers:
            assert scraper.enabled is True
            assert scraper.source_type == SourceType.VENDOR_ADVISORY
            assert 0.85 <= scraper.confidence <= 0.95
            assert hasattr(scraper, 'discover')

    def test_scraper_names(self):
        """Test that scraper names are correctly set."""
        expected_names = {
            CitrixScraper: "Citrix",
            IvantiScraper: "Ivanti",
            PaloAltoScraper: "Palo Alto Networks",
            FortinetScraper: "Fortinet",
            VMwareScraper: "VMware",
        }

        for scraper_class, expected_name in expected_names.items():
            scraper = scraper_class()
            assert scraper.name == expected_name

    def test_scraper_base_urls(self):
        """Test that all scrapers have valid base URLs."""
        scrapers = [
            CitrixScraper(),
            IvantiScraper(),
            PaloAltoScraper(),
            FortinetScraper(),
            VMwareScraper(),
        ]

        for scraper in scrapers:
            assert scraper.base_url.startswith("https://")
            assert len(scraper.base_url) > 10

    @patch('requests.Session.get')
    def test_all_scrapers_handle_errors(self, mock_get):
        """Test that all scrapers handle HTTP errors gracefully."""
        mock_get.side_effect = Exception("Connection timeout")

        scrapers = [
            CitrixScraper(),
            IvantiScraper(),
            PaloAltoScraper(),
            FortinetScraper(),
            VMwareScraper(),
        ]

        for scraper in scrapers:
            # Should raise DiscoveryError, not propagate raw exception
            from src.discovery.base import DiscoveryError
            with pytest.raises(DiscoveryError):
                list(scraper.discover())


class TestVendorDiscoveryExpansion:
    """Tests for expanded VendorDiscovery active vendors."""

    def test_default_active_vendors_count(self):
        """Test that default active vendors list has been expanded."""
        discovery = VendorDiscovery()

        # Phase 3 should have at least 8 active vendors
        assert len(discovery.endpoints) >= 8
        assert len(discovery.active_vendors) >= 8

    def test_phase3_vendors_included(self):
        """Test that Phase 3 vendors are in active list."""
        discovery = VendorDiscovery()

        phase3_vendors = [
            "Cisco PSIRT",
            "Red Hat Security Data",
            "Debian Security Tracker",
            "Oracle CPU",
            "Apache Security",
        ]

        endpoint_names = [e.name for e in discovery.endpoints]

        for vendor in phase3_vendors:
            assert vendor in discovery.active_vendors, f"{vendor} not in active_vendors"
            assert vendor in endpoint_names, f"{vendor} not in endpoints"

    def test_phase2b_vendors_still_active(self):
        """Test that Phase 2B vendors are still active."""
        discovery = VendorDiscovery()

        phase2b_vendors = [
            "Microsoft MSRC",
            "F5 Security Advisories",
            "Juniper Security Bulletins",
        ]

        endpoint_names = [e.name for e in discovery.endpoints]

        for vendor in phase2b_vendors:
            assert vendor in discovery.active_vendors
            assert vendor in endpoint_names

    @patch('src.discovery.vendor_discovery.requests.Session')
    def test_cisco_endpoint_accessible(self, mock_session_class):
        """Test that Cisco PSIRT endpoint is configured correctly."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock Cisco response (requires auth, should be skipped)
        mock_response = Mock()
        mock_response.status_code = 401  # Unauthorized
        mock_session.get.return_value = mock_response

        discovery = VendorDiscovery(active_vendors=["Cisco PSIRT"])

        # Should handle gracefully
        results = list(discovery.discover())
        # May return empty if auth required, but shouldn't crash
        assert isinstance(results, list)

    @patch('src.discovery.vendor_discovery.requests.Session')
    def test_red_hat_endpoint_accessible(self, mock_session_class):
        """Test that Red Hat Security Data endpoint works."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock Red Hat JSON API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"cve": {"CVE_data_meta": {"ID": "CVE-2025-99999"}}}'
        mock_session.get.return_value = mock_response

        discovery = VendorDiscovery(active_vendors=["Red Hat Security Data"])
        results = list(discovery.discover())

        # Should extract CVE from response
        assert len(results) >= 1
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-99999" in cve_ids

    @patch('src.discovery.vendor_discovery.requests.Session')
    def test_debian_endpoint_accessible(self, mock_session_class):
        """Test that Debian Security Tracker endpoint works."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock Debian HTML response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <body>
            <div class="advisory">CVE-2025-88888 - Security update for package</div>
        </body>
        </html>
        """
        mock_session.get.return_value = mock_response

        discovery = VendorDiscovery(active_vendors=["Debian Security Tracker"])
        results = list(discovery.discover())

        assert len(results) >= 1
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2025-88888" in cve_ids


class TestCombinedVendorCoverage:
    """Tests for combined coverage from all vendor sources."""

    def test_total_vendor_sources(self):
        """Test total number of active vendor sources."""
        from main import create_discovery_modules

        modules = create_discovery_modules()

        # Count vendor-related modules
        vendor_modules = [
            m for m in modules
            if 'vendor' in m.name.lower() or
               m.name in ["Citrix", "Ivanti", "Palo Alto Networks", "Fortinet", "VMware"]
        ]

        # Should have VendorDiscovery + 5 specialized scrapers = 6 vendor sources
        assert len(vendor_modules) >= 6

    def test_no_duplicate_vendors(self):
        """Test that we don't have duplicate vendor coverage."""
        from main import create_discovery_modules

        modules = create_discovery_modules()
        module_names = [m.name for m in modules]

        # Check for exact duplicates
        assert len(module_names) == len(set(module_names)), "Duplicate discovery modules detected"

    def test_all_vendor_sources_enabled(self):
        """Test that all vendor sources are enabled by default."""
        from main import create_discovery_modules

        modules = create_discovery_modules()

        vendor_modules = [
            m for m in modules
            if 'vendor' in m.name.lower() or
               m.name in ["Citrix", "Ivanti", "Palo Alto Networks", "Fortinet", "VMware"]
        ]

        for module in vendor_modules:
            assert module.enabled is True


class TestPhase3VendorIntegration:
    """Integration tests for Phase 3 vendor activations."""

    def test_main_create_modules_includes_vendors(self):
        """Test that main.py's create_discovery_modules includes all vendors."""
        from main import create_discovery_modules

        modules = create_discovery_modules()
        module_names = [m.name for m in modules]

        # Specialized scrapers
        assert "Citrix" in module_names
        assert "Ivanti" in module_names
        assert "Palo Alto Networks" in module_names
        assert "Fortinet" in module_names
        assert "VMware" in module_names

        # VendorDiscovery (generic)
        assert "Vendor Discovery" in module_names

    def test_vendor_sources_have_correct_types(self):
        """Test that all vendor sources have correct source_type."""
        from main import create_discovery_modules

        modules = create_discovery_modules()

        vendor_modules = [
            m for m in modules
            if 'vendor' in m.name.lower() or
               m.name in ["Citrix", "Ivanti", "Palo Alto Networks", "Fortinet", "VMware"]
        ]

        for module in vendor_modules:
            assert module.source_type == SourceType.VENDOR_ADVISORY
