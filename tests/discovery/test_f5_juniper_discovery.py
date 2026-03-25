"""
Tests for F5 and Juniper vendor discovery.

Verifies that F5 Networks and Juniper Networks endpoints are properly
configured and functional for discovering CVEs.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from src.discovery.vendor_discovery import VendorDiscovery
from src.config import VENDOR_ENDPOINTS


def test_f5_endpoint_configured():
    """Test that F5 endpoint exists in VENDOR_ENDPOINTS."""
    f5_endpoints = [e for e in VENDOR_ENDPOINTS if "f5" in e.name.lower()]
    assert len(f5_endpoints) > 0
    assert f5_endpoints[0].name == "F5 Security Advisories"
    assert "f5.com" in f5_endpoints[0].base_url


def test_juniper_endpoint_configured():
    """Test that Juniper endpoint exists in VENDOR_ENDPOINTS."""
    juniper_endpoints = [e for e in VENDOR_ENDPOINTS if "juniper" in e.name.lower()]
    assert len(juniper_endpoints) > 0
    assert juniper_endpoints[0].name == "Juniper Security Bulletins"
    assert "juniper.net" in juniper_endpoints[0].base_url


def test_default_active_vendors_includes_f5_and_juniper():
    """Test default active_vendors includes F5 and Juniper."""
    discovery = VendorDiscovery()

    endpoint_names = [e.name for e in discovery.endpoints]
    assert "F5 Security Advisories" in endpoint_names
    assert "Juniper Security Bulletins" in endpoint_names


@patch('src.discovery.vendor_discovery.requests.Session')
def test_f5_discovery_from_html(mock_session_class):
    """Test discovering CVEs from F5 security advisories page."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock F5 advisory HTML response
    html_response = Mock()
    html_response.status_code = 200
    html_response.text = '''
    <html>
    <body>
        <div class="advisory">
            <h2>K12345678: BIG-IP security vulnerability CVE-2025-33456</h2>
            <p>A security vulnerability exists in BIG-IP that could allow...</p>
        </div>
        <div class="advisory">
            <h2>Security Advisory: CVE-2025-33457 - NGINX Controller</h2>
            <p>Critical vulnerability affecting F5 NGINX Controller</p>
        </div>
        <div class="advisory">
            <h2>Multiple CVEs addressed: CVE-2025-33458, CVE-2025-33459</h2>
        </div>
    </body>
    </html>
    '''
    mock_session.get.return_value = html_response

    # Create discovery with only F5 active
    discovery = VendorDiscovery(active_vendors=["F5 Security Advisories"])

    # Run discovery
    results = list(discovery.discover())

    # Verify results
    assert len(results) >= 3
    cve_ids = [r.cve_id for r in results]
    assert "CVE-2025-33456" in cve_ids
    assert "CVE-2025-33457" in cve_ids
    assert "CVE-2025-33458" in cve_ids

    # Verify all results are from F5
    for result in results:
        assert result.source_name == "F5 Security Advisories"
        assert 0.5 <= result.confidence <= 1.0  # Generic scraping has lower confidence


@patch('src.discovery.vendor_discovery.requests.Session')
def test_juniper_discovery_from_html(mock_session_class):
    """Test discovering CVEs from Juniper security bulletins."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock Juniper advisory HTML response
    html_response = Mock()
    html_response.status_code = 200
    html_response.text = '''
    <html>
    <body>
        <div class="security-bulletin">
            <h3>JSA11234: Junos OS vulnerability (CVE-2025-44567)</h3>
            <p>A vulnerability in Junos OS could allow remote code execution</p>
        </div>
        <div class="security-bulletin">
            <h3>2025-01 Security Bulletin</h3>
            <p>Multiple vulnerabilities: CVE-2025-44568, CVE-2025-44569</p>
        </div>
    </body>
    </html>
    '''
    mock_session.get.return_value = html_response

    # Create discovery with only Juniper active
    discovery = VendorDiscovery(active_vendors=["Juniper Security Bulletins"])

    # Run discovery
    results = list(discovery.discover())

    # Verify results
    assert len(results) >= 2
    cve_ids = [r.cve_id for r in results]
    assert "CVE-2025-44567" in cve_ids
    assert "CVE-2025-44568" in cve_ids

    # Verify all results are from Juniper
    for result in results:
        assert result.source_name == "Juniper Security Bulletins"
        assert 0.5 <= result.confidence <= 1.0


@patch('src.discovery.vendor_discovery.requests.Session')
def test_combined_discovery_all_three_vendors(mock_session_class):
    """Test that all three vendors (MSRC, F5, Juniper) work together."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock responses for all three vendors
    msrc_updates = Mock()
    msrc_updates.status_code = 200
    msrc_updates.json.return_value = {"value": []}  # Empty for simplicity

    f5_html = Mock()
    f5_html.status_code = 200
    f5_html.text = "<html><body>CVE-2025-11111</body></html>"

    juniper_html = Mock()
    juniper_html.status_code = 200
    juniper_html.text = "<html><body>CVE-2025-22222</body></html>"

    mock_session.get.side_effect = [msrc_updates, f5_html, juniper_html]

    # Create discovery with all three active (default behavior)
    discovery = VendorDiscovery()

    # Verify all three are in the active list
    endpoint_names = [e.name for e in discovery.endpoints]
    assert "Microsoft MSRC" in endpoint_names
    assert "F5 Security Advisories" in endpoint_names
    assert "Juniper Security Bulletins" in endpoint_names

    # Run discovery
    results = list(discovery.discover())

    # Should find CVEs from F5 and Juniper (MSRC returned empty)
    cve_ids = [r.cve_id for r in results]
    assert "CVE-2025-11111" in cve_ids
    assert "CVE-2025-22222" in cve_ids


@patch('src.discovery.vendor_discovery.requests.Session')
def test_f5_handles_http_error(mock_session_class):
    """Test that F5 handles HTTP errors gracefully."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock HTTP error
    mock_session.get.side_effect = Exception("Connection timeout")

    discovery = VendorDiscovery(active_vendors=["F5 Security Advisories"])

    # Should complete without crashing
    results = list(discovery.discover())

    # May return empty, but shouldn't raise exception
    assert isinstance(results, list)


@patch('src.discovery.vendor_discovery.requests.Session')
def test_juniper_handles_empty_page(mock_session_class):
    """Test that Juniper handles empty pages gracefully."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock empty response
    empty_response = Mock()
    empty_response.status_code = 200
    empty_response.text = "<html><body></body></html>"
    mock_session.get.return_value = empty_response

    discovery = VendorDiscovery(active_vendors=["Juniper Security Bulletins"])
    results = list(discovery.discover())

    # Should complete without error, returning empty list
    assert len(results) == 0
