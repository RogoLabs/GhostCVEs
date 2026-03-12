"""
Tests for Microsoft MSRC vendor discovery.

Verifies that Microsoft MSRC endpoint is properly configured and
functional for discovering CVEs from the MSRC CVRF API.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.discovery.vendor_discovery import VendorDiscovery
from src.config import VENDOR_ENDPOINTS


def test_msrc_endpoint_configured():
    """Test that MSRC endpoint exists in VENDOR_ENDPOINTS."""
    msrc_endpoints = [e for e in VENDOR_ENDPOINTS if "msrc" in e.name.lower()]
    assert len(msrc_endpoints) > 0
    assert msrc_endpoints[0].name == "Microsoft MSRC"
    assert "api.msrc.microsoft.com" in msrc_endpoints[0].base_url


def test_active_vendors_filters_endpoints():
    """Test that active_vendors list filters which endpoints are processed."""
    # Create with specific active vendors
    discovery = VendorDiscovery(active_vendors=["Microsoft MSRC", "Oracle CPU"])

    # Should only have 2 endpoints
    assert len(discovery.endpoints) == 2
    endpoint_names = [e.name for e in discovery.endpoints]
    assert "Microsoft MSRC" in endpoint_names
    assert "Oracle CPU" in endpoint_names
    assert "Apache Security" not in endpoint_names


def test_default_active_vendors():
    """Test default active_vendors includes key vendors."""
    discovery = VendorDiscovery()

    # Should have at least MSRC in the default list
    endpoint_names = [e.name for e in discovery.endpoints]
    assert "Microsoft MSRC" in endpoint_names


@patch('src.discovery.vendor_discovery.requests.Session')
def test_msrc_cvrf_parsing(mock_session_class):
    """Test parsing CVEs from MSRC CVRF XML response."""
    # Mock session and response
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock MSRC API response (list of updates)
    updates_response = Mock()
    updates_response.status_code = 200
    updates_response.json.return_value = {
        "value": [
            {
                "ID": "2025-Mar",
                "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/2025-Mar"
            }
        ]
    }

    # Mock CVRF XML document
    cvrf_response = Mock()
    cvrf_response.status_code = 200
    cvrf_response.content = b'''<?xml version="1.0"?>
    <cvrfdoc xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">
        <Vulnerability>
            <CVE>CVE-2025-12345</CVE>
            <Title>Windows Kernel Elevation of Privilege</Title>
        </Vulnerability>
        <Vulnerability>
            <CVE>CVE-2025-12346</CVE>
            <Title>Microsoft Office Remote Code Execution</Title>
        </Vulnerability>
    </cvrfdoc>
    '''

    # Configure mock to return different responses for different URLs
    mock_session.get.side_effect = [updates_response, cvrf_response]

    # Create discovery with only MSRC active
    discovery = VendorDiscovery(active_vendors=["Microsoft MSRC"])

    # Run discovery
    results = list(discovery.discover())

    # Verify results
    assert len(results) >= 2
    cve_ids = [r.cve_id for r in results]
    assert "CVE-2025-12345" in cve_ids
    assert "CVE-2025-12346" in cve_ids

    # Verify all results are from MSRC
    for result in results:
        assert result.source_name == "Microsoft MSRC"
        assert result.confidence == 1.0
        assert "msrc.microsoft.com" in result.evidence_url


@patch('src.discovery.vendor_discovery.requests.Session')
def test_msrc_handles_empty_response(mock_session_class):
    """Test that MSRC handles empty API responses gracefully."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock empty response
    empty_response = Mock()
    empty_response.status_code = 200
    empty_response.json.return_value = {"value": []}
    mock_session.get.return_value = empty_response

    discovery = VendorDiscovery(active_vendors=["Microsoft MSRC"])
    results = list(discovery.discover())

    # Should complete without error, returning empty list
    assert len(results) == 0


@patch('src.discovery.vendor_discovery.requests.Session')
def test_msrc_handles_malformed_cvrf(mock_session_class):
    """Test that MSRC handles malformed CVRF XML gracefully."""
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session

    # Mock updates response with CVRF URL
    updates_response = Mock()
    updates_response.status_code = 200
    updates_response.json.return_value = {
        "value": [{"ID": "2025-Mar", "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/2025-Mar"}]
    }

    # Mock malformed CVRF response
    cvrf_response = Mock()
    cvrf_response.status_code = 200
    cvrf_response.content = b"<invalid>xml</not-matching>"

    mock_session.get.side_effect = [updates_response, cvrf_response]

    discovery = VendorDiscovery(active_vendors=["Microsoft MSRC"])

    # Should handle gracefully without crashing
    results = list(discovery.discover())

    # May return empty or partial results, but shouldn't raise exception
    assert isinstance(results, list)
