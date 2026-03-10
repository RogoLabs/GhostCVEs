"""
Integration Smoke Test for CVE.org API Client
==============================================

Quick smoke test to verify the API client can be instantiated and used
with the existing ValidationResult infrastructure.

This test doesn't make real API calls but validates integration points.

Author: rogolabs.net
"""

import pytest
from unittest.mock import Mock, patch

from src.api.cve_org_client import CVEOrgAPIClient
from src.registry.validator import ValidationResult, CVEStatus


class TestCVEOrgIntegration:
    """Integration tests for CVE.org API client."""

    def test_client_instantiation(self):
        """Test that client can be instantiated with default config."""
        client = CVEOrgAPIClient()
        assert client is not None
        assert client.base_url == "https://cveawg.mitre.org/api/cve"

    @patch("requests.Session.get")
    def test_validation_result_compatibility(self, mock_get):
        """Test that returned ValidationResult is compatible with existing code."""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "RESERVED",
                "dateReserved": "2025-01-01T00:00:00.000Z",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        # Validate CVE
        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        # Verify ValidationResult has all expected attributes
        assert hasattr(result, "cve_id")
        assert hasattr(result, "status")
        assert hasattr(result, "is_ghost")
        assert hasattr(result, "registry_source")
        assert hasattr(result, "description")
        assert hasattr(result, "published_date")
        assert hasattr(result, "last_modified")
        assert hasattr(result, "raw_response")
        assert hasattr(result, "validated_at")

        # Verify values
        assert result.cve_id == "CVE-2025-12345"
        assert result.status == CVEStatus.RESERVED
        assert result.is_ghost is True
        assert result.registry_source == "CVE.ORG"

    @patch("requests.Session.get")
    def test_multiple_validations(self, mock_get):
        """Test that multiple validations work correctly."""
        # Mock responses for different CVE IDs
        def mock_response_factory(*args, **kwargs):
            url = args[0]
            response = Mock()
            response.status_code = 200

            if "12345" in url:
                response.json.return_value = {
                    "cveMetadata": {"cveId": "CVE-2025-12345", "state": "PUBLISHED"},
                    "containers": {}
                }
            elif "67890" in url:
                response.json.return_value = {
                    "cveMetadata": {"cveId": "CVE-2025-67890", "state": "RESERVED"},
                    "containers": {}
                }
            else:
                response.status_code = 404

            return response

        mock_get.side_effect = mock_response_factory

        client = CVEOrgAPIClient()

        # Validate multiple CVEs
        result1 = client.validate("CVE-2025-12345", found_in_wild=True)
        result2 = client.validate("CVE-2025-67890", found_in_wild=True)
        result3 = client.validate("CVE-2025-99999", found_in_wild=True)

        assert result1.status == CVEStatus.PUBLISHED
        assert result1.is_ghost is False

        assert result2.status == CVEStatus.RESERVED
        assert result2.is_ghost is True

        assert result3.status == CVEStatus.NOT_FOUND
        assert result3.is_ghost is True

    @patch("requests.Session.get")
    def test_error_handling_integration(self, mock_get):
        """Test that errors don't break the validation flow."""
        mock_get.side_effect = Exception("Network error")

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        # Should return ERROR status, not crash
        assert result.status == CVEStatus.ERROR
        assert result.is_ghost is False  # Don't flag as ghost on errors
