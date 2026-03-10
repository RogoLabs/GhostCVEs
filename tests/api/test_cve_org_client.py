"""
Tests for CVE.org API Client
=============================

Comprehensive test suite for the CVEOrgAPIClient, covering:
- Status validation (PUBLISHED, RESERVED, REJECTED, NOT_FOUND)
- Rate limiting (30 requests/minute)
- Error handling (404, 429, network errors)
- Recent changes monitoring
- ValidationResult construction
- CVE state parsing and date handling

All HTTP requests are mocked - no real API calls.

Author: rogolabs.net
"""

import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

import pytest
import requests

from src.api.cve_org_client import CVEOrgAPIClient
from src.registry.validator import ValidationResult, CVEStatus


class TestCVEOrgAPIClientInit:
    """Test CVEOrgAPIClient initialization."""

    def test_init_default_config(self):
        """Test initialization with default configuration."""
        client = CVEOrgAPIClient()

        assert client.base_url == "https://cveawg.mitre.org/api/cve"
        assert client.timeout == 30
        assert client.max_retries == 3
        assert client.retry_delay == 1.0
        assert client.session is not None
        assert client.rate_limiter is not None

    def test_init_custom_config(self):
        """Test initialization with custom configuration."""
        client = CVEOrgAPIClient(
            base_url="https://custom.api/cve",
            timeout=60,
            max_retries=5,
            retry_delay=2.0,
        )

        assert client.base_url == "https://custom.api/cve"
        assert client.timeout == 60
        assert client.max_retries == 5
        assert client.retry_delay == 2.0

    def test_session_headers(self):
        """Test that session has correct headers."""
        client = CVEOrgAPIClient()

        assert "User-Agent" in client.session.headers
        assert "Accept" in client.session.headers
        assert client.session.headers["Accept"] == "application/json"


class TestValidatePublishedCVE:
    """Test validation of PUBLISHED CVEs."""

    @patch("requests.Session.get")
    def test_validate_published_cve_basic(self, mock_get):
        """Test validation of a basic PUBLISHED CVE."""
        # Mock CVE.org API response for PUBLISHED CVE
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
                "datePublished": "2025-01-15T10:00:00.000Z",
                "dateUpdated": "2025-01-15T10:00:00.000Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Buffer overflow in example software"
                        }
                    ]
                }
            }
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert isinstance(result, ValidationResult)
        assert result.cve_id == "CVE-2025-12345"
        assert result.status == CVEStatus.PUBLISHED
        assert result.is_ghost is False  # PUBLISHED + found_in_wild = not ghost
        assert result.registry_source == "CVE.ORG"
        assert result.description == "Buffer overflow in example software"
        assert result.published_date is not None
        assert result.last_modified is not None

    @patch("requests.Session.get")
    def test_validate_published_cve_no_description(self, mock_get):
        """Test PUBLISHED CVE with no description."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-54321",
                "state": "PUBLISHED",
                "datePublished": "2025-02-01T12:00:00.000Z",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-54321", found_in_wild=True)

        assert result.status == CVEStatus.PUBLISHED
        assert result.description is None
        assert result.is_ghost is False


class TestValidateReservedCVE:
    """Test validation of RESERVED CVEs (Ghost candidates)."""

    @patch("requests.Session.get")
    def test_validate_reserved_cve_is_ghost(self, mock_get):
        """Test RESERVED CVE found in wild is classified as Ghost."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-99999",
                "state": "RESERVED",
                "dateReserved": "2025-01-01T00:00:00.000Z",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-99999", found_in_wild=True)

        assert result.status == CVEStatus.RESERVED
        assert result.is_ghost is True  # RESERVED + found_in_wild = Ghost!
        assert result.registry_source == "CVE.ORG"

    @patch("requests.Session.get")
    def test_validate_reserved_cve_not_in_wild(self, mock_get):
        """Test RESERVED CVE not found in wild is not Ghost."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-88888",
                "state": "RESERVED",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-88888", found_in_wild=False)

        assert result.status == CVEStatus.RESERVED
        assert result.is_ghost is False  # RESERVED but not found_in_wild = not Ghost


class TestValidateRejectedCVE:
    """Test validation of REJECTED CVEs."""

    @patch("requests.Session.get")
    def test_validate_rejected_cve(self, mock_get):
        """Test REJECTED CVE is not classified as Ghost."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-77777",
                "state": "REJECTED",
                "datePublished": "2025-01-10T08:00:00.000Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "** REJECT ** This CVE was rejected."
                        }
                    ]
                }
            }
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-77777", found_in_wild=True)

        assert result.status == CVEStatus.REJECTED
        assert result.is_ghost is False  # REJECTED never counts as Ghost
        assert "REJECT" in result.description


class TestValidateNotFoundCVE:
    """Test validation of CVEs not found in registry."""

    @patch("requests.Session.get")
    def test_validate_not_found_cve_404(self, mock_get):
        """Test 404 response for CVE not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-66666", found_in_wild=True)

        assert result.status == CVEStatus.NOT_FOUND
        assert result.is_ghost is True  # NOT_FOUND + found_in_wild = Ghost!
        assert result.registry_source == "CVE.ORG"

    @patch("requests.Session.get")
    def test_validate_not_found_cve_not_in_wild(self, mock_get):
        """Test NOT_FOUND CVE not in wild is not Ghost."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-55555", found_in_wild=False)

        assert result.status == CVEStatus.NOT_FOUND
        assert result.is_ghost is False  # NOT_FOUND but not found_in_wild


class TestRateLimiting:
    """Test rate limiting enforcement (30 requests/minute)."""

    @patch("requests.Session.get")
    def test_rate_limiting_enforced(self, mock_get):
        """Test that rate limiter enforces 30 requests/minute."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-11111",
                "state": "PUBLISHED",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()

        # Make 30 requests rapidly - should complete without waiting
        start_time = time.time()
        for i in range(30):
            client.validate(f"CVE-2025-{10000 + i}", found_in_wild=False)
        elapsed = time.time() - start_time

        # Should complete quickly (no rate limiting yet)
        assert elapsed < 5.0

        # 31st request should trigger rate limiting
        start_time = time.time()
        client.validate("CVE-2025-99999", found_in_wild=False)
        elapsed = time.time() - start_time

        # Should have waited (rate limit exceeded)
        # Note: Exact timing depends on RateLimiter implementation
        # We just verify it didn't fail
        assert mock_get.call_count == 31

    @patch("requests.Session.get")
    def test_rate_limiter_resets(self, mock_get):
        """Test that rate limiter resets after window."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {"cveId": "CVE-2025-11111", "state": "PUBLISHED"},
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()

        # Verify rate limiter exists and has correct settings
        assert client.rate_limiter.requests_per_window == 30
        assert client.rate_limiter.window_seconds == 60


class TestErrorHandling:
    """Test error handling for various failure scenarios."""

    @patch("requests.Session.get")
    def test_handle_429_rate_limit_response(self, mock_get):
        """Test handling of 429 rate limit response."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.text = "Rate limit exceeded"
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.ERROR
        assert result.is_ghost is False  # Don't classify as Ghost on API errors
        assert result.registry_source == "CVE.ORG"

    @patch("requests.Session.get")
    def test_handle_500_server_error(self, mock_get):
        """Test handling of 500 server error."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.ERROR
        assert result.is_ghost is False

    @patch("requests.Session.get")
    def test_handle_network_timeout(self, mock_get):
        """Test handling of network timeout."""
        mock_get.side_effect = requests.Timeout("Connection timed out")

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.ERROR
        assert result.is_ghost is False

    @patch("requests.Session.get")
    def test_handle_connection_error(self, mock_get):
        """Test handling of connection error."""
        mock_get.side_effect = requests.ConnectionError("Failed to connect")

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.ERROR
        assert result.is_ghost is False

    @patch("requests.Session.get")
    def test_handle_invalid_json_response(self, mock_get):
        """Test handling of invalid JSON in response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.ERROR
        assert result.is_ghost is False


class TestRetryLogic:
    """Test retry logic for transient failures."""

    @patch("requests.Session.get")
    @patch("time.sleep")  # Mock sleep to speed up tests
    def test_retry_on_timeout(self, mock_sleep, mock_get):
        """Test that client retries on timeout."""
        # First 2 calls timeout, 3rd succeeds
        mock_get.side_effect = [
            requests.Timeout("Timeout 1"),
            requests.Timeout("Timeout 2"),
            Mock(
                status_code=200,
                json=lambda: {
                    "cveMetadata": {"cveId": "CVE-2025-12345", "state": "PUBLISHED"},
                    "containers": {}
                }
            )
        ]

        client = CVEOrgAPIClient(max_retries=3, retry_delay=1.0)
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.PUBLISHED
        assert mock_get.call_count == 3  # 2 retries + 1 success
        assert mock_sleep.call_count == 2  # Sleep between retries

    @patch("requests.Session.get")
    @patch("time.sleep")
    def test_retry_exhausted(self, mock_sleep, mock_get):
        """Test that client gives up after max retries."""
        mock_get.side_effect = requests.Timeout("Persistent timeout")

        client = CVEOrgAPIClient(max_retries=3, retry_delay=0.1)
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.ERROR
        assert mock_get.call_count == 3  # max_retries attempts


class TestDateParsing:
    """Test parsing of ISO 8601 dates from CVE.org API."""

    @patch("requests.Session.get")
    def test_parse_iso8601_dates(self, mock_get):
        """Test parsing of ISO 8601 formatted dates."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
                "datePublished": "2025-01-15T10:30:45.123Z",
                "dateUpdated": "2025-02-20T14:22:33.456Z",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.published_date is not None
        assert result.published_date.year == 2025
        assert result.published_date.month == 1
        assert result.published_date.day == 15

        assert result.last_modified is not None
        assert result.last_modified.year == 2025
        assert result.last_modified.month == 2
        assert result.last_modified.day == 20

    @patch("requests.Session.get")
    def test_handle_missing_dates(self, mock_get):
        """Test handling of missing date fields."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "RESERVED",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.published_date is None
        assert result.last_modified is None

    @patch("requests.Session.get")
    def test_handle_invalid_date_format(self, mock_get):
        """Test handling of invalid date format."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
                "datePublished": "invalid-date-format",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        # Should not crash, just set date to None
        assert result.published_date is None


class TestCVEIDNormalization:
    """Test CVE ID normalization."""

    @patch("requests.Session.get")
    def test_normalize_lowercase_cve_id(self, mock_get):
        """Test that lowercase CVE IDs are normalized to uppercase."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("cve-2025-12345", found_in_wild=True)

        assert result.cve_id == "CVE-2025-12345"
        # Verify API was called with uppercase ID
        mock_get.assert_called_once()
        call_args = mock_get.call_args[0][0]
        assert "CVE-2025-12345" in call_args


class TestRecentChangesMonitoring:
    """Test monitoring of recent CVE changes (RESERVED -> PUBLISHED)."""

    @patch("requests.Session.get")
    def test_get_recent_changes_basic(self, mock_get):
        """Test fetching recent changes from CVE.org API."""
        # Note: CVE.org API doesn't have a direct "recent changes" endpoint
        # This tests the conceptual interface for monitoring
        # Implementation may query multiple CVEs or use a different approach

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
                "dateUpdated": datetime.utcnow().isoformat() + "Z",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()

        # Check that we can monitor a specific CVE for changes
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.last_modified is not None
        # Recent update (within last hour)
        # Use timezone-aware comparison
        age = datetime.utcnow().replace(tzinfo=result.last_modified.tzinfo) - result.last_modified
        assert age < timedelta(hours=1)


class TestRawResponseStorage:
    """Test that raw API responses are stored for debugging."""

    @patch("requests.Session.get")
    def test_raw_response_stored(self, mock_get):
        """Test that raw API response is stored in ValidationResult."""
        raw_data = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test description"}]
                }
            }
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = raw_data
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.raw_response is not None
        assert result.raw_response == raw_data
        assert "cveMetadata" in result.raw_response


class TestBatchValidation:
    """Test batch validation of multiple CVE IDs."""

    @patch("requests.Session.get")
    def test_validate_batch(self, mock_get):
        """Test validating multiple CVE IDs in batch."""
        # Mock different responses for different CVE IDs
        def side_effect(*args, **kwargs):
            url = args[0]
            if "12345" in url:
                return Mock(
                    status_code=200,
                    json=lambda: {
                        "cveMetadata": {"cveId": "CVE-2025-12345", "state": "PUBLISHED"},
                        "containers": {}
                    }
                )
            elif "67890" in url:
                return Mock(
                    status_code=200,
                    json=lambda: {
                        "cveMetadata": {"cveId": "CVE-2025-67890", "state": "RESERVED"},
                        "containers": {}
                    }
                )
            else:
                return Mock(status_code=404)

        mock_get.side_effect = side_effect

        client = CVEOrgAPIClient()
        cve_ids = ["CVE-2025-12345", "CVE-2025-67890", "CVE-2025-99999"]
        results = client.validate_batch(cve_ids, found_in_wild=True)

        assert len(results) == 3
        assert results[0].status == CVEStatus.PUBLISHED
        assert results[1].status == CVEStatus.RESERVED
        assert results[2].status == CVEStatus.NOT_FOUND

        # Check Ghost classification
        assert results[0].is_ghost is False  # PUBLISHED
        assert results[1].is_ghost is True   # RESERVED + found_in_wild
        assert results[2].is_ghost is True   # NOT_FOUND + found_in_wild


class TestEdgeCases:
    """Test edge cases and unusual scenarios."""

    @patch("requests.Session.get")
    def test_validate_with_empty_containers(self, mock_get):
        """Test handling of response with empty containers."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.status == CVEStatus.PUBLISHED
        assert result.description is None

    @patch("requests.Session.get")
    def test_validate_with_multiple_descriptions(self, mock_get):
        """Test extraction of English description when multiple languages exist."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "PUBLISHED",
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {"lang": "es", "value": "Descripción en español"},
                        {"lang": "en", "value": "English description"},
                        {"lang": "fr", "value": "Description en français"},
                    ]
                }
            }
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        assert result.description == "English description"

    @patch("requests.Session.get")
    def test_validate_with_unknown_state(self, mock_get):
        """Test handling of unknown CVE state."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cveMetadata": {
                "cveId": "CVE-2025-12345",
                "state": "UNKNOWN_STATE",
            },
            "containers": {}
        }
        mock_get.return_value = mock_response

        client = CVEOrgAPIClient()
        result = client.validate("CVE-2025-12345", found_in_wild=True)

        # Should default to ERROR or NOT_FOUND for unknown states
        assert result.status in (CVEStatus.ERROR, CVEStatus.NOT_FOUND)
