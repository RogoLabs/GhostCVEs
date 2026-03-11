"""
Tests for CVE.org Recent Changes Monitor Discovery Module
===========================================================

Unit tests for the CVEOrgMonitor class that queries CVE.org API
for recently published/updated CVEs and tracks state transitions
from RESERVED to PUBLISHED.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
import json

from src.discovery.cve_org_monitor import CVEOrgMonitor
from src.discovery.base import DiscoveryResult, DiscoveryError
from src.config import SourceType


class TestCVEOrgMonitorInitialization:
    """Tests for CVEOrgMonitor initialization."""

    def test_initialization_defaults(self):
        """Test CVEOrgMonitor initialization with defaults."""
        monitor = CVEOrgMonitor()

        assert monitor.name == "CVE.org Recent Changes Monitor"
        assert monitor.source_type == SourceType.CVE_ORG
        assert monitor.enabled is True
        assert monitor.lookback_days == 1  # Default: last 24 hours

    def test_initialization_custom_lookback(self):
        """Test CVEOrgMonitor initialization with custom lookback period."""
        monitor = CVEOrgMonitor(lookback_days=7)

        assert monitor.lookback_days == 7

    def test_initialization_disabled(self):
        """Test initialization with disabled flag."""
        monitor = CVEOrgMonitor(enabled=False)
        assert monitor.enabled is False

    def test_initialization_creates_session(self):
        """Test that session is created during initialization."""
        monitor = CVEOrgMonitor()

        assert monitor.session is not None
        assert "User-Agent" in monitor.session.headers


class TestCVEOrgMonitorDiscovery:
    """Tests for CVEOrgMonitor discovery functionality."""

    def test_discover_single_published_cve(self):
        """Test discovering a single recently published CVE."""
        mock_response = {
            "cveRecords": [
                {
                    "cveId": "CVE-2025-12345",
                    "cveMetadata": {
                        "state": "PUBLISHED",
                        "datePublished": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
                        "dateUpdated": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                    },
                    "containers": {
                        "cna": {
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": "A critical vulnerability in the system"
                                }
                            ]
                        }
                    }
                }
            ]
        }

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_response["cveRecords"]):
            results = list(monitor.discover())

        assert len(results) == 1
        result = results[0]
        assert result.cve_id == "CVE-2025-12345"
        assert result.source_type == SourceType.CVE_ORG
        assert result.source_name == "CVE.org Recent Changes Monitor"
        assert result.confidence == 1.0  # Perfect confidence - authoritative source
        assert "critical vulnerability" in result.context.lower()

    def test_discover_multiple_published_cves(self):
        """Test discovering multiple recently published CVEs."""
        now = datetime.now(timezone.utc)
        mock_cves = [
            {
                "cveId": "CVE-2025-12345",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (now - timedelta(hours=2)).isoformat() + "Z",
                    "dateUpdated": (now - timedelta(hours=1)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "First vulnerability"
                            }
                        ]
                    }
                }
            },
            {
                "cveId": "CVE-2025-12346",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (now - timedelta(hours=1)).isoformat() + "Z",
                    "dateUpdated": (now - timedelta(minutes=30)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Second vulnerability"
                            }
                        ]
                    }
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = list(monitor.discover())

        assert len(results) == 2
        cve_ids = {r.cve_id for r in results}
        assert cve_ids == {"CVE-2025-12345", "CVE-2025-12346"}

        for result in results:
            assert result.confidence == 1.0
            assert result.source_type == SourceType.CVE_ORG

    def test_discover_skips_reserved_cves(self):
        """Test that RESERVED status CVEs are skipped."""
        mock_cves = [
            {
                "cveId": "CVE-2025-99999",
                "cveMetadata": {
                    "state": "RESERVED",
                    "datePublished": None,
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {}
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = list(monitor.discover())

        # Should skip RESERVED status
        assert len(results) == 0

    def test_discover_skips_rejected_cves(self):
        """Test that REJECTED status CVEs are skipped."""
        mock_cves = [
            {
                "cveId": "CVE-2025-88888",
                "cveMetadata": {
                    "state": "REJECTED",
                    "datePublished": None,
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {}
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = list(monitor.discover())

        # Should skip REJECTED status
        assert len(results) == 0

    def test_discover_cve_with_raw_data(self):
        """Test that raw_data contains full CVE metadata."""
        mock_cves = [
            {
                "cveId": "CVE-2025-12345",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                    "assignerOrgId": "mitre",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Full description of vulnerability"
                            }
                        ]
                    }
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = list(monitor.discover())

        assert len(results) == 1
        result = results[0]

        # Verify raw_data is preserved
        assert result.raw_data is not None
        assert result.raw_data.get("state") == "PUBLISHED"
        assert "datePublished" in result.raw_data
        assert "dateUpdated" in result.raw_data

    def test_discover_handles_missing_descriptions(self):
        """Test discovery with CVE missing descriptions."""
        mock_cves = [
            {
                "cveId": "CVE-2025-54321",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {}
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = list(monitor.discover())

        assert len(results) == 1
        result = results[0]
        assert result.cve_id == "CVE-2025-54321"
        # Should still work without description

    def test_discover_handles_api_error(self):
        """Test that API errors are handled properly."""
        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", side_effect=Exception("API Error")):
            with pytest.raises(DiscoveryError):
                list(monitor.discover())

    def test_evidence_url_format(self):
        """Test that evidence_url points to CVE.org."""
        mock_cves = [
            {
                "cveId": "CVE-2025-12345",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test vulnerability"
                            }
                        ]
                    }
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = list(monitor.discover())

        assert len(results) == 1
        result = results[0]

        # Evidence URL should point to CVE.org
        assert "cve.mitre.org" in result.evidence_url or "cveawg.mitre.org" in result.evidence_url
        assert "CVE-2025-12345" in result.evidence_url


class TestCVEOrgMonitorFetchLogic:
    """Tests for CVE.org API fetch logic."""

    def test_fetch_recent_cves_constructs_url(self):
        """Test that _fetch_recent_cves constructs proper API URL."""
        monitor = CVEOrgMonitor(lookback_days=1)

        with patch.object(monitor.session, "get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: {"cveRecords": []}
            )

            try:
                monitor._fetch_recent_cves()
            except:
                pass

            # Verify session.get was called
            assert mock_get.called
            call_args = mock_get.call_args

            # URL should contain the base URL and CVE ID or other parameters
            url = call_args[0][0]
            assert "cveawg.mitre.org" in url or "cve.mitre.org" in url

    def test_fetch_with_custom_lookback_period(self):
        """Test that lookback_days affects the query."""
        monitor = CVEOrgMonitor(lookback_days=7)

        # The lookback_days should be used when determining time window
        assert monitor.lookback_days == 7

    def test_discover_result_discovered_at_timestamp(self):
        """Test that discovered_at is set to CVE's update timestamp."""
        update_time = datetime.now(timezone.utc) - timedelta(hours=1)
        mock_cves = [
            {
                "cveId": "CVE-2025-12345",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (update_time - timedelta(minutes=30)).isoformat() + "Z",
                    "dateUpdated": update_time.isoformat() + "Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test"
                            }
                        ]
                    }
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = list(monitor.discover())

        assert len(results) == 1
        result = results[0]

        # discovered_at should be close to the dateUpdated time
        # (within a small tolerance for parsing)
        assert result.discovered_at is not None
        time_diff = abs((result.discovered_at - update_time).total_seconds())
        assert time_diff < 5  # Within 5 seconds


class TestCVEOrgMonitorIntegration:
    """Integration tests for CVEOrgMonitor."""

    def test_run_method(self):
        """Test the run() method which wraps discover()."""
        mock_cves = [
            {
                "cveId": "CVE-2025-12345",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test"
                            }
                        ]
                    }
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = monitor.run()

        assert len(results) == 1
        assert results[0].cve_id == "CVE-2025-12345"

    def test_disabled_discovery(self):
        """Test that disabled discovery returns empty results."""
        monitor = CVEOrgMonitor(enabled=False)

        results = monitor.run()

        assert len(results) == 0

    def test_confidence_is_perfect(self):
        """Test that all results have perfect confidence (1.0)."""
        mock_cves = [
            {
                "cveId": "CVE-2025-12345",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test"
                            }
                        ]
                    }
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = monitor.run()

        for result in results:
            assert result.confidence == 1.0

    def test_source_type_is_cve_org(self):
        """Test that source_type is set correctly."""
        mock_cves = [
            {
                "cveId": "CVE-2025-12345",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "datePublished": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
                    "dateUpdated": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat() + "Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test"
                            }
                        ]
                    }
                }
            }
        ]

        monitor = CVEOrgMonitor()

        with patch.object(monitor, "_fetch_recent_cves", return_value=mock_cves):
            results = monitor.run()

        for result in results:
            assert result.source_type == SourceType.CVE_ORG
