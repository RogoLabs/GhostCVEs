"""
Tests for GitHub Security Advisories Discovery Module
=======================================================

Unit tests for the GitHubAdvisoryDiscovery class that queries the
GitHub Security Advisories Database via GraphQL API.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import json

from src.discovery.github_advisory_discovery import GitHubAdvisoryDiscovery
from src.discovery.base import DiscoveryResult, DiscoveryError
from src.config import SourceType


class TestGitHubAdvisoryDiscovery:
    """Tests for GitHubAdvisoryDiscovery class."""

    def test_initialization(self):
        """Test GitHubAdvisoryDiscovery initialization."""
        discovery = GitHubAdvisoryDiscovery(token="test-token")

        assert discovery.name == "GitHub Security Advisories"
        assert discovery.source_type == SourceType.GITHUB_ADVISORY
        assert discovery.enabled is True
        assert discovery.token == "test-token"

    def test_initialization_with_env_token(self):
        """Test initialization reads token from environment."""
        with patch.dict("os.environ", {"GITHUB_TOKEN": "env-token"}):
            discovery = GitHubAdvisoryDiscovery()
            assert discovery.token == "env-token"

    def test_initialization_disabled(self):
        """Test initialization with disabled flag."""
        discovery = GitHubAdvisoryDiscovery(token="test-token", enabled=False)
        assert discovery.enabled is False

    def test_discover_single_advisory_single_cve(self):
        """Test discovering a single advisory with one CVE."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": ["CVE-2025-12345"],
                                "summary": "Critical vulnerability in test package",
                                "description": "A detailed description of the vulnerability",
                                "severity": "CRITICAL",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "test-package",
                                                    "ecosystem": "PIP"
                                                },
                                                "vulnerableVersionRange": ">= 1.0, < 2.0",
                                                "firstPatchedVersion": {
                                                    "identifier": "2.0"
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = list(discovery.discover())

        assert len(results) == 1
        result = results[0]
        assert result.cve_id == "CVE-2025-12345"
        assert result.source_type == SourceType.GITHUB_ADVISORY
        assert result.source_name == "GitHub Security Advisories"
        assert result.confidence == 0.90
        assert "test-package" in result.context
        assert "CRITICAL" in result.context

    def test_discover_advisory_multiple_cves(self):
        """Test discovering a single advisory with multiple CVEs."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": ["CVE-2025-12345", "CVE-2025-12346"],
                                "summary": "Multiple CVEs in package",
                                "description": "Multiple vulnerabilities",
                                "severity": "HIGH",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "test-package",
                                                    "ecosystem": "NPM"
                                                },
                                                "vulnerableVersionRange": "< 3.0.0",
                                                "firstPatchedVersion": None
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = list(discovery.discover())

        # Should yield one result per CVE
        assert len(results) == 2
        cve_ids = {r.cve_id for r in results}
        assert cve_ids == {"CVE-2025-12345", "CVE-2025-12346"}

        # All should have same source/confidence
        for result in results:
            assert result.source_type == SourceType.GITHUB_ADVISORY
            assert result.confidence == 0.90

    def test_discover_multiple_packages_in_advisory(self):
        """Test advisory with multiple affected packages."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": ["CVE-2025-12345"],
                                "summary": "Affects multiple packages",
                                "description": "Multiple packages affected",
                                "severity": "MEDIUM",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "package-one",
                                                    "ecosystem": "PIP"
                                                },
                                                "vulnerableVersionRange": "< 1.5.0",
                                                "firstPatchedVersion": {"identifier": "1.5.0"}
                                            }
                                        },
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "package-two",
                                                    "ecosystem": "MAVEN"
                                                },
                                                "vulnerableVersionRange": ">= 2.0, < 2.1.0",
                                                "firstPatchedVersion": {"identifier": "2.1.0"}
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = list(discovery.discover())

        assert len(results) == 1
        result = results[0]
        # Context should include affected packages
        assert "package-one" in result.context
        assert "package-two" in result.context

    def test_discover_handles_api_error(self):
        """Test that API errors are handled properly."""
        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", side_effect=Exception("API Error")):
            with pytest.raises(DiscoveryError):
                list(discovery.discover())

    def test_discover_skips_advisories_without_cves(self):
        """Test that advisories without CVE IDs are skipped."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": [],  # No CVEs
                                "summary": "No CVE advisory",
                                "description": "Advisory without CVE",
                                "severity": "LOW",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": []
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = list(discovery.discover())

        # Should not yield any results
        assert len(results) == 0

    def test_graphql_query_construction(self):
        """Test that GraphQL query is properly constructed."""
        discovery = GitHubAdvisoryDiscovery(token="test-token")

        # Mock the session.post to capture the query
        with patch.object(discovery.session, "post") as mock_post:
            mock_post.return_value = Mock(
                status_code=200,
                json=lambda: {"data": {"securityAdvisories": {"edges": []}}}
            )

            try:
                list(discovery.discover())
            except:
                pass  # We're just interested in the query being sent

            # Verify post was called with GraphQL endpoint
            assert mock_post.called
            call_args = mock_post.call_args
            assert "api.github.com/graphql" in call_args[0][0]

            # Check that the request body contains a query
            request_body = json.loads(call_args[1]["data"])
            assert "query" in request_body
            assert "securityAdvisories" in request_body["query"]

    def test_session_headers_include_token(self):
        """Test that session headers include authorization."""
        discovery = GitHubAdvisoryDiscovery(token="test-token-123")

        assert "Authorization" in discovery.session.headers
        assert discovery.session.headers["Authorization"] == "Bearer test-token-123"

    def test_session_headers_without_token(self):
        """Test session creation without token."""
        with patch.dict("os.environ", {"GITHUB_TOKEN": ""}):
            discovery = GitHubAdvisoryDiscovery(token="")

            # Session should be created but without auth header
            assert discovery.session is not None
            # Auth header might not be set or might be empty

    def test_discovery_result_raw_data(self):
        """Test that raw_data contains advisory metadata."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": ["CVE-2025-12345"],
                                "summary": "Test vulnerability",
                                "description": "Detailed description",
                                "severity": "CRITICAL",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "test-package",
                                                    "ecosystem": "PIP"
                                                },
                                                "vulnerableVersionRange": ">= 1.0, < 2.0",
                                                "firstPatchedVersion": {"identifier": "2.0"}
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = list(discovery.discover())

        assert len(results) == 1
        result = results[0]

        # Verify raw_data contains important metadata
        assert result.raw_data is not None
        assert result.raw_data.get("ghsa_id") == "GHSA-1234-5678-9abc"
        assert result.raw_data.get("severity") == "CRITICAL"
        affected_packages = result.raw_data.get("affected_packages", [])
        assert len(affected_packages) > 0
        assert any(pkg["name"] == "test-package" for pkg in affected_packages)

    def test_discovery_result_evidence_url(self):
        """Test that evidence_url points to GitHub advisory."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": ["CVE-2025-12345"],
                                "summary": "Test",
                                "description": "Test",
                                "severity": "MEDIUM",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "test-package",
                                                    "ecosystem": "PIP"
                                                },
                                                "vulnerableVersionRange": ">= 1.0, < 2.0",
                                                "firstPatchedVersion": None
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = list(discovery.discover())

        assert len(results) == 1
        result = results[0]

        # Evidence URL should point to GitHub advisory database
        assert "github.com/advisories/GHSA-1234-5678-9abc" in result.evidence_url

    def test_discovery_result_context_with_severity(self):
        """Test that context includes severity and package information."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": ["CVE-2025-12345"],
                                "summary": "Buffer overflow",
                                "description": "A buffer overflow in processing",
                                "severity": "CRITICAL",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "vulnerable-lib",
                                                    "ecosystem": "MAVEN"
                                                },
                                                "vulnerableVersionRange": "< 3.0.0",
                                                "firstPatchedVersion": {"identifier": "3.0.0"}
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = list(discovery.discover())

        assert len(results) == 1
        result = results[0]

        # Context should mention severity and package
        context = result.context.lower()
        assert "critical" in context
        assert "vulnerable-lib" in context


class TestGitHubAdvisoryDiscoveryIntegration:
    """Integration-style tests for GitHubAdvisoryDiscovery."""

    def test_run_method(self):
        """Test the run() method which wraps discover()."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-1234-5678-9abc",
                                "cveIds": ["CVE-2025-12345"],
                                "summary": "Test",
                                "description": "Test",
                                "severity": "HIGH",
                                "publishedAt": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z",
                                "updatedAt": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "test-package",
                                                    "ecosystem": "PIP"
                                                },
                                                "vulnerableVersionRange": ">= 1.0, < 2.0",
                                                "firstPatchedVersion": None
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }

        discovery = GitHubAdvisoryDiscovery(token="test-token")

        with patch.object(discovery, "_query_graphql", return_value=mock_response):
            results = discovery.run()

        assert len(results) == 1
        assert results[0].cve_id == "CVE-2025-12345"

    def test_disabled_discovery(self):
        """Test that disabled discovery returns empty results."""
        discovery = GitHubAdvisoryDiscovery(token="test-token", enabled=False)

        results = discovery.run()

        assert len(results) == 0
