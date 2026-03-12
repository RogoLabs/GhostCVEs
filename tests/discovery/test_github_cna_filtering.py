"""
Tests for GitHub CNA filtering in GitHub Advisory Discovery.

Verifies that CVEs assigned by GitHub's CNA (GitHub_M) are detected
and given higher confidence scores.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone
from src.discovery.github_advisory_discovery import GitHubAdvisoryDiscovery


class TestGitHubCNADetection:
    """Tests for detecting GitHub CNA (GitHub_M) assignments."""

    def test_is_github_cna_assignment_npm(self):
        """Test that NPM packages are detected as GitHub CNA."""
        discovery = GitHubAdvisoryDiscovery(token="fake_token")

        affected_packages = [
            {"name": "express", "ecosystem": "NPM", "vulnerable_range": "< 4.17.3"}
        ]

        assert discovery._is_github_cna_assignment(affected_packages, "GHSA-xxxx") is True

    def test_is_github_cna_assignment_pypi(self):
        """Test that PyPI packages are detected as GitHub CNA."""
        discovery = GitHubAdvisoryDiscovery(token="fake_token")

        affected_packages = [
            {"name": "django", "ecosystem": "PIP", "vulnerable_range": "< 4.0.1"}
        ]

        assert discovery._is_github_cna_assignment(affected_packages, "GHSA-yyyy") is True

    def test_is_github_cna_assignment_rubygems(self):
        """Test that RubyGems packages are detected as GitHub CNA."""
        discovery = GitHubAdvisoryDiscovery(token="fake_token")

        affected_packages = [
            {"name": "rails", "ecosystem": "RUBYGEMS", "vulnerable_range": "< 7.0.0"}
        ]

        assert discovery._is_github_cna_assignment(affected_packages, "GHSA-zzzz") is True

    def test_is_not_github_cna_assignment(self):
        """Test that non-GitHub CNA ecosystems are not detected."""
        discovery = GitHubAdvisoryDiscovery(token="fake_token")

        # Package from non-GitHub CNA ecosystem (e.g., Debian, Red Hat)
        affected_packages = [
            {"name": "linux-kernel", "ecosystem": "DEBIAN", "vulnerable_range": "< 5.10"}
        ]

        assert discovery._is_github_cna_assignment(affected_packages, "GHSA-aaaa") is False

    def test_is_github_cna_multiple_ecosystems(self):
        """Test with multiple packages, some in GitHub CNA ecosystems."""
        discovery = GitHubAdvisoryDiscovery(token="fake_token")

        affected_packages = [
            {"name": "lodash", "ecosystem": "NPM", "vulnerable_range": "< 4.17.20"},
            {"name": "some-debian-pkg", "ecosystem": "DEBIAN", "vulnerable_range": "< 1.0"}
        ]

        # Should return True if ANY package is in GitHub CNA ecosystem
        assert discovery._is_github_cna_assignment(affected_packages, "GHSA-bbbb") is True

    def test_is_github_cna_case_insensitive(self):
        """Test that ecosystem detection is case-insensitive."""
        discovery = GitHubAdvisoryDiscovery(token="fake_token")

        affected_packages = [
            {"name": "package", "ecosystem": "npm", "vulnerable_range": "< 1.0"}  # lowercase
        ]

        assert discovery._is_github_cna_assignment(affected_packages, "GHSA-cccc") is True


class TestGitHubCNAConfidenceBoost:
    """Tests for confidence boost applied to GitHub CNA assignments."""

    @patch('src.discovery.github_advisory_discovery.requests.Session')
    def test_github_cna_has_higher_confidence(self, mock_session_class):
        """Test that GitHub CNA assignments get confidence boost."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock GraphQL response with GitHub CNA advisory (NPM package)
        graphql_response = Mock()
        graphql_response.status_code = 200
        graphql_response.json.return_value = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-test-1234",
                                "cveIds": ["CVE-2025-12345"],
                                "summary": "Test vulnerability in express",
                                "description": "Detailed description",
                                "severity": "HIGH",
                                "publishedAt": "2025-03-01T00:00:00Z",
                                "updatedAt": "2025-03-01T00:00:00Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "express",
                                                    "ecosystem": "NPM"
                                                },
                                                "vulnerableVersionRange": "< 4.17.3",
                                                "firstPatchedVersion": {"identifier": "4.17.3"}
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
        mock_session.post.return_value = graphql_response

        discovery = GitHubAdvisoryDiscovery(token="fake_token")
        results = list(discovery.discover())

        assert len(results) == 1
        result = results[0]

        # GitHub CNA assignments should have confidence of 0.93
        assert result.confidence == 0.93
        assert result.raw_data["is_github_cna"] is True
        assert "[GitHub CNA]" in result.context

    @patch('src.discovery.github_advisory_discovery.requests.Session')
    def test_non_github_cna_has_normal_confidence(self, mock_session_class):
        """Test that non-GitHub CNA advisories have normal confidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock GraphQL response with non-GitHub CNA advisory
        graphql_response = Mock()
        graphql_response.status_code = 200
        graphql_response.json.return_value = {
            "data": {
                "securityAdvisories": {
                    "edges": [
                        {
                            "node": {
                                "ghsaId": "GHSA-test-5678",
                                "cveIds": ["CVE-2025-23456"],
                                "summary": "Test vulnerability in system package",
                                "description": "Detailed description",
                                "severity": "CRITICAL",
                                "publishedAt": "2025-03-01T00:00:00Z",
                                "updatedAt": "2025-03-01T00:00:00Z",
                                "vulnerabilities": {
                                    "edges": [
                                        {
                                            "node": {
                                                "package": {
                                                    "name": "linux-kernel",
                                                    "ecosystem": "LINUX"
                                                },
                                                "vulnerableVersionRange": "< 5.10",
                                                "firstPatchedVersion": {"identifier": "5.10"}
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
        mock_session.post.return_value = graphql_response

        discovery = GitHubAdvisoryDiscovery(token="fake_token")
        results = list(discovery.discover())

        assert len(results) == 1
        result = results[0]

        # Non-GitHub CNA assignments should have confidence of 0.90
        assert result.confidence == 0.90
        assert result.raw_data["is_github_cna"] is False
        assert "[GitHub CNA]" not in result.context

    def test_github_cna_ecosystems_coverage(self):
        """Test that all major GitHub CNA ecosystems are recognized."""
        discovery = GitHubAdvisoryDiscovery(token="fake_token")

        github_ecosystems = [
            "NPM", "RUBYGEMS", "PYPI", "MAVEN", "NUGET",
            "COMPOSER", "GO", "RUST", "PIP", "CARGO"
        ]

        for ecosystem in github_ecosystems:
            affected_packages = [
                {"name": "test-package", "ecosystem": ecosystem}
            ]
            assert discovery._is_github_cna_assignment(affected_packages, "GHSA-test") is True, \
                f"Failed to detect GitHub CNA for ecosystem: {ecosystem}"
