"""
Tests for Discovery Modules
===========================

Unit tests for the discovery base class and discovery result dataclass.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from src.discovery.base import (
    BaseDiscovery,
    DiscoveryResult,
    DiscoveryError,
    RateLimiter,
)


class TestDiscoveryResult:
    """Tests for DiscoveryResult dataclass."""
    
    def test_creation(self):
        """Test DiscoveryResult creation."""
        result = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        assert result.cve_id == "CVE-2025-12345"
        assert result.source_type == "github_commit"
        assert result.discovered_at is not None
    
    def test_cve_id_normalization(self):
        """Test that CVE ID is normalized to uppercase."""
        result = DiscoveryResult(
            cve_id="cve-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        assert result.cve_id == "CVE-2025-12345"
    
    def test_hash(self):
        """Test that DiscoveryResult is hashable."""
        result1 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        result2 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        # Same CVE and URL should have same hash
        assert hash(result1) == hash(result2)
        
        # Should be usable in a set
        results_set = {result1, result2}
        assert len(results_set) == 1
    
    def test_equality(self):
        """Test DiscoveryResult equality."""
        result1 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        result2 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="rss_feed",  # Different source type
            source_name="Security Blog",
            evidence_url="https://github.com/test/repo",  # Same URL
        )
        
        result3 = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://other.example.com",  # Different URL
        )
        
        # Same CVE and URL = equal
        assert result1 == result2
        
        # Different URL = not equal
        assert result1 != result3
    
    def test_confidence_default(self):
        """Test default confidence score."""
        result = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="Test Repository",
            evidence_url="https://github.com/test/repo",
        )
        
        assert result.confidence == 1.0


class TestRateLimiter:
    """Tests for RateLimiter class."""
    
    def test_acquire_under_limit(self):
        """Test acquiring when under rate limit."""
        limiter = RateLimiter(requests_per_window=10, window_seconds=60)
        
        # First request should be immediate
        wait_time = limiter.acquire()
        assert wait_time == 0.0
    
    def test_acquire_at_limit(self):
        """Test acquiring when at rate limit."""
        limiter = RateLimiter(requests_per_window=2, window_seconds=60)
        
        # First two requests should be immediate
        limiter.acquire()
        limiter.acquire()
        
        # Third request should require waiting
        wait_time = limiter.acquire()
        assert wait_time > 0
    
    def test_reset(self):
        """Test rate limiter reset."""
        limiter = RateLimiter(requests_per_window=1, window_seconds=60)
        
        limiter.acquire()
        # At limit now
        
        limiter.reset()
        
        # Should be able to acquire immediately
        wait_time = limiter.acquire()
        assert wait_time == 0.0


class TestDiscoveryError:
    """Tests for DiscoveryError exception."""
    
    def test_creation(self):
        """Test DiscoveryError creation."""
        error = DiscoveryError(
            module_name="TestModule",
            message="Test error message",
        )
        
        assert error.module_name == "TestModule"
        assert error.message == "Test error message"
        assert "[TestModule]" in str(error)
    
    def test_with_original_error(self):
        """Test DiscoveryError wrapping another exception."""
        original = ValueError("Original error")
        
        error = DiscoveryError(
            module_name="TestModule",
            message="Wrapped error",
            original_error=original,
        )
        
        assert error.original_error == original


class ConcreteDiscovery(BaseDiscovery):
    """Concrete implementation for testing BaseDiscovery."""
    
    def __init__(self, results_to_return=None):
        super().__init__(
            name="Test Discovery",
            source_type="test",
            enabled=True,
        )
        self._results_to_return = results_to_return or []
    
    def discover(self):
        for result in self._results_to_return:
            yield result


class TestBaseDiscovery:
    """Tests for BaseDiscovery abstract class."""
    
    def test_initialization(self):
        """Test BaseDiscovery initialization."""
        discovery = ConcreteDiscovery()
        
        assert discovery.name == "Test Discovery"
        assert discovery.source_type == "test"
        assert discovery.enabled is True
    
    def test_run_returns_results(self):
        """Test that run() returns discovery results."""
        test_results = [
            DiscoveryResult(
                cve_id="CVE-2025-12345",
                source_type="test",
                source_name="Test",
                evidence_url="https://example.com",
            ),
        ]
        
        discovery = ConcreteDiscovery(results_to_return=test_results)
        results = discovery.run()
        
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2025-12345"
    
    def test_run_when_disabled(self):
        """Test that run() returns empty when disabled."""
        discovery = ConcreteDiscovery()
        discovery.enabled = False
        
        results = discovery.run()
        
        assert len(results) == 0
    
    def test_results_property(self):
        """Test results property."""
        test_results = [
            DiscoveryResult(
                cve_id="CVE-2025-12345",
                source_type="test",
                source_name="Test",
                evidence_url="https://example.com",
            ),
        ]
        
        discovery = ConcreteDiscovery(results_to_return=test_results)
        discovery.run()
        
        # results property should return a copy
        results = discovery.results
        assert len(results) == 1
        
        # Modifying the copy shouldn't affect internal state
        results.append(Mock())
        assert len(discovery.results) == 1
    
    def test_repr(self):
        """Test string representation."""
        discovery = ConcreteDiscovery()
        
        repr_str = repr(discovery)
        
        assert "Test Discovery" in repr_str
        assert "enabled=True" in repr_str
