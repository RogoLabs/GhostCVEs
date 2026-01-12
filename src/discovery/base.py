"""
Base Discovery Module
=====================

Abstract base class and common data structures for all discovery modules.
Provides consistent interface for CVE identification across different sources.

Author: rogolabs.net
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator
import logging


logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    """
    Represents a single CVE discovery from any source.
    
    Attributes:
        cve_id: The CVE identifier (e.g., CVE-2025-12345)
        source_type: Classification of the source (github_commit, rss_feed, etc.)
        source_name: Human-readable name of the source
        evidence_url: Direct URL to the evidence of the CVE mention
        discovered_at: Timestamp when this discovery was made
        context: Optional surrounding text/context of the CVE mention
        confidence: Confidence score (0.0-1.0) of the discovery validity
        raw_data: Optional raw data from the source for debugging
    """
    cve_id: str
    source_type: str
    source_name: str
    evidence_url: str
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    context: str | None = None
    confidence: float = 1.0
    raw_data: dict | None = None
    
    def __post_init__(self) -> None:
        """Normalize CVE ID to uppercase."""
        self.cve_id = self.cve_id.upper()
    
    def __hash__(self) -> int:
        """Hash based on CVE ID and evidence URL for deduplication."""
        return hash((self.cve_id, self.evidence_url))
    
    def __eq__(self, other: object) -> bool:
        """Equality based on CVE ID and evidence URL."""
        if not isinstance(other, DiscoveryResult):
            return NotImplemented
        return self.cve_id == other.cve_id and self.evidence_url == other.evidence_url


class BaseDiscovery(ABC):
    """
    Abstract base class for all discovery modules.
    
    Provides common interface and utilities for discovering CVE mentions
    across various sources. Subclasses must implement the `discover` method.
    
    Attributes:
        name: Human-readable name of the discovery module
        source_type: Classification of the source type
        enabled: Whether this discovery module is active
    """
    
    def __init__(
        self,
        name: str,
        source_type: str,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the discovery module.
        
        Args:
            name: Human-readable name of the discovery module
            source_type: Classification of the source type
            enabled: Whether this discovery module is active
        """
        self.name = name
        self.source_type = source_type
        self.enabled = enabled
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._results: list[DiscoveryResult] = []
    
    @abstractmethod
    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Execute the discovery process and yield results.
        
        This method should be implemented by all subclasses to perform
        the actual discovery logic for their specific source.
        
        Yields:
            DiscoveryResult objects for each CVE mention found
        
        Raises:
            DiscoveryError: If the discovery process fails
        """
        pass
    
    def run(self) -> list[DiscoveryResult]:
        """
        Execute discovery and return all results as a list.
        
        This is a convenience wrapper around `discover()` that collects
        all results and handles common error cases.
        
        Returns:
            List of DiscoveryResult objects
        """
        if not self.enabled:
            self.logger.info(f"Discovery module '{self.name}' is disabled, skipping")
            return []
        
        self.logger.info(f"Starting discovery: {self.name}")
        self._results = []
        
        try:
            for result in self.discover():
                self._results.append(result)
                self.logger.debug(
                    f"Found {result.cve_id} in {result.source_name}"
                )
        except Exception as e:
            self.logger.error(
                f"Discovery failed for {self.name}: {e}",
                exc_info=True
            )
        
        self.logger.info(
            f"Discovery complete: {self.name} - Found {len(self._results)} CVE mentions"
        )
        return self._results
    
    @property
    def results(self) -> list[DiscoveryResult]:
        """Return the results from the last discovery run."""
        return self._results.copy()
    
    def __repr__(self) -> str:
        """String representation of the discovery module."""
        return (
            f"{self.__class__.__name__}("
            f"name='{self.name}', "
            f"source_type='{self.source_type}', "
            f"enabled={self.enabled})"
        )


class DiscoveryError(Exception):
    """
    Custom exception for discovery-related errors.
    
    Attributes:
        module_name: Name of the discovery module that raised the error
        message: Error description
        original_error: The original exception if this wraps another error
    """
    
    def __init__(
        self,
        module_name: str,
        message: str,
        original_error: Exception | None = None,
    ) -> None:
        """
        Initialize the discovery error.
        
        Args:
            module_name: Name of the discovery module
            message: Error description
            original_error: Optional original exception
        """
        self.module_name = module_name
        self.message = message
        self.original_error = original_error
        super().__init__(f"[{module_name}] {message}")


class RateLimiter:
    """
    Simple rate limiter for API requests.
    
    Tracks request timestamps and enforces rate limits to avoid
    hitting API restrictions.
    """
    
    def __init__(self, requests_per_window: int, window_seconds: int) -> None:
        """
        Initialize the rate limiter.
        
        Args:
            requests_per_window: Maximum requests allowed in the window
            window_seconds: Size of the rate limit window in seconds
        """
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self._request_times: list[datetime] = []
    
    def acquire(self) -> float:
        """
        Acquire permission to make a request.
        
        Returns:
            Number of seconds to wait before making the request (0 if immediate)
        """
        now = datetime.utcnow()
        window_start = now.timestamp() - self.window_seconds
        
        # Remove old request timestamps
        self._request_times = [
            t for t in self._request_times
            if t.timestamp() > window_start
        ]
        
        if len(self._request_times) < self.requests_per_window:
            self._request_times.append(now)
            return 0.0
        
        # Calculate wait time
        oldest = min(self._request_times)
        wait_time = (oldest.timestamp() + self.window_seconds) - now.timestamp()
        return max(0.0, wait_time)
    
    def reset(self) -> None:
        """Reset the rate limiter state."""
        self._request_times = []
