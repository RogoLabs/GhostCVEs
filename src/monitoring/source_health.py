"""
Source Health Monitoring
========================

Tracks and reports on discovery source reliability and uptime.

Monitors success/failure rates, response times, and consecutive failures
to classify sources as healthy, degraded, or failing. Provides real-time
health status and historical trend analysis for all discovery sources.

Author: rogolabs.net
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, Dict
from collections import deque
import logging

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Source health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILING = "failing"


@dataclass
class SourceHealth:
    """
    Health metrics for a discovery source.

    Attributes:
        source_name: Name of the discovery source
        status: Current health status (HEALTHY/DEGRADED/FAILING)
        consecutive_failures: Number of consecutive failures
        last_success: Timestamp of last successful fetch
        error_rate_24h: Error rate over last 24 hours (0.0-1.0)
        avg_response_time: Average response time in seconds
        last_error: Most recent error message
    """

    source_name: str
    status: HealthStatus
    consecutive_failures: int
    last_success: Optional[datetime]
    error_rate_24h: float
    avg_response_time: float
    last_error: Optional[str]


class SourceHealthMonitor:
    """
    Monitors and tracks source health in real-time.

    Maintains health status for all discovery sources, tracking successes,
    failures, and response times to identify degraded or failing sources.

    Health Status Classification:
    - HEALTHY: 0-2 consecutive failures
    - DEGRADED: 3-4 consecutive failures
    - FAILING: 5+ consecutive failures

    Attributes:
        _health_data: Dict mapping source names to SourceHealth objects
        _fetch_history: Rolling 24h history of fetches per source
    """

    def __init__(self):
        """Initialize health monitor."""
        self._health_data: Dict[str, SourceHealth] = {}
        self._fetch_history: Dict[str, deque] = {}  # Rolling 24h history

        logger.debug("SourceHealthMonitor initialized")

    def record_success(self, source_name: str, response_time: float):
        """
        Record successful fetch from a source.

        Resets consecutive failure counter and updates average response time
        using exponential moving average.

        Args:
            source_name: Name of the source
            response_time: Time taken in seconds
        """
        if source_name not in self._health_data:
            self._health_data[source_name] = SourceHealth(
                source_name=source_name,
                status=HealthStatus.HEALTHY,
                consecutive_failures=0,
                last_success=datetime.now(timezone.utc),
                error_rate_24h=0.0,
                avg_response_time=response_time,
                last_error=None
            )
        else:
            health = self._health_data[source_name]
            health.consecutive_failures = 0
            health.last_success = datetime.now(timezone.utc)
            health.status = HealthStatus.HEALTHY

            # Update average response time (exponential moving average)
            # Alpha = 0.3 weights recent values more heavily
            alpha = 0.3
            health.avg_response_time = (
                alpha * response_time +
                (1 - alpha) * health.avg_response_time
            )

        # Record in 24h history
        self._record_fetch(source_name, success=True)

        logger.debug(f"{source_name}: Recorded success ({response_time:.2f}s)")

    def record_failure(self, source_name: str, error: Exception):
        """
        Record failed fetch from a source.

        Increments consecutive failure counter and updates health status
        based on failure thresholds.

        Args:
            source_name: Name of the source
            error: Exception that caused the failure
        """
        if source_name not in self._health_data:
            self._health_data[source_name] = SourceHealth(
                source_name=source_name,
                status=HealthStatus.DEGRADED,
                consecutive_failures=1,
                last_success=None,
                error_rate_24h=1.0,
                avg_response_time=0.0,
                last_error=str(error)
            )
        else:
            health = self._health_data[source_name]
            health.consecutive_failures += 1
            health.last_error = str(error)

            # Update status based on consecutive failures
            if health.consecutive_failures >= 5:
                health.status = HealthStatus.FAILING
            elif health.consecutive_failures >= 3:
                health.status = HealthStatus.DEGRADED

        # Record in 24h history
        self._record_fetch(source_name, success=False)

        logger.warning(
            f"{source_name}: Recorded failure "
            f"({self._health_data[source_name].consecutive_failures} consecutive) - {error}"
        )

    def get_source_health(self, source_name: str) -> Optional[SourceHealth]:
        """
        Get current health status for a source.

        Args:
            source_name: Name of the source

        Returns:
            SourceHealth object or None if not tracked
        """
        return self._health_data.get(source_name)

    def get_failing_sources(self) -> list[SourceHealth]:
        """
        Get list of sources in failing state.

        Returns:
            List of SourceHealth objects for failing sources
        """
        return [
            health for health in self._health_data.values()
            if health.status == HealthStatus.FAILING
        ]

    def get_degraded_sources(self) -> list[SourceHealth]:
        """
        Get list of sources in degraded state.

        Returns:
            List of SourceHealth objects for degraded sources
        """
        return [
            health for health in self._health_data.values()
            if health.status == HealthStatus.DEGRADED
        ]

    def get_all_health(self) -> list[SourceHealth]:
        """
        Get health status for all tracked sources.

        Returns:
            List of all SourceHealth objects
        """
        return list(self._health_data.values())

    def _record_fetch(self, source_name: str, success: bool):
        """
        Record fetch in 24h rolling history.

        Args:
            source_name: Name of the source
            success: Whether the fetch succeeded
        """
        if source_name not in self._fetch_history:
            self._fetch_history[source_name] = deque(maxlen=100)

        self._fetch_history[source_name].append({
            'timestamp': datetime.now(timezone.utc),
            'success': success
        })

        # Recalculate 24h error rate
        self._update_error_rate(source_name)

    def _update_error_rate(self, source_name: str):
        """
        Update 24h error rate for a source.

        Calculates error rate based on fetches within the last 24 hours.

        Args:
            source_name: Name of the source
        """
        if source_name not in self._fetch_history:
            return

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_fetches = [
            f for f in self._fetch_history[source_name]
            if f['timestamp'] > cutoff
        ]

        if not recent_fetches:
            return

        failures = sum(1 for f in recent_fetches if not f['success'])
        error_rate = failures / len(recent_fetches)

        if source_name in self._health_data:
            self._health_data[source_name].error_rate_24h = error_rate
