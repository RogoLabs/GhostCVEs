"""Tests for source health monitoring."""
import pytest
from datetime import datetime, timedelta, timezone
from src.monitoring.source_health import (
    SourceHealth,
    SourceHealthMonitor,
    HealthStatus
)


def test_source_health_creation():
    """Test creating SourceHealth instance."""
    health = SourceHealth(
        source_name="test_source",
        status=HealthStatus.HEALTHY,
        consecutive_failures=0,
        last_success=datetime.now(timezone.utc),
        error_rate_24h=0.02,
        avg_response_time=2.5,
        last_error=None
    )

    assert health.source_name == "test_source"
    assert health.status == HealthStatus.HEALTHY


def test_health_monitor_record_success():
    """Test recording successful fetch."""
    monitor = SourceHealthMonitor()

    monitor.record_success("test_source", response_time=2.0)

    health = monitor.get_source_health("test_source")
    assert health.status == HealthStatus.HEALTHY
    assert health.consecutive_failures == 0
    assert health.last_success is not None


def test_health_monitor_record_failure():
    """Test recording failed fetch."""
    monitor = SourceHealthMonitor()

    # Record multiple failures
    for i in range(3):
        monitor.record_failure("test_source", Exception("Connection timeout"))

    health = monitor.get_source_health("test_source")
    assert health.status == HealthStatus.DEGRADED
    assert health.consecutive_failures == 3
    assert health.last_error == "Connection timeout"


def test_failing_status_after_many_failures():
    """Test source marked as failing after many failures."""
    monitor = SourceHealthMonitor()

    # Record 6 failures
    for i in range(6):
        monitor.record_failure("test_source", Exception("Error"))

    health = monitor.get_source_health("test_source")
    assert health.status == HealthStatus.FAILING
    assert health.consecutive_failures == 6


def test_recovery_after_failures():
    """Test that source recovers after successful fetch."""
    monitor = SourceHealthMonitor()

    # Record failures
    for i in range(4):
        monitor.record_failure("test_source", Exception("Error"))

    health = monitor.get_source_health("test_source")
    assert health.status == HealthStatus.DEGRADED

    # Record success
    monitor.record_success("test_source", response_time=1.5)

    health = monitor.get_source_health("test_source")
    assert health.status == HealthStatus.HEALTHY
    assert health.consecutive_failures == 0


def test_get_failing_sources():
    """Test retrieving all failing sources."""
    monitor = SourceHealthMonitor()

    # Create failing sources
    for i in range(6):
        monitor.record_failure("failing_source_1", Exception("Error"))
        monitor.record_failure("failing_source_2", Exception("Error"))

    # Create healthy source
    monitor.record_success("healthy_source", response_time=1.0)

    failing = monitor.get_failing_sources()
    failing_names = [s.source_name for s in failing]

    assert len(failing) == 2
    assert "failing_source_1" in failing_names
    assert "failing_source_2" in failing_names
    assert "healthy_source" not in failing_names


def test_get_degraded_sources():
    """Test retrieving degraded sources."""
    monitor = SourceHealthMonitor()

    # Create degraded source (3-4 failures)
    for i in range(3):
        monitor.record_failure("degraded_source", Exception("Error"))

    # Create healthy source
    monitor.record_success("healthy_source", response_time=1.0)

    degraded = monitor.get_degraded_sources()
    degraded_names = [s.source_name for s in degraded]

    assert len(degraded) == 1
    assert "degraded_source" in degraded_names
    assert "healthy_source" not in degraded_names


def test_avg_response_time_calculation():
    """Test exponential moving average for response time."""
    monitor = SourceHealthMonitor()

    # Record multiple successes with different response times
    monitor.record_success("test_source", response_time=1.0)
    monitor.record_success("test_source", response_time=2.0)
    monitor.record_success("test_source", response_time=3.0)

    health = monitor.get_source_health("test_source")

    # EMA should be between 1.0 and 3.0
    assert 1.0 < health.avg_response_time < 3.0


def test_error_rate_24h():
    """Test 24-hour error rate calculation."""
    monitor = SourceHealthMonitor()

    # Record mix of successes and failures
    monitor.record_success("test_source", response_time=1.0)
    monitor.record_success("test_source", response_time=1.0)
    monitor.record_failure("test_source", Exception("Error"))

    health = monitor.get_source_health("test_source")

    # Should be ~33% error rate (1 failure out of 3 fetches)
    assert 0.2 < health.error_rate_24h < 0.5


def test_get_all_health():
    """Test retrieving health for all sources."""
    monitor = SourceHealthMonitor()

    # Create multiple sources
    monitor.record_success("source_1", response_time=1.0)
    monitor.record_success("source_2", response_time=2.0)
    monitor.record_failure("source_3", Exception("Error"))

    all_health = monitor.get_all_health()

    assert len(all_health) == 3
    source_names = [h.source_name for h in all_health]
    assert "source_1" in source_names
    assert "source_2" in source_names
    assert "source_3" in source_names


def test_unknown_source_returns_none():
    """Test that getting health for unknown source returns None."""
    monitor = SourceHealthMonitor()

    health = monitor.get_source_health("nonexistent_source")
    assert health is None


def test_health_status_enum_values():
    """Test that HealthStatus enum has correct values."""
    assert HealthStatus.HEALTHY.value == "healthy"
    assert HealthStatus.DEGRADED.value == "degraded"
    assert HealthStatus.FAILING.value == "failing"


def test_first_failure_sets_degraded():
    """Test that first failure sets status to degraded."""
    monitor = SourceHealthMonitor()

    monitor.record_failure("test_source", Exception("First failure"))

    health = monitor.get_source_health("test_source")
    assert health.status == HealthStatus.DEGRADED
    assert health.consecutive_failures == 1
