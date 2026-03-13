"""Tests for health monitoring integration into discovery pipeline."""
import pytest
from unittest.mock import Mock, MagicMock
from datetime import datetime, timezone
from src.pipeline.orchestrator import PipelineOrchestrator
from src.monitoring.source_health import HealthStatus
from src.discovery.base import DiscoveryResult
from src.storage import DatabaseManager


class MockDiscovery:
    """Mock discovery module for testing."""

    def __init__(self, name="mock_source", fail=False, results=None):
        self.name = name
        self.source_type = "test"
        self.enabled = True
        self._fail = fail
        self._results = results or []

    def run(self):
        """Mock run method."""
        if self._fail:
            raise Exception("Mock discovery error")
        return self._results


def test_orchestrator_has_health_monitor():
    """Test that orchestrator initializes with health monitor."""
    db = Mock(spec=DatabaseManager)
    orchestrator = PipelineOrchestrator(db)

    assert hasattr(orchestrator, 'health_monitor')
    assert orchestrator.health_monitor is not None


def test_orchestrator_tracks_successful_discovery():
    """Test that orchestrator records health for successful discovery."""
    db = Mock(spec=DatabaseManager)
    db.get_statistics.return_value = {'total_ghosts': 0}

    orchestrator = PipelineOrchestrator(db)

    # Create mock discovery that succeeds
    mock_discovery = MockDiscovery(name="successful_source", results=[])

    # Run pipeline
    stats = orchestrator.run_full_pipeline([mock_discovery])

    # Check health was recorded as successful
    health = orchestrator.health_monitor.get_source_health("successful_source")
    assert health is not None
    assert health.status == HealthStatus.HEALTHY
    assert health.consecutive_failures == 0


def test_orchestrator_tracks_failed_discovery():
    """Test that orchestrator records health for failed discovery."""
    db = Mock(spec=DatabaseManager)
    db.get_statistics.return_value = {'total_ghosts': 0}

    orchestrator = PipelineOrchestrator(db)

    # Create mock discovery that fails
    mock_discovery = MockDiscovery(name="failing_source", fail=True)

    # Run pipeline (should handle exception gracefully)
    stats = orchestrator.run_full_pipeline([mock_discovery])

    # Check failure was recorded
    health = orchestrator.health_monitor.get_source_health("failing_source")
    assert health is not None
    assert health.status in [HealthStatus.DEGRADED, HealthStatus.FAILING]
    assert health.consecutive_failures > 0


def test_orchestrator_tracks_multiple_sources():
    """Test that orchestrator tracks health for multiple sources."""
    db = Mock(spec=DatabaseManager)
    db.get_statistics.return_value = {'total_ghosts': 0}

    orchestrator = PipelineOrchestrator(db)

    # Create multiple mock discoveries
    sources = [
        MockDiscovery(name="source_1"),
        MockDiscovery(name="source_2"),
        MockDiscovery(name="source_3"),
    ]

    # Run pipeline
    stats = orchestrator.run_full_pipeline(sources)

    # Check all sources were tracked
    all_health = orchestrator.health_monitor.get_all_health()
    health_names = [h.source_name for h in all_health]

    assert "source_1" in health_names
    assert "source_2" in health_names
    assert "source_3" in health_names


def test_orchestrator_measures_response_time():
    """Test that orchestrator records response times."""
    db = Mock(spec=DatabaseManager)
    db.get_statistics.return_value = {'total_ghosts': 0}

    orchestrator = PipelineOrchestrator(db)

    # Create mock discovery
    mock_discovery = MockDiscovery(name="timed_source")

    # Run pipeline
    orchestrator.run_full_pipeline([mock_discovery])

    # Check response time was recorded
    health = orchestrator.health_monitor.get_source_health("timed_source")
    assert health is not None
    assert health.avg_response_time >= 0


def test_orchestrator_continues_after_source_failure():
    """Test that pipeline continues after one source fails."""
    db = Mock(spec=DatabaseManager)
    db.get_statistics.return_value = {'total_ghosts': 0}

    orchestrator = PipelineOrchestrator(db)

    # Mix of failing and successful sources
    sources = [
        MockDiscovery(name="source_1"),
        MockDiscovery(name="failing", fail=True),
        MockDiscovery(name="source_3"),
    ]

    # Run pipeline
    stats = orchestrator.run_full_pipeline(sources)

    # Check all sources were attempted
    all_health = orchestrator.health_monitor.get_all_health()
    assert len(all_health) == 3

    # Check success sources are healthy
    health_1 = orchestrator.health_monitor.get_source_health("source_1")
    assert health_1.status == HealthStatus.HEALTHY

    # Check failed source is degraded/failing
    health_fail = orchestrator.health_monitor.get_source_health("failing")
    assert health_fail.status in [HealthStatus.DEGRADED, HealthStatus.FAILING]

    # Check subsequent source still ran
    health_3 = orchestrator.health_monitor.get_source_health("source_3")
    assert health_3.status == HealthStatus.HEALTHY


def test_health_monitor_survives_pipeline_restarts():
    """Test that health monitor maintains state across pipeline runs."""
    db = Mock(spec=DatabaseManager)
    db.get_statistics.return_value = {'total_ghosts': 0}

    orchestrator = PipelineOrchestrator(db)

    # First run
    sources_1 = [MockDiscovery(name="persistent_source")]
    orchestrator.run_full_pipeline(sources_1)

    health_1 = orchestrator.health_monitor.get_source_health("persistent_source")
    assert health_1.consecutive_failures == 0

    # Second run
    sources_2 = [MockDiscovery(name="persistent_source")]
    orchestrator.run_full_pipeline(sources_2)

    # Health should still be tracked
    health_2 = orchestrator.health_monitor.get_source_health("persistent_source")
    assert health_2 is not None
    assert health_2.consecutive_failures == 0


def test_failing_sources_list():
    """Test retrieving list of failing sources from orchestrator."""
    db = Mock(spec=DatabaseManager)
    db.get_statistics.return_value = {'total_ghosts': 0}

    orchestrator = PipelineOrchestrator(db)

    # Create mix of sources with different failure counts
    healthy = MockDiscovery(name="healthy_source")
    failing = MockDiscovery(name="failing_source", fail=True)

    # Run failing source multiple times to accumulate failures
    for i in range(6):
        try:
            orchestrator.run_full_pipeline([failing])
        except:
            pass

    # Run healthy source
    orchestrator.run_full_pipeline([healthy])

    # Get failing sources
    failing_sources = orchestrator.health_monitor.get_failing_sources()
    failing_names = [s.source_name for s in failing_sources]

    assert "failing_source" in failing_names
    assert "healthy_source" not in failing_names
