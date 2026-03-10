"""
Tests for Pipeline Orchestrator
================================

Tests the complete pipeline integration that coordinates discovery,
validation, and storage of Ghost CVE detections.

Author: rogolabs.net
"""

import unittest
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch, call

from src.discovery.base import DiscoveryResult, BaseDiscovery
from src.registry.validator import ValidationResult, CVEStatus
from src.storage.models import GhostCVE
from src.pipeline.orchestrator import (
    PipelineOrchestrator,
    PipelineStats,
    ProcessedCVE,
)


class MockDiscovery(BaseDiscovery):
    """Mock discovery source for testing."""

    def __init__(self, results=None, name="Mock Discovery"):
        super().__init__(name=name, source_type="mock")
        self._mock_results = results or []

    def discover(self):
        """Yield mock results."""
        for result in self._mock_results:
            yield result


class TestPipelineOrchestrator(unittest.TestCase):
    """Test cases for PipelineOrchestrator."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_db = Mock()
        self.orchestrator = PipelineOrchestrator(self.mock_db)

    def test_initialization(self):
        """Test orchestrator initializes with required components."""
        self.assertIsNotNone(self.orchestrator.db)
        self.assertIsNotNone(self.orchestrator.validator)
        self.assertEqual(self.orchestrator.db, self.mock_db)

    def test_process_discovery_new_ghost(self):
        """Test processing a discovery that results in a new Ghost CVE."""
        # Create mock discovery result
        discovery = DiscoveryResult(
            cve_id="CVE-2025-12345",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/abc123",
            discovered_at=datetime(2025, 1, 15, 10, 0, 0),
            confidence=0.95,
        )

        # Mock validation result (RESERVED = Ghost)
        mock_validation = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="LOCAL",
        )

        # Mock database response
        mock_ghost_cve = Mock(spec=GhostCVE)
        mock_ghost_cve.cve_id = "CVE-2025-12345"
        mock_ghost_cve.is_ghost = True
        mock_ghost_cve.first_seen = datetime(2025, 1, 15, 10, 0, 0)

        # Set up mocks
        with patch.object(self.orchestrator.validator, 'validate', return_value=mock_validation):
            self.mock_db.record_discovery.return_value = mock_ghost_cve

            # Process discovery
            result = self.orchestrator.process_discovery(discovery)

            # Verify result
            self.assertIsNotNone(result)
            self.assertEqual(result.cve_id, "CVE-2025-12345")
            self.assertTrue(result.is_ghost)

            # Verify validator was called
            self.orchestrator.validator.validate.assert_called_once_with(
                "CVE-2025-12345",
                found_in_wild=True
            )

            # Verify database was called
            self.mock_db.record_discovery.assert_called_once()

    def test_process_discovery_published_cve(self):
        """Test processing a discovery for a published (non-ghost) CVE."""
        discovery = DiscoveryResult(
            cve_id="CVE-2024-99999",
            source_type="rss_feed",
            source_name="Security Feed",
            evidence_url="https://example.com/feed",
            confidence=0.9,
        )

        # Mock validation result (PUBLISHED = Not a Ghost)
        mock_validation = ValidationResult(
            cve_id="CVE-2024-99999",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="NVD_LOCAL",
            description="Some vulnerability",
        )

        mock_ghost_cve = Mock(spec=GhostCVE)
        mock_ghost_cve.cve_id = "CVE-2024-99999"
        mock_ghost_cve.is_ghost = False

        with patch.object(self.orchestrator.validator, 'validate', return_value=mock_validation):
            self.mock_db.record_discovery.return_value = mock_ghost_cve

            result = self.orchestrator.process_discovery(discovery)

            self.assertIsNotNone(result)
            self.assertEqual(result.cve_id, "CVE-2024-99999")
            self.assertFalse(result.is_ghost)

    def test_process_discovery_handles_errors(self):
        """Test that processing handles errors gracefully."""
        discovery = DiscoveryResult(
            cve_id="CVE-2025-00001",
            source_type="github_commit",
            source_name="test/repo",
            evidence_url="https://github.com/test/repo/commit/xyz",
        )

        # Mock validator to raise exception
        with patch.object(self.orchestrator.validator, 'validate', side_effect=Exception("Validation failed")):
            result = self.orchestrator.process_discovery(discovery)

            # Should return None on error
            self.assertIsNone(result)

    def test_run_full_pipeline_single_source(self):
        """Test running the full pipeline with a single discovery source."""
        # Create mock discoveries
        discoveries = [
            DiscoveryResult(
                cve_id="CVE-2025-12345",
                source_type="github",
                source_name="repo1",
                evidence_url="https://github.com/repo1/commit/1",
            ),
            DiscoveryResult(
                cve_id="CVE-2025-67890",
                source_type="github",
                source_name="repo1",
                evidence_url="https://github.com/repo1/commit/2",
            ),
        ]

        mock_source = MockDiscovery(discoveries, name="Test Source 1")

        # Mock validation - first is ghost, second is published
        validation_results = [
            ValidationResult(
                cve_id="CVE-2025-12345",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="LOCAL",
            ),
            ValidationResult(
                cve_id="CVE-2025-67890",
                status=CVEStatus.PUBLISHED,
                is_ghost=False,
                registry_source="LOCAL",
            ),
        ]

        mock_ghosts = [
            Mock(spec=GhostCVE, cve_id="CVE-2025-12345", is_ghost=True, first_seen=datetime.utcnow(), registry_status="RESERVED"),
            Mock(spec=GhostCVE, cve_id="CVE-2025-67890", is_ghost=False, first_seen=datetime.utcnow(), registry_status="PUBLISHED"),
        ]

        with patch.object(self.orchestrator.validator, 'validate', side_effect=validation_results):
            self.mock_db.record_discovery.side_effect = mock_ghosts

            # Run pipeline
            stats = self.orchestrator.run_full_pipeline([mock_source])

            # Verify stats
            self.assertIsNotNone(stats)
            self.assertEqual(stats.total_discoveries, 2)
            self.assertEqual(stats.ghosts_found, 1)
            self.assertEqual(stats.published_found, 1)
            self.assertEqual(stats.errors, 0)

    def test_run_full_pipeline_multiple_sources(self):
        """Test running pipeline with multiple discovery sources."""
        # Source 1
        source1_discoveries = [
            DiscoveryResult(
                cve_id="CVE-2025-12345",
                source_type="github",
                source_name="repo1",
                evidence_url="https://github.com/repo1/commit/1",
            ),
        ]
        mock_source1 = MockDiscovery(source1_discoveries, name="Test Source 1")

        # Source 2
        source2_discoveries = [
            DiscoveryResult(
                cve_id="CVE-2025-67890",
                source_type="rss",
                source_name="feed1",
                evidence_url="https://example.com/feed",
            ),
        ]
        mock_source2 = MockDiscovery(source2_discoveries, name="Test Source 2")

        validation_results = [
            ValidationResult(
                cve_id="CVE-2025-12345",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="LOCAL",
            ),
            ValidationResult(
                cve_id="CVE-2025-67890",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="LOCAL",
            ),
        ]

        mock_ghosts = [
            Mock(spec=GhostCVE, cve_id="CVE-2025-12345", is_ghost=True, first_seen=datetime.utcnow(), registry_status="RESERVED"),
            Mock(spec=GhostCVE, cve_id="CVE-2025-67890", is_ghost=True, first_seen=datetime.utcnow(), registry_status="RESERVED"),
        ]

        with patch.object(self.orchestrator.validator, 'validate', side_effect=validation_results):
            self.mock_db.record_discovery.side_effect = mock_ghosts

            stats = self.orchestrator.run_full_pipeline([mock_source1, mock_source2])

            self.assertEqual(stats.total_discoveries, 2)
            self.assertEqual(stats.ghosts_found, 2)
            self.assertEqual(len(stats.sources_used), 2)

    def test_run_full_pipeline_deduplication(self):
        """Test that pipeline deduplicates CVEs found in multiple sources."""
        # Both sources find the same CVE
        discovery1 = DiscoveryResult(
            cve_id="CVE-2025-54321",
            source_type="github",
            source_name="repo1",
            evidence_url="https://github.com/repo1/commit/1",
        )

        discovery2 = DiscoveryResult(
            cve_id="CVE-2025-54321",
            source_type="rss",
            source_name="feed1",
            evidence_url="https://example.com/feed",  # Different URL
        )

        source1 = MockDiscovery([discovery1], name="Test Source 1")
        source2 = MockDiscovery([discovery2], name="Test Source 2")

        validation = ValidationResult(
            cve_id="CVE-2025-54321",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="LOCAL",
        )

        mock_ghost = Mock(spec=GhostCVE, cve_id="CVE-2025-54321", is_ghost=True, first_seen=datetime.utcnow(), registry_status="RESERVED")

        with patch.object(self.orchestrator.validator, 'validate', return_value=validation):
            self.mock_db.record_discovery.return_value = mock_ghost

            stats = self.orchestrator.run_full_pipeline([source1, source2])

            # Should process both discoveries (different evidence URLs)
            self.assertEqual(stats.total_discoveries, 2)
            # But same CVE counted once in unique count
            self.assertEqual(stats.unique_cves, 1)

    def test_run_full_pipeline_handles_discovery_errors(self):
        """Test that pipeline continues even if one source fails."""
        # Working source
        working_discoveries = [
            DiscoveryResult(
                cve_id="CVE-2025-12345",
                source_type="github",
                source_name="repo1",
                evidence_url="https://github.com/repo1/commit/1",
            ),
        ]
        working_source = MockDiscovery(working_discoveries, name="Working Source")

        # Failing source - need to mock it properly
        failing_source = Mock(spec=BaseDiscovery)
        failing_source.name = "Failing Source"
        failing_source.run = Mock(side_effect=Exception("Discovery failed"))

        validation = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="LOCAL",
        )

        mock_ghost = Mock(spec=GhostCVE, cve_id="CVE-2025-12345", is_ghost=True, first_seen=datetime.utcnow(), registry_status="RESERVED")

        with patch.object(self.orchestrator.validator, 'validate', return_value=validation):
            self.mock_db.record_discovery.return_value = mock_ghost

            stats = self.orchestrator.run_full_pipeline([working_source, failing_source])

            # Should still process working source
            self.assertEqual(stats.total_discoveries, 1)
            self.assertEqual(stats.ghosts_found, 1)
            # Should record the error
            self.assertEqual(stats.errors, 1)

    def test_get_statistics(self):
        """Test getting statistics from orchestrator."""
        stats = PipelineStats(
            total_discoveries=10,
            unique_cves=8,
            ghosts_found=3,
            published_found=5,
            sources_used=["source1", "source2"],
            errors=0,
            duration_seconds=45.2,
        )

        # Verify all fields are accessible
        self.assertEqual(stats.total_discoveries, 10)
        self.assertEqual(stats.unique_cves, 8)
        self.assertEqual(stats.ghosts_found, 3)
        self.assertEqual(stats.published_found, 5)
        self.assertEqual(len(stats.sources_used), 2)
        self.assertEqual(stats.errors, 0)
        self.assertAlmostEqual(stats.duration_seconds, 45.2)

    def test_check_for_resolutions(self):
        """Test checking for Ghost CVE resolutions (RESERVED -> PUBLISHED)."""
        # Mock existing ghosts in database
        mock_ghosts = [
            Mock(
                spec=GhostCVE,
                cve_id="CVE-2025-12345",
                is_ghost=True,
                registry_status="RESERVED",
            ),
            Mock(
                spec=GhostCVE,
                cve_id="CVE-2025-67890",
                is_ghost=True,
                registry_status="RESERVED",
            ),
        ]

        self.mock_db.get_ghost_cves.return_value = mock_ghosts

        # First CVE is now published, second still reserved
        validation_results = [
            ValidationResult(
                cve_id="CVE-2025-12345",
                status=CVEStatus.PUBLISHED,
                is_ghost=False,
                registry_source="LOCAL",
                description="Now published",
            ),
            ValidationResult(
                cve_id="CVE-2025-67890",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="LOCAL",
            ),
        ]

        with patch.object(self.orchestrator.validator, 'validate', side_effect=validation_results):
            # Mock the session context manager
            mock_session = MagicMock()
            self.mock_db.get_session.return_value.__enter__ = Mock(return_value=mock_session)
            self.mock_db.get_session.return_value.__exit__ = Mock(return_value=False)

            resolved_count = self.orchestrator.check_for_resolutions()

            # Should detect 1 resolution
            self.assertEqual(resolved_count, 1)


class TestProcessedCVE(unittest.TestCase):
    """Test cases for ProcessedCVE dataclass."""

    def test_processed_cve_creation(self):
        """Test creating a ProcessedCVE instance."""
        processed = ProcessedCVE(
            cve_id="CVE-2025-12345",
            is_ghost=True,
            status="RESERVED",
            first_seen=datetime(2025, 1, 15),
            sources=["github", "rss"],
        )

        self.assertEqual(processed.cve_id, "CVE-2025-12345")
        self.assertTrue(processed.is_ghost)
        self.assertEqual(processed.status, "RESERVED")
        self.assertEqual(len(processed.sources), 2)


if __name__ == "__main__":
    unittest.main()
