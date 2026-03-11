"""
End-to-End Pipeline Integration Tests
======================================

Comprehensive integration tests that verify the complete Ghost CVE detection
pipeline from discovery through resolution. Tests realistic workflows with
mocked external dependencies.

Test Coverage:
1. Complete Ghost Detection Flow (Discovery -> Ghost)
2. Published CVE Flow (Discovery -> Published)
3. Grace Period Handling (Within 6 hours)
4. Resolution Detection (RESERVED -> PUBLISHED)
5. Multi-Source Deduplication
6. Error Recovery and Fallback

Author: rogolabs.net
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.discovery.base import DiscoveryResult, BaseDiscovery
from src.models.dataclasses import DisclosureClassification
from src.models.enums import DisclosureStatus, DisclosureType, CVEStatus
from src.pipeline.orchestrator import PipelineOrchestrator, PipelineStats
from src.registry.validator import ValidationResult
from src.storage.database import DatabaseManager
from src.storage.models import GhostCVE, DiscoverySource


class MockDiscoverySource(BaseDiscovery):
    """Mock discovery source for testing."""

    def __init__(self, results=None, name="Mock Discovery", source_type="mock"):
        super().__init__(name=name, source_type=source_type)
        self._mock_results = results or []

    def discover(self):
        """Yield mock discovery results."""
        for result in self._mock_results:
            yield result


class TestCompleteGhostDetectionFlow(unittest.TestCase):
    """
    Test Scenario 1: Complete Ghost Detection Flow

    A CVE is discovered in the wild, classified as PUBLIC disclosure,
    validated as RESERVED status, determined to be a ghost (past grace period),
    and stored in the database.
    """

    def setUp(self):
        """Set up test environment with isolated database."""
        # Create temporary database
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = Path(self.temp_db.name)
        self.temp_db.close()

        # Initialize database manager
        self.db = DatabaseManager(self.db_path)
        self.db.initialize()

        # Create orchestrator
        self.orchestrator = PipelineOrchestrator(self.db)

    def tearDown(self):
        """Clean up test database."""
        if self.db_path.exists():
            self.db_path.unlink()

    def test_complete_ghost_detection_flow(self):
        """
        Test complete flow: Discovery -> Validation -> Ghost Classification -> Storage

        Scenario:
        - CVE-2026-1234 discovered in vendor advisory
        - CVE.org API returns RESERVED status
        - CVE discovered more than 6 hours ago (past grace period)
        - Should be classified as Ghost
        - Should be stored in database with correct metadata
        """
        # Arrange: Create discovery from vendor advisory (8 hours ago)
        discovery_time = datetime.now(timezone.utc) - timedelta(hours=8)
        discovery = DiscoveryResult(
            cve_id="CVE-2026-1234",
            source_type="vendor_advisory",
            source_name="Example Vendor Security Advisory",
            evidence_url="https://vendor.example.com/security/advisory-2026-12345",
            discovered_at=discovery_time,
            confidence=0.95,
            context="Critical vulnerability in Example Product v1.2.3",
        )

        # Mock disclosure: PUBLIC disclosure (vendor advisory with details)
        mock_disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Vendor advisory with vulnerability details",
        )

        # Mock validation: RESERVED status (Ghost)
        mock_validation = ValidationResult(
            cve_id="CVE-2026-1234",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
            description=None,
        )

        # Act: Process discovery through pipeline
        with patch.object(
            self.orchestrator.disclosure_classifier, "classify", return_value=mock_disclosure
        ), patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=mock_validation
        ):
            result = self.orchestrator.process_discovery(discovery)

        # Assert: Verify result
        self.assertIsNotNone(result, "Processing should succeed")
        self.assertEqual(result.cve_id, "CVE-2026-1234")
        self.assertTrue(result.is_ghost, "CVE should be classified as Ghost")
        self.assertEqual(result.status, "RESERVED")
        self.assertEqual(len(result.sources), 1)
        self.assertEqual(result.sources[0], "Example Vendor Security Advisory")

        # Assert: Verify database storage
        with self.db.get_session() as session:
            ghost_cve = (
                session.query(GhostCVE).filter_by(cve_id="CVE-2026-1234").first()
            )
            self.assertIsNotNone(ghost_cve, "Ghost CVE should be stored in database")
            self.assertTrue(ghost_cve.is_ghost)
            self.assertEqual(ghost_cve.registry_status, "RESERVED")
            self.assertEqual(ghost_cve.registry_source, "CVE_ORG_LOCAL")
            self.assertEqual(ghost_cve.discovery_count, 1)

            # Verify discovery source was recorded
            sources = (
                session.query(DiscoverySource)
                .filter_by(ghost_cve_id=ghost_cve.id)
                .all()
            )
            self.assertEqual(len(sources), 1)
            self.assertEqual(sources[0].source_type, "vendor_advisory")
            self.assertEqual(
                sources[0].evidence_url,
                "https://vendor.example.com/security/advisory-2026-12345",
            )

    def test_ghost_with_multiple_evidence_sources(self):
        """
        Test Ghost CVE discovered in multiple places.

        Scenario:
        - Same CVE found in vendor advisory AND security mailing list
        - Both sources should be linked to same Ghost CVE
        - Discovery count should be incremented
        """
        # Arrange: Two discoveries of same CVE
        discovery1 = DiscoveryResult(
            cve_id="CVE-2026-9099",
            source_type="vendor_advisory",
            source_name="Vendor Security Page",
            evidence_url="https://vendor.example.com/cve-2026-99999",
            discovered_at=datetime.now(timezone.utc) - timedelta(hours=10),
            confidence=0.95,
        )

        discovery2 = DiscoveryResult(
            cve_id="CVE-2026-9099",
            source_type="mailing_list",
            source_name="security-announce@lists.example.org",
            evidence_url="https://lists.example.org/archive/msg12345.html",
            discovered_at=datetime.now(timezone.utc) - timedelta(hours=9),
            confidence=0.90,
        )

        mock_disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Public disclosure with details",
        )

        mock_validation = ValidationResult(
            cve_id="CVE-2026-9099",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )

        # Act: Process both discoveries
        with patch.object(
            self.orchestrator.disclosure_classifier, "classify", return_value=mock_disclosure
        ), patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=mock_validation
        ):
            result1 = self.orchestrator.process_discovery(discovery1)
            result2 = self.orchestrator.process_discovery(discovery2)

        # Assert: Both processing succeeded
        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertTrue(result1.is_ghost)
        self.assertTrue(result2.is_ghost)

        # Assert: Database has single Ghost CVE with multiple sources
        with self.db.get_session() as session:
            ghost_cve = (
                session.query(GhostCVE).filter_by(cve_id="CVE-2026-9099").first()
            )
            self.assertIsNotNone(ghost_cve)
            self.assertEqual(ghost_cve.discovery_count, 2)

            # Verify both sources recorded
            sources = (
                session.query(DiscoverySource)
                .filter_by(ghost_cve_id=ghost_cve.id)
                .all()
            )
            self.assertEqual(len(sources), 2)
            source_types = {s.source_type for s in sources}
            self.assertEqual(source_types, {"vendor_advisory", "mailing_list"})


class TestPublishedCVEFlow(unittest.TestCase):
    """
    Test Scenario 2: Published CVE Flow

    A CVE is discovered and validated as PUBLISHED, so it's NOT a ghost.
    Should be recorded but not flagged as ghost.
    """

    def setUp(self):
        """Set up test environment."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = Path(self.temp_db.name)
        self.temp_db.close()

        self.db = DatabaseManager(self.db_path)
        self.db.initialize()
        self.orchestrator = PipelineOrchestrator(self.db)

    def tearDown(self):
        """Clean up."""
        if self.db_path.exists():
            self.db_path.unlink()

    def test_published_cve_not_ghost(self):
        """
        Test CVE that is already published.

        Scenario:
        - CVE-2026-1011 discovered in GitHub advisory
        - CVE.org shows PUBLISHED status with description
        - Should NOT be classified as Ghost
        - Should still be recorded for tracking
        """
        # Arrange
        discovery = DiscoveryResult(
            cve_id="CVE-2026-1011",
            source_type="github_advisory",
            source_name="github.com/vendor/repo",
            evidence_url="https://github.com/vendor/repo/security/advisories/GHSA-xxxx",
            discovered_at=datetime.now(timezone.utc) - timedelta(hours=12),
            confidence=1.0,
        )

        mock_disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=1.0,
            reasoning="GitHub advisory with full details",
        )

        mock_validation = ValidationResult(
            cve_id="CVE-2026-1011",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="NVD_LOCAL",
            description="Buffer overflow in Example Product allows remote code execution",
            raw_response={"description": "Buffer overflow in Example Product allows remote code execution"},
        )

        # Act
        with patch.object(
            self.orchestrator.disclosure_classifier, "classify", return_value=mock_disclosure
        ), patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=mock_validation
        ):
            result = self.orchestrator.process_discovery(discovery)

        # Assert
        self.assertIsNotNone(result)
        self.assertEqual(result.cve_id, "CVE-2026-1011")
        self.assertFalse(result.is_ghost, "Published CVE should NOT be a Ghost")
        self.assertEqual(result.status, "PUBLISHED")
        self.assertIsNotNone(result.description)

        # Verify in database
        with self.db.get_session() as session:
            cve = session.query(GhostCVE).filter_by(cve_id="CVE-2026-1011").first()
            self.assertIsNotNone(cve)
            self.assertFalse(cve.is_ghost)
            self.assertEqual(cve.registry_status, "PUBLISHED")
            self.assertIn("Buffer overflow", cve.description)


class TestGracePeriodHandling(unittest.TestCase):
    """
    Test Scenario 3: Grace Period Handling

    CVEs discovered recently (< 6 hours) should not be immediately
    classified as ghosts even if RESERVED.
    """

    def setUp(self):
        """Set up test environment."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = Path(self.temp_db.name)
        self.temp_db.close()

        self.db = DatabaseManager(self.db_path)
        self.db.initialize()
        self.orchestrator = PipelineOrchestrator(self.db)

    def tearDown(self):
        """Clean up."""
        if self.db_path.exists():
            self.db_path.unlink()

    def test_recent_cve_within_grace_period(self):
        """
        Test CVE discovered very recently (2 hours ago).

        Scenario:
        - CVE-2026-2022 discovered 2 hours ago
        - Status is RESERVED
        - Within 6-hour grace period
        - Should NOT be classified as Ghost yet
        """
        # Arrange: Recent discovery (2 hours ago)
        discovery = DiscoveryResult(
            cve_id="CVE-2026-2022",
            source_type="vendor_advisory",
            source_name="Vendor Security Team",
            evidence_url="https://vendor.example.com/security/2026-22222",
            discovered_at=datetime.now(timezone.utc) - timedelta(hours=2),
            confidence=0.95,
        )

        # Mock validation: RESERVED but not ghost due to grace period
        mock_validation = ValidationResult(
            cve_id="CVE-2026-2022",
            status=CVEStatus.RESERVED,
            is_ghost=False,  # Grace period logic would set this
            registry_source="CVE_ORG_LOCAL",
        )

        # Act
        with patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=mock_validation
        ):
            result = self.orchestrator.process_discovery(discovery)

        # Assert
        self.assertIsNotNone(result)
        self.assertEqual(result.cve_id, "CVE-2026-2022")
        self.assertFalse(result.is_ghost, "Recent CVE should not be Ghost yet")
        self.assertEqual(result.status, "RESERVED")

        # Verify database
        with self.db.get_session() as session:
            cve = session.query(GhostCVE).filter_by(cve_id="CVE-2026-2022").first()
            self.assertIsNotNone(cve)
            self.assertFalse(cve.is_ghost)
            self.assertEqual(cve.registry_status, "RESERVED")


class TestResolutionDetection(unittest.TestCase):
    """
    Test Scenario 4: Resolution Detection

    Existing Ghost CVEs that transition from RESERVED to PUBLISHED
    should be detected and marked as resolved.
    """

    def setUp(self):
        """Set up test environment with existing ghost."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = Path(self.temp_db.name)
        self.temp_db.close()

        self.db = DatabaseManager(self.db_path)
        self.db.initialize()
        self.orchestrator = PipelineOrchestrator(self.db)

        # Create an existing Ghost CVE
        discovery = DiscoveryResult(
            cve_id="CVE-2026-3033",
            source_type="vendor_advisory",
            source_name="Vendor Site",
            evidence_url="https://vendor.example.com/cve-33333",
            discovered_at=datetime.now(timezone.utc) - timedelta(days=5),
        )

        # Initially RESERVED (Ghost)
        initial_disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Public security advisory",
        )

        initial_validation = ValidationResult(
            cve_id="CVE-2026-3033",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )

        with patch.object(
            self.orchestrator.disclosure_classifier, "classify", return_value=initial_disclosure
        ), patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=initial_validation
        ):
            self.orchestrator.process_discovery(discovery)

    def tearDown(self):
        """Clean up."""
        if self.db_path.exists():
            self.db_path.unlink()

    def test_ghost_resolution_to_published(self):
        """
        Test detection of Ghost CVE resolution.

        Scenario:
        - Ghost CVE-2026-3033 exists in database (RESERVED)
        - check_for_resolutions() runs
        - CVE.org now shows PUBLISHED status
        - Ghost should be marked as resolved (is_ghost=False)
        - Status should update to PUBLISHED
        """
        # Arrange: Mock validation now returns PUBLISHED
        resolved_validation = ValidationResult(
            cve_id="CVE-2026-3033",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="NVD_LOCAL",
            description="Resolved: SQL injection in authentication module",
            raw_response={"description": "Resolved: SQL injection in authentication module"},
        )

        # Act: Check for resolutions
        with patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=resolved_validation
        ):
            resolved_count = self.orchestrator.check_for_resolutions()

        # Assert: One resolution detected
        self.assertEqual(resolved_count, 1, "Should detect 1 resolution")

        # Verify database updated
        with self.db.get_session() as session:
            cve = session.query(GhostCVE).filter_by(cve_id="CVE-2026-3033").first()
            self.assertIsNotNone(cve)
            self.assertFalse(cve.is_ghost, "Ghost should be resolved")
            self.assertEqual(cve.registry_status, "PUBLISHED")
            self.assertIsNotNone(cve.description)
            self.assertIn("SQL injection", cve.description)

    def test_no_resolutions_all_still_reserved(self):
        """
        Test when no resolutions occur.

        Scenario:
        - Ghost CVE still RESERVED
        - check_for_resolutions() should detect no changes
        """
        # Arrange: Still RESERVED
        still_reserved = ValidationResult(
            cve_id="CVE-2026-3033",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )

        # Act
        with patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=still_reserved
        ):
            resolved_count = self.orchestrator.check_for_resolutions()

        # Assert: No resolutions
        self.assertEqual(resolved_count, 0, "Should detect no resolutions")

        # Verify still a ghost
        with self.db.get_session() as session:
            cve = session.query(GhostCVE).filter_by(cve_id="CVE-2026-3033").first()
            self.assertTrue(cve.is_ghost, "Should still be a Ghost")


class TestMultiSourceDeduplication(unittest.TestCase):
    """
    Test Scenario 5: Multi-Source Deduplication

    Same CVE found by multiple discovery sources should be
    properly deduplicated with all sources linked.
    """

    def setUp(self):
        """Set up test environment."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = Path(self.temp_db.name)
        self.temp_db.close()

        self.db = DatabaseManager(self.db_path)
        self.db.initialize()
        self.orchestrator = PipelineOrchestrator(self.db)

    def tearDown(self):
        """Clean up."""
        if self.db_path.exists():
            self.db_path.unlink()

    def test_multi_source_deduplication(self):
        """
        Test same CVE found by multiple sources.

        Scenario:
        - CVE-2026-4044 found by GitHub, RSS, and Vendor sources
        - Should create single Ghost CVE entry
        - All three sources should be linked
        - Highest confidence source should be primary
        """
        # Arrange: Three discoveries from different sources
        github_discovery = DiscoveryResult(
            cve_id="CVE-2026-4044",
            source_type="github_advisory",
            source_name="github.com/example/repo",
            evidence_url="https://github.com/example/repo/security/advisories/GHSA-1234",
            confidence=0.85,
            discovered_at=datetime.now(timezone.utc) - timedelta(hours=10),
        )

        rss_discovery = DiscoveryResult(
            cve_id="CVE-2026-4044",
            source_type="rss_feed",
            source_name="Security RSS Feed",
            evidence_url="https://security-feed.example.com/item/44444",
            confidence=0.90,
            discovered_at=datetime.now(timezone.utc) - timedelta(hours=9),
        )

        vendor_discovery = DiscoveryResult(
            cve_id="CVE-2026-4044",
            source_type="vendor_advisory",
            source_name="Official Vendor Advisory",
            evidence_url="https://vendor.example.com/advisories/44444",
            confidence=0.98,  # Highest confidence
            discovered_at=datetime.now(timezone.utc) - timedelta(hours=8),
        )

        mock_validation = ValidationResult(
            cve_id="CVE-2026-4044",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )

        # Act: Process all three discoveries
        with patch.object(
            self.orchestrator.multi_source_validator, "validate", return_value=mock_validation
        ):
            result1 = self.orchestrator.process_discovery(github_discovery)
            result2 = self.orchestrator.process_discovery(rss_discovery)
            result3 = self.orchestrator.process_discovery(vendor_discovery)

        # Assert: All processed successfully
        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertIsNotNone(result3)

        # Verify database: Single CVE with multiple sources
        with self.db.get_session() as session:
            cve = session.query(GhostCVE).filter_by(cve_id="CVE-2026-4044").first()
            self.assertIsNotNone(cve)
            self.assertTrue(cve.is_ghost)
            self.assertEqual(cve.discovery_count, 3)

            # Verify all three sources recorded
            sources = (
                session.query(DiscoverySource).filter_by(ghost_cve_id=cve.id).all()
            )
            self.assertEqual(len(sources), 3)

            # Verify source types
            source_types = {s.source_type for s in sources}
            self.assertEqual(
                source_types,
                {"github_advisory", "rss_feed", "vendor_advisory"},
            )

            # Verify confidence scores preserved for each source
            confidence_map = {s.source_type: s.confidence for s in sources}
            self.assertAlmostEqual(confidence_map["github_advisory"], 0.85, places=2)
            self.assertAlmostEqual(confidence_map["rss_feed"], 0.90, places=2)
            self.assertAlmostEqual(confidence_map["vendor_advisory"], 0.98, places=2)

            # Verify overall confidence score is average
            expected_avg = (0.85 + 0.90 + 0.98) / 3
            self.assertAlmostEqual(cve.confidence_score, expected_avg, places=2)


class TestErrorRecovery(unittest.TestCase):
    """
    Test Scenario 6: Error Recovery and Fallback

    Pipeline should handle errors gracefully and continue processing.
    """

    def setUp(self):
        """Set up test environment."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = Path(self.temp_db.name)
        self.temp_db.close()

        self.db = DatabaseManager(self.db_path)
        self.db.initialize()
        self.orchestrator = PipelineOrchestrator(self.db)

    def tearDown(self):
        """Clean up."""
        if self.db_path.exists():
            self.db_path.unlink()

    def test_validation_failure_graceful_handling(self):
        """
        Test pipeline handles validation failures gracefully.

        Scenario:
        - Discovery succeeds
        - Validation raises exception
        - Pipeline should catch error and continue
        - Error should be logged but not crash
        """
        # Arrange
        discovery = DiscoveryResult(
            cve_id="CVE-2026-5055",
            source_type="vendor_advisory",
            source_name="Vendor Site",
            evidence_url="https://vendor.example.com/cve-55555",
        )

        # Act: Mock validator to raise exception
        with patch.object(
            self.orchestrator.multi_source_validator,
            "validate",
            side_effect=Exception("Validation service unavailable"),
        ):
            result = self.orchestrator.process_discovery(discovery)

        # Assert: Should return None but not crash
        self.assertIsNone(result, "Should return None on error")

        # Verify nothing stored in database
        with self.db.get_session() as session:
            cve = session.query(GhostCVE).filter_by(cve_id="CVE-2026-5055").first()
            self.assertIsNone(cve, "Failed discovery should not be stored")

    def test_discovery_source_failure_continues_pipeline(self):
        """
        Test pipeline continues when one discovery source fails.

        Scenario:
        - Source 1 works fine
        - Source 2 raises exception
        - Source 3 works fine
        - Pipeline should process Sources 1 and 3 successfully
        """
        # Arrange: Three sources - one will fail
        working_discoveries_1 = [
            DiscoveryResult(
                cve_id="CVE-2026-6061",
                source_type="vendor_advisory",
                source_name="Source 1",
                evidence_url="https://example.com/1",
            )
        ]

        working_discoveries_3 = [
            DiscoveryResult(
                cve_id="CVE-2026-6063",
                source_type="rss_feed",
                source_name="Source 3",
                evidence_url="https://example.com/3",
            )
        ]

        source1 = MockDiscoverySource(working_discoveries_1, name="Working Source 1")
        source2 = Mock(spec=BaseDiscovery)
        source2.name = "Failing Source 2"
        source2.run = Mock(side_effect=Exception("Source 2 unavailable"))

        source3 = MockDiscoverySource(working_discoveries_3, name="Working Source 3")

        mock_disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Public disclosure",
        )

        mock_validation_1 = ValidationResult(
            cve_id="CVE-2026-6061",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )

        mock_validation_3 = ValidationResult(
            cve_id="CVE-2026-6063",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )

        # Act: Run pipeline with mixed sources
        with patch.object(
            self.orchestrator.disclosure_classifier, "classify", return_value=mock_disclosure
        ), patch.object(
            self.orchestrator.multi_source_validator, "validate", side_effect=[mock_validation_1, mock_validation_3]
        ):
            stats = self.orchestrator.run_full_pipeline([source1, source2, source3])

        # Assert: Pipeline completed with errors
        self.assertEqual(stats.total_discoveries, 2, "Should process 2 discoveries")
        self.assertEqual(stats.unique_cves, 2)
        self.assertEqual(stats.errors, 1, "Should record 1 error from failed source")
        # sources_used includes successful sources (may not include failed source depending on implementation)
        self.assertGreaterEqual(len(stats.sources_used), 2, "Should have at least 2 working sources")

        # Verify successful discoveries stored
        with self.db.get_session() as session:
            cve1 = session.query(GhostCVE).filter_by(cve_id="CVE-2026-6061").first()
            cve3 = session.query(GhostCVE).filter_by(cve_id="CVE-2026-6063").first()
            self.assertIsNotNone(cve1, "Source 1 CVE should be stored")
            self.assertIsNotNone(cve3, "Source 3 CVE should be stored")


class TestFullPipelineIntegration(unittest.TestCase):
    """
    Comprehensive end-to-end test of the complete pipeline.

    Tests realistic scenario with multiple sources, mixed results,
    and resolution checking.
    """

    def setUp(self):
        """Set up test environment."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = Path(self.temp_db.name)
        self.temp_db.close()

        self.db = DatabaseManager(self.db_path)
        self.db.initialize()
        self.orchestrator = PipelineOrchestrator(self.db)

    def tearDown(self):
        """Clean up."""
        if self.db_path.exists():
            self.db_path.unlink()

    def test_full_pipeline_realistic_scenario(self):
        """
        Test complete realistic pipeline scenario.

        Scenario:
        - 3 discovery sources active
        - Mix of Ghost and Published CVEs discovered
        - Some CVEs found by multiple sources
        - Run full pipeline
        - Verify statistics
        - Check for resolutions
        """
        # Arrange: Create realistic discoveries
        source1_discoveries = [
            DiscoveryResult(
                cve_id="CVE-2026-7071",  # Will be Ghost
                source_type="vendor_advisory",
                source_name="Vendor A",
                evidence_url="https://vendora.example.com/cve-77771",
                discovered_at=datetime.now(timezone.utc) - timedelta(days=2),
            ),
            DiscoveryResult(
                cve_id="CVE-2026-7072",  # Will be Published
                source_type="vendor_advisory",
                source_name="Vendor A",
                evidence_url="https://vendora.example.com/cve-77772",
                discovered_at=datetime.now(timezone.utc) - timedelta(days=1),
            ),
        ]

        source2_discoveries = [
            DiscoveryResult(
                cve_id="CVE-2026-7071",  # Same as source1 - dedup
                source_type="github_advisory",
                source_name="github.com/example/repo",
                evidence_url="https://github.com/example/repo/security/GHSA-5678",
                discovered_at=datetime.now(timezone.utc) - timedelta(days=2),
            ),
            DiscoveryResult(
                cve_id="CVE-2026-7073",  # New Ghost
                source_type="github_advisory",
                source_name="github.com/example/repo",
                evidence_url="https://github.com/example/repo/commit/abc123",
                discovered_at=datetime.now(timezone.utc) - timedelta(hours=15),
            ),
        ]

        source3_discoveries = [
            DiscoveryResult(
                cve_id="CVE-2026-7074",  # Published
                source_type="rss_feed",
                source_name="Security News Feed",
                evidence_url="https://security-news.example.com/item/77774",
                discovered_at=datetime.now(timezone.utc) - timedelta(hours=12),
            ),
        ]

        source1 = MockDiscoverySource(source1_discoveries, name="Vendor Advisories")
        source2 = MockDiscoverySource(source2_discoveries, name="GitHub Security")
        source3 = MockDiscoverySource(source3_discoveries, name="RSS Feeds")

        # Mock disclosure responses - PUBLIC for all
        disclosure_response = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Public advisory with details",
        )

        # Mock validation responses - return the same validation for duplicate CVE
        validation_responses = [
            ValidationResult(  # CVE-2026-7071 from source1
                cve_id="CVE-2026-7071",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="CVE_ORG_LOCAL",
            ),
            ValidationResult(  # CVE-2026-7072 from source1
                cve_id="CVE-2026-7072",
                status=CVEStatus.PUBLISHED,
                is_ghost=False,
                registry_source="NVD_LOCAL",
                description="Known vulnerability",
                raw_response={"description": "Known vulnerability"},
            ),
            ValidationResult(  # CVE-2026-7071 from source2 (duplicate)
                cve_id="CVE-2026-7071",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="CVE_ORG_LOCAL",
            ),
            ValidationResult(  # CVE-2026-7073 from source2
                cve_id="CVE-2026-7073",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="CVE_ORG_LOCAL",
            ),
            ValidationResult(  # CVE-2026-7074 from source3
                cve_id="CVE-2026-7074",
                status=CVEStatus.PUBLISHED,
                is_ghost=False,
                registry_source="NVD_LOCAL",
                description="Published vulnerability",
                raw_response={"description": "Published vulnerability"},
            ),
        ]

        # Act: Run full pipeline
        with patch.object(
            self.orchestrator.disclosure_classifier, "classify", return_value=disclosure_response
        ), patch.object(
            self.orchestrator.multi_source_validator, "validate", side_effect=validation_responses
        ):
            stats = self.orchestrator.run_full_pipeline([source1, source2, source3])

        # Assert: Verify statistics
        self.assertEqual(stats.total_discoveries, 5, "Should process 5 total discoveries")
        self.assertEqual(stats.unique_cves, 4, "Should find 4 unique CVEs")
        # Note: ghosts_found counts total ghost discoveries (including duplicates),
        # so CVE-2026-7071 counted twice (once from each source) = 3 total
        self.assertEqual(stats.ghosts_found, 3, "Should find 3 Ghost discoveries (including 1 duplicate)")
        self.assertEqual(stats.published_found, 2, "Should find 2 Published")
        self.assertEqual(stats.errors, 0, "Should have no errors")
        self.assertEqual(len(stats.sources_used), 3, "Should use 3 sources")

        # Verify database state
        with self.db.get_session() as session:
            all_cves = session.query(GhostCVE).all()
            self.assertEqual(len(all_cves), 4, "Should have 4 CVE entries")

            ghosts = session.query(GhostCVE).filter_by(is_ghost=True).all()
            self.assertEqual(len(ghosts), 2, "Should have 2 Ghosts")

            # Check deduplication: CVE-2026-7071 found by 2 sources
            cve_77771 = session.query(GhostCVE).filter_by(cve_id="CVE-2026-7071").first()
            self.assertIsNotNone(cve_77771)
            self.assertEqual(cve_77771.discovery_count, 2)
            sources = (
                session.query(DiscoverySource)
                .filter_by(ghost_cve_id=cve_77771.id)
                .all()
            )
            self.assertEqual(len(sources), 2, "Should have 2 sources for CVE-2026-7071")

    def test_pipeline_statistics_accuracy(self):
        """
        Test that pipeline statistics are accurately calculated.
        """
        # Arrange
        discoveries = [
            DiscoveryResult(
                cve_id="CVE-2026-8081",
                source_type="test",
                source_name="Test Source",
                evidence_url=f"https://example.com/88881",
                discovered_at=datetime.now(timezone.utc) - timedelta(hours=10),
            ),
            DiscoveryResult(
                cve_id="CVE-2026-8082",
                source_type="test",
                source_name="Test Source",
                evidence_url=f"https://example.com/88882",
                discovered_at=datetime.now(timezone.utc) - timedelta(hours=10),
            ),
        ]

        source = MockDiscoverySource(discoveries, name="Test Source")

        mock_validation_ghost = ValidationResult(
            cve_id="CVE-2026-8081",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )

        mock_validation_published = ValidationResult(
            cve_id="CVE-2026-8082",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="NVD_LOCAL",
        )

        mock_disclosure = DisclosureClassification(
            status=DisclosureStatus.PUBLIC,
            disclosure_type=DisclosureType.ADVISORY,
            confidence=0.95,
            reasoning="Public disclosure",
        )

        # Act
        with patch.object(
            self.orchestrator.disclosure_classifier, "classify", return_value=mock_disclosure
        ), patch.object(
            self.orchestrator.multi_source_validator,
            "validate",
            side_effect=[mock_validation_ghost, mock_validation_published],
        ):
            stats = self.orchestrator.run_full_pipeline([source])

        # Assert: Detailed statistics check
        self.assertIsInstance(stats, PipelineStats)
        self.assertIsNotNone(stats.started_at)
        self.assertEqual(stats.total_discoveries, 2)
        self.assertEqual(stats.unique_cves, 2)
        self.assertEqual(stats.ghosts_found, 1)
        self.assertEqual(stats.published_found, 1)
        self.assertGreater(stats.duration_seconds, 0)
        self.assertEqual(stats.sources_used, ["Test Source"])


if __name__ == "__main__":
    unittest.main()
