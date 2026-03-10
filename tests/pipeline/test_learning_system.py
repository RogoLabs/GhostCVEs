"""
Tests for Learning System - Stage 6 of pipeline.

Tests source reliability tracking and learning from ghost resolutions.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock
from src.pipeline.learning_system import (
    SourceReliabilityTracker,
    CNARegistryLearning,
    LearningSystem,
)


class TestSourceReliabilityTracker:
    """Tests for SourceReliabilityTracker."""

    def test_initialization(self):
        """Test tracker initialization."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        assert tracker.db_manager == db_manager
        assert tracker._cache == {}
        assert tracker._last_cache_refresh is None

    def test_record_resolution_true_positive(self):
        """Test recording a true positive resolution."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        # True positive: resolution_days > 1.0
        tracker.record_resolution(
            source_name="TestSource",
            resolution_days=3.5,
            timestamp=datetime.utcnow()
        )

        # Verify database call
        db_manager.record_source_outcome.assert_called_once()
        call_args = db_manager.record_source_outcome.call_args[1]
        assert call_args["source_name"] == "TestSource"
        assert call_args["was_true_positive"] is True
        assert call_args["resolution_days"] == 3.5

    def test_record_resolution_false_positive(self):
        """Test recording a false positive (sync lag within grace period)."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        # False positive: resolution_days <= 1.0
        tracker.record_resolution(
            source_name="TestSource",
            resolution_days=0.5,
            timestamp=datetime.utcnow()
        )

        # Verify database call
        db_manager.record_source_outcome.assert_called_once()
        call_args = db_manager.record_source_outcome.call_args[1]
        assert call_args["was_true_positive"] is False
        assert call_args["resolution_days"] == 0.5

    def test_get_reliability_from_cache(self):
        """Test getting reliability from cache."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        # Prime cache
        tracker._cache["TestSource"] = 0.85
        tracker._last_cache_refresh = datetime.utcnow()

        reliability = tracker.get_reliability("TestSource")

        assert reliability == 0.85
        # Should not hit database
        db_manager.get_source_reliability.assert_not_called()

    def test_get_reliability_from_database(self):
        """Test getting reliability from database when not cached."""
        db_manager = Mock()
        db_manager.get_all_source_names.return_value = ["TestSource"]
        db_manager.get_source_reliability.return_value = 0.90

        tracker = SourceReliabilityTracker(db_manager)

        reliability = tracker.get_reliability("TestSource")

        assert reliability == 0.90
        # Should now be cached
        assert tracker._cache["TestSource"] == 0.90

    def test_get_reliability_default_for_unknown_source(self):
        """Test default reliability for unknown sources."""
        db_manager = Mock()
        db_manager.get_all_source_names.return_value = []
        db_manager.get_source_reliability.return_value = None

        tracker = SourceReliabilityTracker(db_manager)

        reliability = tracker.get_reliability("UnknownSource")

        assert reliability == 0.75  # Default
        assert "UnknownSource" not in tracker._cache

    def test_calculate_reliability_high_accuracy_fast(self):
        """Test reliability calculation with high accuracy and fast resolution."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        outcomes = [
            {"was_true_positive": True, "resolution_days": 2.0},
            {"was_true_positive": True, "resolution_days": 1.5},
            {"was_true_positive": True, "resolution_days": 2.5},
            {"was_true_positive": False, "resolution_days": 0.8},
        ]

        reliability = tracker._calculate_reliability(outcomes)

        # Accuracy: 3/4 = 0.75
        # Speed bonus: avg = 1.7 days < 3, so +0.10
        # Expected: 0.75 + 0.10 = 0.85
        assert reliability == 0.85

    def test_calculate_reliability_perfect_very_fast(self):
        """Test reliability calculation with perfect accuracy and very fast resolution."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        outcomes = [
            {"was_true_positive": True, "resolution_days": 2.0},
            {"was_true_positive": True, "resolution_days": 2.5},
            {"was_true_positive": True, "resolution_days": 1.5},
        ]

        reliability = tracker._calculate_reliability(outcomes)

        # Accuracy: 3/3 = 1.0
        # Speed bonus: avg = 2.0 days < 3, so +0.10
        # Expected: 1.0 + 0.10 = 1.10, capped at 1.0
        assert reliability == 1.0

    def test_calculate_reliability_medium_accuracy_medium_speed(self):
        """Test reliability calculation with medium accuracy and medium speed."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        outcomes = [
            {"was_true_positive": True, "resolution_days": 5.0},
            {"was_true_positive": True, "resolution_days": 6.0},
            {"was_true_positive": False, "resolution_days": 0.5},
            {"was_true_positive": False, "resolution_days": 0.7},
        ]

        reliability = tracker._calculate_reliability(outcomes)

        # Accuracy: 2/4 = 0.50
        # Speed bonus: avg = (5+6+0.5+0.7)/4 = 3.05 days < 7, so +0.05
        # Expected: 0.50 + 0.05 = 0.55
        assert reliability == 0.55

    def test_calculate_reliability_low_accuracy_slow(self):
        """Test reliability calculation with low accuracy and slow resolution."""
        db_manager = Mock()
        tracker = SourceReliabilityTracker(db_manager)

        outcomes = [
            {"was_true_positive": True, "resolution_days": 10.0},
            {"was_true_positive": False, "resolution_days": 0.5},
            {"was_true_positive": False, "resolution_days": 0.3},
            {"was_true_positive": False, "resolution_days": 0.8},
        ]

        reliability = tracker._calculate_reliability(outcomes)

        # Accuracy: 1/4 = 0.25
        # Speed bonus: avg (of true positives only) = 10.0 days >= 7, so 0
        # Expected: 0.25 + 0.0 = 0.25
        assert reliability == 0.25

    def test_should_recalculate_resolutions_threshold(self):
        """Test recalculation triggers after 50 resolutions."""
        db_manager = Mock()
        db_manager.get_resolutions_since_last_recalc.return_value = 50
        db_manager.get_days_since_last_recalc.return_value = 2.0

        tracker = SourceReliabilityTracker(db_manager)

        assert tracker._should_recalculate() is True

    def test_should_recalculate_time_threshold(self):
        """Test recalculation triggers after 7 days."""
        db_manager = Mock()
        db_manager.get_resolutions_since_last_recalc.return_value = 20
        db_manager.get_days_since_last_recalc.return_value = 7.5

        tracker = SourceReliabilityTracker(db_manager)

        assert tracker._should_recalculate() is True

    def test_should_not_recalculate_below_thresholds(self):
        """Test recalculation doesn't trigger below thresholds."""
        db_manager = Mock()
        db_manager.get_resolutions_since_last_recalc.return_value = 30
        db_manager.get_days_since_last_recalc.return_value = 3.0

        tracker = SourceReliabilityTracker(db_manager)

        assert tracker._should_recalculate() is False

    def test_recalculate_all_updates_all_sources(self):
        """Test recalculating all source reliabilities."""
        db_manager = Mock()
        db_manager.get_all_source_names.return_value = ["Source1", "Source2"]

        # Source1 outcomes
        source1_outcomes = [
            {"was_true_positive": True, "resolution_days": 2.0},
            {"was_true_positive": True, "resolution_days": 3.0},
        ]
        # Source2 outcomes
        source2_outcomes = [
            {"was_true_positive": True, "resolution_days": 5.0},
            {"was_true_positive": False, "resolution_days": 0.5},
        ]

        db_manager.get_source_outcomes.side_effect = [source1_outcomes, source2_outcomes]

        tracker = SourceReliabilityTracker(db_manager)
        tracker.recalculate_all()

        # Verify both sources updated
        assert db_manager.update_source_reliability.call_count == 2

        # Verify mark_recalculation called
        db_manager.mark_recalculation.assert_called_once()

    def test_refresh_cache_loads_all_sources(self):
        """Test cache refresh loads all sources."""
        db_manager = Mock()
        db_manager.get_all_source_names.return_value = ["Source1", "Source2", "Source3"]
        db_manager.get_source_reliability.side_effect = [0.85, 0.90, None]

        tracker = SourceReliabilityTracker(db_manager)
        tracker._refresh_cache()

        # Should cache known sources
        assert tracker._cache["Source1"] == 0.85
        assert tracker._cache["Source2"] == 0.90
        assert "Source3" not in tracker._cache  # Unknown source not cached


class TestCNARegistryLearning:
    """Tests for CNARegistryLearning (stub)."""

    def test_initialization(self):
        """Test CNA registry learning initialization."""
        db_manager = Mock()
        learning = CNARegistryLearning(db_manager)

        assert learning.db_manager == db_manager

    def test_update_cna_patterns_stub(self):
        """Test CNA pattern update (stub implementation)."""
        db_manager = Mock()
        learning = CNARegistryLearning(db_manager)

        # Should not raise, just pass through
        learning.update_cna_patterns(
            cna_name="mitre",
            resolution_days=5.0,
            was_ghost=True
        )


class TestLearningSystem:
    """Tests for LearningSystem orchestrator."""

    def test_initialization(self):
        """Test learning system initialization."""
        db_manager = Mock()
        system = LearningSystem(db_manager)

        assert system.db_manager == db_manager
        assert isinstance(system.reliability_tracker, SourceReliabilityTracker)
        assert isinstance(system.cna_learning, CNARegistryLearning)

    def test_learn_from_resolution_single_source(self):
        """Test learning from a ghost resolution with single source."""
        db_manager = Mock()

        # Mock resolution data
        cve_id = "CVE-2025-12345"
        first_discovered = datetime(2025, 3, 1, 12, 0, 0)
        resolved_date = datetime(2025, 3, 5, 18, 0, 0)
        resolution_days = 4.25

        source = Mock()
        source.source_name = "TestSource"
        source.discovered_at = first_discovered

        # Set up mocks
        db_manager.get_sources_for_cve.return_value = [source]
        db_manager.get_ghost_by_id.return_value = Mock(
            cve_id=cve_id,
            first_seen=first_discovered,
            is_ghost=True
        )
        db_manager.get_resolutions_since_last_recalc.return_value = 10
        db_manager.get_days_since_last_recalc.return_value = 1.0

        system = LearningSystem(db_manager)
        system.learn_from_resolution(
            cve_id=cve_id,
            resolved_date=resolved_date,
            was_true_ghost=True,
            cna_name="mitre"
        )

        # Verify resolution recorded for source
        db_manager.record_source_outcome.assert_called_once()

        # Verify resolution history stored
        db_manager.store_resolution_pattern.assert_called_once()
        call_args = db_manager.store_resolution_pattern.call_args[1]
        assert call_args["cve_id"] == cve_id
        assert call_args["was_true_ghost"] is True
        assert abs(call_args["resolution_time_days"] - resolution_days) < 0.01

    def test_learn_from_resolution_multiple_sources(self):
        """Test learning from resolution with multiple sources (only earliest counts)."""
        db_manager = Mock()

        cve_id = "CVE-2025-67890"
        first_discovered = datetime(2025, 3, 1, 12, 0, 0)
        resolved_date = datetime(2025, 3, 8, 12, 0, 0)

        # Multiple sources, different times
        source1 = Mock()
        source1.source_name = "Source1"
        source1.source_type = "vendor_advisory"
        source1.discovered_at = first_discovered

        source2 = Mock()
        source2.source_name = "Source2"
        source2.source_type = "blog"
        source2.discovered_at = first_discovered + timedelta(days=2)

        source3 = Mock()
        source3.source_name = "Source3"
        source3.source_type = "rss_feed"
        source3.discovered_at = first_discovered + timedelta(days=1)

        db_manager.get_sources_for_cve.return_value = [source1, source2, source3]
        db_manager.get_ghost_by_id.return_value = Mock(
            cve_id=cve_id,
            first_seen=first_discovered
        )
        db_manager.get_resolutions_since_last_recalc.return_value = 10
        db_manager.get_days_since_last_recalc.return_value = 1.0

        system = LearningSystem(db_manager)
        system.learn_from_resolution(
            cve_id=cve_id,
            resolved_date=resolved_date,
            was_true_ghost=True
        )

        # Should only record for earliest source (Source1)
        assert db_manager.record_source_outcome.call_count == 1
        call_args = db_manager.record_source_outcome.call_args[1]
        assert call_args["source_name"] == "Source1"

    def test_learn_from_resolution_triggers_recalculation(self):
        """Test that resolution triggers recalculation when threshold met."""
        db_manager = Mock()
        db_manager.get_resolutions_since_last_recalc.return_value = 50
        db_manager.get_days_since_last_recalc.return_value = 1.0
        db_manager.get_all_source_names.return_value = ["Source1"]
        db_manager.get_source_outcomes.return_value = [
            {"was_true_positive": True, "resolution_days": 3.0}
        ]

        cve_id = "CVE-2025-99999"
        source = Mock()
        source.source_name = "Source1"
        source.discovered_at = datetime(2025, 3, 1, 12, 0, 0)

        db_manager.get_sources_for_cve.return_value = [source]
        db_manager.get_ghost_by_id.return_value = Mock(
            cve_id=cve_id,
            first_seen=datetime(2025, 3, 1, 12, 0, 0)
        )

        system = LearningSystem(db_manager)
        system.learn_from_resolution(
            cve_id=cve_id,
            resolved_date=datetime(2025, 3, 5, 12, 0, 0),
            was_true_ghost=True
        )

        # Should trigger recalculation
        db_manager.mark_recalculation.assert_called_once()

    def test_learn_from_resolution_no_sources_found(self):
        """Test learning when no sources found for CVE."""
        db_manager = Mock()
        db_manager.get_sources_for_cve.return_value = []

        system = LearningSystem(db_manager)

        # Should not raise, just log and return
        system.learn_from_resolution(
            cve_id="CVE-2025-00000",
            resolved_date=datetime.utcnow(),
            was_true_ghost=True
        )

        # Should not record anything
        db_manager.record_source_outcome.assert_not_called()
        db_manager.store_resolution_pattern.assert_not_called()
