"""
Tests for Multi-Source Validator
=================================

Tests the MultiSourceValidator class that orchestrates validation across
multiple sources with caching and fallback logic.

Author: rogolabs.net
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, MagicMock, patch

from src.registry.multi_source_validator import MultiSourceValidator
from src.registry.validator import ValidationResult, CVEStatus


class TestMultiSourceValidator:
    """Test suite for MultiSourceValidator."""

    @pytest.fixture
    def mock_cve_org_client(self):
        """Create a mock CVE.org API client."""
        mock = Mock()
        mock.validate = Mock()
        return mock

    @pytest.fixture
    def mock_local_registry(self):
        """Create a mock local CVE registry."""
        mock = Mock()
        mock.get_status = Mock()
        mock.get_published_date = Mock()
        mock.is_available = Mock(return_value=True)
        return mock

    @pytest.fixture
    def mock_nvd_local(self):
        """Create a mock NVD local registry."""
        mock = Mock()
        mock.get_status = Mock()
        mock.get_published_date = Mock()
        mock.is_available = Mock(return_value=True)
        return mock

    @pytest.fixture
    def validator(self, mock_cve_org_client, mock_local_registry, mock_nvd_local):
        """Create a MultiSourceValidator with mocked dependencies."""
        return MultiSourceValidator(
            cve_org_client=mock_cve_org_client,
            local_registry=mock_local_registry,
            nvd_local=mock_nvd_local,
        )

    def test_cache_hit_returns_cached_result(self, validator):
        """Test that cached results are returned immediately."""
        # Pre-populate cache
        cached_result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
            validated_at=datetime.now(timezone.utc),
        )
        validator.set_cache("CVE-2025-1234", cached_result)

        # Validate - should return cached result without calling any source
        result = validator.validate("CVE-2025-1234")

        assert result == cached_result
        assert result.registry_source == "CVE.ORG"

        # Verify no sources were called
        validator.cve_org_client.validate.assert_not_called()

    def test_cache_expired_fetches_fresh_data(self, validator):
        """Test that expired cache entries trigger fresh validation."""
        # Pre-populate cache with expired result (2 hours old)
        old_result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
            validated_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        validator.set_cache("CVE-2025-1234", old_result)

        # Mock CVE.org to return a fresh result
        fresh_result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
            validated_at=datetime.now(timezone.utc),
        )
        validator.cve_org_client.validate.return_value = fresh_result

        # Validate - should fetch fresh data
        result = validator.validate("CVE-2025-1234")

        assert result == fresh_result
        validator.cve_org_client.validate.assert_called_once()

    def test_cve_org_published_returns_immediately(self, validator):
        """Test that CVE.org PUBLISHED status is returned immediately."""
        result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
        )
        validator.cve_org_client.validate.return_value = result

        # Validate
        validation = validator.validate("CVE-2025-1234")

        assert validation.status == CVEStatus.PUBLISHED
        assert validation.registry_source == "CVE.ORG"
        assert not validation.is_ghost

        # Local sources should not be called
        validator.local_registry.get_status.assert_not_called()
        validator.nvd_local.get_status.assert_not_called()

    def test_cve_org_reserved_returns_immediately(self, validator):
        """Test that CVE.org RESERVED status is returned immediately."""
        result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE.ORG",
        )
        validator.cve_org_client.validate.return_value = result

        # Validate
        validation = validator.validate("CVE-2025-1234")

        assert validation.status == CVEStatus.RESERVED
        assert validation.registry_source == "CVE.ORG"
        assert validation.is_ghost

        # Local sources should not be called
        validator.local_registry.get_status.assert_not_called()

    def test_cve_org_error_falls_back_to_local(self, validator):
        """Test that CVE.org ERROR status triggers fallback to local sources."""
        # CVE.org returns ERROR
        error_result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )
        validator.cve_org_client.validate.return_value = error_result

        # Local registry returns PUBLISHED
        validator.local_registry.get_status.return_value = ("PUBLISHED", "Test description")
        validator.local_registry.get_published_date.return_value = datetime(2025, 1, 15)

        # Validate
        validation = validator.validate("CVE-2025-1234")

        assert validation.status == CVEStatus.PUBLISHED
        assert validation.registry_source == "LOCAL"
        assert not validation.is_ghost

        # Verify fallback was used
        validator.local_registry.get_status.assert_called_once()

    def test_local_registry_fallback_when_cve_org_fails(self, validator):
        """Test fallback to local CVE registry when CVE.org has ERROR."""
        # CVE.org returns ERROR
        validator.cve_org_client.validate.return_value = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # Local registry has the CVE
        validator.local_registry.get_status.return_value = ("RESERVED", "** RESERVED **")
        validator.local_registry.get_published_date.return_value = None

        # Validate
        result = validator.validate("CVE-2025-1234")

        assert result.status == CVEStatus.RESERVED
        assert result.registry_source == "LOCAL"
        assert result.is_ghost

    def test_nvd_fallback_when_local_not_found(self, validator):
        """Test fallback to NVD when local CVE registry returns NOT_FOUND."""
        # CVE.org returns ERROR
        validator.cve_org_client.validate.return_value = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # Local registry doesn't have it
        validator.local_registry.get_status.return_value = ("NOT_FOUND", None)

        # NVD has it
        validator.nvd_local.get_status.return_value = ("PUBLISHED", "Vulnerability in XYZ")
        validator.nvd_local.get_published_date.return_value = datetime(2025, 1, 10)

        # Validate
        result = validator.validate("CVE-2025-1234")

        assert result.status == CVEStatus.PUBLISHED
        assert result.registry_source == "NVD_LOCAL"
        assert not result.is_ghost

    def test_all_sources_not_found_returns_not_found(self, validator):
        """Test that NOT_FOUND is returned when all sources fail."""
        # CVE.org returns ERROR
        validator.cve_org_client.validate.return_value = ValidationResult(
            cve_id="CVE-2025-9999",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # Local registry doesn't have it
        validator.local_registry.get_status.return_value = ("NOT_FOUND", None)

        # NVD doesn't have it
        validator.nvd_local.get_status.return_value = ("NOT_FOUND", None)

        # Validate
        result = validator.validate("CVE-2025-9999")

        assert result.status == CVEStatus.NOT_FOUND
        assert result.registry_source == "NONE"
        assert result.is_ghost  # found_in_wild=True by default

    def test_local_unavailable_skips_to_nvd(self, validator):
        """Test that unavailable local registry is skipped."""
        # CVE.org returns ERROR
        validator.cve_org_client.validate.return_value = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # Local registry unavailable
        validator.local_registry.is_available.return_value = False

        # NVD has it
        validator.nvd_local.get_status.return_value = ("PUBLISHED", "Test vulnerability")
        validator.nvd_local.get_published_date.return_value = datetime(2025, 1, 5)

        # Validate
        result = validator.validate("CVE-2025-1234")

        assert result.status == CVEStatus.PUBLISHED
        assert result.registry_source == "NVD_LOCAL"

        # Local should not be queried
        validator.local_registry.get_status.assert_not_called()

    def test_cache_management_methods(self, validator):
        """Test cache get, set, and clear operations."""
        result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # Test set and get
        validator.set_cache("CVE-2025-1234", result)
        cached = validator.get_cache("CVE-2025-1234")
        assert cached == result

        # Test clear
        validator.clear_cache()
        assert validator.get_cache("CVE-2025-1234") is None

    def test_validate_batch(self, validator):
        """Test batch validation of multiple CVE IDs."""
        # Mock CVE.org responses
        results = [
            ValidationResult(
                cve_id="CVE-2025-1111",
                status=CVEStatus.PUBLISHED,
                is_ghost=False,
                registry_source="CVE.ORG",
            ),
            ValidationResult(
                cve_id="CVE-2025-2222",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="CVE.ORG",
            ),
            ValidationResult(
                cve_id="CVE-2025-3333",
                status=CVEStatus.NOT_FOUND,
                is_ghost=True,
                registry_source="CVE.ORG",
            ),
        ]

        validator.cve_org_client.validate.side_effect = results

        # Validate batch
        cve_ids = ["CVE-2025-1111", "CVE-2025-2222", "CVE-2025-3333"]
        batch_results = validator.validate_batch(cve_ids)

        assert len(batch_results) == 3
        assert batch_results[0].status == CVEStatus.PUBLISHED
        assert batch_results[1].status == CVEStatus.RESERVED
        assert batch_results[2].status == CVEStatus.NOT_FOUND

    def test_priority_order_cve_org_first(self, validator):
        """Test that CVE.org is checked first (highest priority)."""
        # CVE.org has it as PUBLISHED
        cve_org_result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
        )
        validator.cve_org_client.validate.return_value = cve_org_result

        # Even if local has it, CVE.org should be used
        validator.local_registry.get_status.return_value = ("RESERVED", "** RESERVED **")

        result = validator.validate("CVE-2025-1234")

        assert result.registry_source == "CVE.ORG"
        assert result.status == CVEStatus.PUBLISHED

        # Local should not be checked since CVE.org succeeded
        validator.local_registry.get_status.assert_not_called()

    def test_found_in_wild_parameter_propagates(self, validator):
        """Test that found_in_wild parameter is passed through correctly."""
        result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.RESERVED,
            is_ghost=False,  # Not a ghost when found_in_wild=False
            registry_source="CVE.ORG",
        )
        validator.cve_org_client.validate.return_value = result

        # Validate with found_in_wild=False
        validation = validator.validate("CVE-2025-1234", found_in_wild=False)

        # Verify found_in_wild was passed to CVE.org client
        validator.cve_org_client.validate.assert_called_with("CVE-2025-1234", False)

    def test_rejected_status_returns_immediately(self, validator):
        """Test that REJECTED status from CVE.org is returned without fallback."""
        result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.REJECTED,
            is_ghost=False,
            registry_source="CVE.ORG",
        )
        validator.cve_org_client.validate.return_value = result

        validation = validator.validate("CVE-2025-1234")

        assert validation.status == CVEStatus.REJECTED
        assert validation.registry_source == "CVE.ORG"
        assert not validation.is_ghost

        # No fallback should occur
        validator.local_registry.get_status.assert_not_called()

    def test_cve_id_normalization(self, validator):
        """Test that CVE IDs are normalized to uppercase."""
        result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
        )
        validator.cve_org_client.validate.return_value = result

        # Pass lowercase CVE ID
        validation = validator.validate("cve-2025-1234")

        # Verify it was normalized
        validator.cve_org_client.validate.assert_called_with("CVE-2025-1234", True)

    def test_cache_ttl_enforcement(self, validator):
        """Test that cache TTL is enforced correctly."""
        # Set custom TTL for testing
        validator._cache_ttl_seconds = 10

        # Add a recent result
        recent_result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
            validated_at=datetime.now(timezone.utc) - timedelta(seconds=5),
        )
        validator.set_cache("CVE-2025-1234", recent_result)

        # Should return cached result (within TTL)
        cached = validator.get_cache("CVE-2025-1234")
        assert cached is not None
        assert cached == recent_result

    def test_cache_expires_after_ttl(self, validator):
        """Test that cache entries expire after TTL."""
        # Set custom TTL for testing
        validator._cache_ttl_seconds = 10

        # Add an old result
        old_result = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
            validated_at=datetime.now(timezone.utc) - timedelta(seconds=15),
        )
        validator.set_cache("CVE-2025-1234", old_result)

        # Should return None (expired)
        cached = validator.get_cache("CVE-2025-1234")
        assert cached is None

    def test_description_propagates_from_sources(self, validator):
        """Test that description field is properly populated from sources."""
        # CVE.org returns ERROR
        validator.cve_org_client.validate.return_value = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # Local registry has description
        description = "Buffer overflow in component X"
        validator.local_registry.get_status.return_value = ("PUBLISHED", description)
        validator.local_registry.get_published_date.return_value = datetime(2025, 1, 15)

        result = validator.validate("CVE-2025-1234")

        assert result.description == description
        assert result.registry_source == "LOCAL"

    def test_published_date_propagates_from_sources(self, validator):
        """Test that published_date field is properly populated from sources."""
        # CVE.org returns ERROR
        validator.cve_org_client.validate.return_value = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # NVD has published date
        pub_date = datetime(2025, 1, 20, 12, 0, 0)
        validator.local_registry.get_status.return_value = ("NOT_FOUND", None)
        validator.nvd_local.get_status.return_value = ("PUBLISHED", "Test vuln")
        validator.nvd_local.get_published_date.return_value = pub_date

        result = validator.validate("CVE-2025-1234")

        assert result.published_date == pub_date
        assert result.registry_source == "NVD_LOCAL"


class TestMultiSourceValidatorIntegration:
    """Integration tests with less mocking."""

    def test_full_fallback_chain(self):
        """Test the complete fallback chain: CVE.org -> Local -> NVD -> NONE."""
        # Create validator with all mocked sources
        cve_org = Mock()
        local_reg = Mock()
        nvd_reg = Mock()

        validator = MultiSourceValidator(
            cve_org_client=cve_org,
            local_registry=local_reg,
            nvd_local=nvd_reg,
        )

        # CVE.org fails
        cve_org.validate.return_value = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.ERROR,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        # Local not found
        local_reg.is_available.return_value = True
        local_reg.get_status.return_value = ("NOT_FOUND", None)

        # NVD not found
        nvd_reg.is_available.return_value = True
        nvd_reg.get_status.return_value = ("NOT_FOUND", None)

        # Validate
        result = validator.validate("CVE-2025-1234")

        # Should exhaust all sources and return NOT_FOUND
        assert result.status == CVEStatus.NOT_FOUND
        assert result.registry_source == "NONE"

        # Verify all sources were tried
        cve_org.validate.assert_called_once()
        local_reg.get_status.assert_called_once()
        nvd_reg.get_status.assert_called_once()

    def test_early_exit_on_success(self):
        """Test that validation stops at first successful source."""
        cve_org = Mock()
        local_reg = Mock()
        nvd_reg = Mock()

        validator = MultiSourceValidator(
            cve_org_client=cve_org,
            local_registry=local_reg,
            nvd_local=nvd_reg,
        )

        # CVE.org succeeds immediately
        cve_org.validate.return_value = ValidationResult(
            cve_id="CVE-2025-1234",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="CVE.ORG",
        )

        result = validator.validate("CVE-2025-1234")

        assert result.status == CVEStatus.PUBLISHED

        # Local and NVD should not be called
        local_reg.get_status.assert_not_called()
        nvd_reg.get_status.assert_not_called()
