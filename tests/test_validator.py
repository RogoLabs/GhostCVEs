"""
Tests for CVE Validator
=======================

Unit tests for the CVEValidator class and registry validation logic.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.registry.validator import CVEValidator, CVEStatus, ValidationResult


class TestCVEStatus:
    """Tests for CVEStatus enumeration."""
    
    def test_status_values(self):
        """Verify all expected status values exist."""
        assert CVEStatus.RESERVED.value == "RESERVED"
        assert CVEStatus.PUBLISHED.value == "PUBLISHED"
        assert CVEStatus.REJECTED.value == "REJECTED"
        assert CVEStatus.NOT_FOUND.value == "NOT_FOUND"
        assert CVEStatus.GHOST.value == "GHOST"
        assert CVEStatus.ERROR.value == "ERROR"


class TestValidationResult:
    """Tests for ValidationResult dataclass."""
    
    def test_creation(self):
        """Test ValidationResult creation."""
        result = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        assert result.cve_id == "CVE-2025-12345"
        assert result.status == CVEStatus.RESERVED
        assert result.is_ghost is True
        assert result.registry_source == "NVD"
        assert result.validated_at is not None
    
    def test_optional_fields(self):
        """Test ValidationResult with optional fields."""
        result = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.PUBLISHED,
            is_ghost=False,
            registry_source="MITRE",
            description="Test vulnerability",
            published_date=datetime(2025, 1, 1),
        )
        
        assert result.description == "Test vulnerability"
        assert result.published_date == datetime(2025, 1, 1)


class TestCVEValidator:
    """Tests for CVEValidator class."""
    
    @pytest.fixture
    def validator(self):
        """Create a CVEValidator instance."""
        return CVEValidator()
    
    def test_initialization(self, validator):
        """Test validator initialization."""
        assert validator.nvd_api_key is None
        assert validator.session is not None
        assert validator._cache == {}
    
    def test_initialization_with_api_key(self):
        """Test validator initialization with NVD API key."""
        validator = CVEValidator(nvd_api_key="test_key")
        assert validator.nvd_api_key == "test_key"
    
    @patch('src.registry.validator.CVEValidator._validate_local')
    def test_validate_uses_cache(self, mock_local, validator):
        """Test that validation results are cached."""
        mock_result = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="CVE_ORG_LOCAL",
        )
        mock_local.return_value = mock_result

        # Enable local validation
        validator._local_available = True

        # First call should hit local validation
        result1 = validator.validate("CVE-2025-12345")
        assert mock_local.call_count == 1

        # Second call should use cache
        result2 = validator.validate("CVE-2025-12345")
        assert mock_local.call_count == 1  # Not incremented

        assert result1.cve_id == result2.cve_id
    
    def test_clear_cache(self, validator):
        """Test cache clearing."""
        validator._cache["CVE-2025-12345"] = Mock()
        assert len(validator._cache) == 1
        
        validator.clear_cache()
        assert len(validator._cache) == 0
    
    @patch('src.registry.validator.CVEValidator._validate_nvd')
    def test_is_ghost(self, mock_nvd, validator):
        """Test is_ghost convenience method."""
        mock_result = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        mock_nvd.return_value = mock_result
        
        assert validator.is_ghost("CVE-2025-12345") is True
    
    @patch('src.registry.validator.CVEValidator._validate_nvd')
    def test_validate_batch(self, mock_nvd, validator):
        """Test batch validation."""
        mock_nvd.return_value = ValidationResult(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            is_ghost=True,
            registry_source="NVD",
        )
        
        cve_ids = ["CVE-2025-12345", "CVE-2025-23456"]
        results = validator.validate_batch(cve_ids)
        
        assert len(results) == 2
    
    def test_cve_id_normalization(self, validator):
        """Test that CVE IDs are normalized to uppercase."""
        with patch.object(validator, '_validate_nvd') as mock_nvd:
            mock_nvd.return_value = ValidationResult(
                cve_id="CVE-2025-12345",
                status=CVEStatus.RESERVED,
                is_ghost=True,
                registry_source="NVD",
            )
            
            # Call with lowercase
            result = validator.validate("cve-2025-12345")
            
            # Should be normalized in cache key
            assert "CVE-2025-12345" in validator._cache


class TestGhostClassification:
    """Tests for Ghost CVE classification logic."""
    
    @pytest.fixture
    def validator(self):
        """Create a CVEValidator instance."""
        return CVEValidator()
    
    def test_reserved_is_ghost(self, validator):
        """Test that RESERVED + found_in_wild = Ghost."""
        result = validator._create_result(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            found_in_wild=True,
            registry_source="NVD",
        )
        
        assert result.is_ghost is True
    
    def test_not_found_is_ghost(self, validator):
        """Test that NOT_FOUND + found_in_wild = Ghost."""
        result = validator._create_result(
            cve_id="CVE-2025-12345",
            status=CVEStatus.NOT_FOUND,
            found_in_wild=True,
            registry_source="NVD",
        )
        
        assert result.is_ghost is True
    
    def test_published_not_ghost(self, validator):
        """Test that PUBLISHED is not a Ghost."""
        result = validator._create_result(
            cve_id="CVE-2025-12345",
            status=CVEStatus.PUBLISHED,
            found_in_wild=True,
            registry_source="NVD",
        )
        
        assert result.is_ghost is False
    
    def test_reserved_not_in_wild_not_ghost(self, validator):
        """Test that RESERVED without wild sighting is not Ghost."""
        result = validator._create_result(
            cve_id="CVE-2025-12345",
            status=CVEStatus.RESERVED,
            found_in_wild=False,
            registry_source="NVD",
        )
        
        assert result.is_ghost is False
