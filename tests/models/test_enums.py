import pytest
from src.models.enums import (
    DisclosureStatus,
    DisclosureType,
    GhostRootCause,
    CVEStatus
)


def test_disclosure_status_values():
    """Test DisclosureStatus enum has correct values."""
    assert DisclosureStatus.PUBLIC.value == "PUBLIC"
    assert DisclosureStatus.MENTIONED_ONLY.value == "MENTIONED_ONLY"
    assert DisclosureStatus.UNCERTAIN.value == "UNCERTAIN"


def test_disclosure_type_values():
    """Test DisclosureType enum has correct values."""
    assert DisclosureType.ADVISORY.value == "ADVISORY"
    assert DisclosureType.PATCH_NOTES.value == "PATCH_NOTES"
    assert DisclosureType.EXPLOIT.value == "EXPLOIT"
    assert DisclosureType.CONFERENCE.value == "CONFERENCE"
    assert DisclosureType.OTHER.value == "OTHER"


def test_ghost_root_cause_values():
    """Test GhostRootCause enum has correct values."""
    assert GhostRootCause.VENDOR_FAILURE.value == "VENDOR_FAILURE"
    assert GhostRootCause.CNA_DELAY.value == "CNA_DELAY"
    assert GhostRootCause.SYSTEM_LAG.value == "SYSTEM_LAG"
    assert GhostRootCause.FAKE_CVE.value == "FAKE_CVE"
    assert GhostRootCause.EMBARGO.value == "EMBARGO"
    assert GhostRootCause.UNKNOWN.value == "UNKNOWN"


def test_cve_status_values():
    """Test CVEStatus enum (existing, verify compatibility)."""
    assert hasattr(CVEStatus, 'PUBLISHED')
    assert hasattr(CVEStatus, 'RESERVED')
    assert hasattr(CVEStatus, 'NOT_FOUND')
    assert hasattr(CVEStatus, 'REJECTED')
