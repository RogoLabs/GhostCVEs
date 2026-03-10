"""
Enums for world-class ghost detection system.

New classification types for 6-stage pipeline.
"""

from enum import Enum


class DisclosureStatus(Enum):
    """
    Public disclosure status.

    Determines if CVE mention constitutes true public disclosure.
    """
    PUBLIC = "PUBLIC"  # CVE + description OR CVE in patch notes
    MENTIONED_ONLY = "MENTIONED_ONLY"  # Just CVE ID mentioned, no details
    UNCERTAIN = "UNCERTAIN"  # Can't determine from context


class DisclosureType(Enum):
    """
    Type of public disclosure.

    Categorizes how CVE was publicly disclosed.
    """
    ADVISORY = "ADVISORY"  # Security advisory
    PATCH_NOTES = "PATCH_NOTES"  # Patch notes / release notes
    EXPLOIT = "EXPLOIT"  # Exploit publication
    CONFERENCE = "CONFERENCE"  # Conference presentation
    OTHER = "OTHER"  # Other public disclosure


class GhostRootCause(Enum):
    """
    Root cause why CVE is a Ghost.

    Identifies the underlying reason for ghost status.
    """
    VENDOR_FAILURE = "VENDOR_FAILURE"  # Vendor disclosed but didn't publish CVE
    CNA_DELAY = "CNA_DELAY"  # CNA hasn't processed publication request
    SYSTEM_LAG = "SYSTEM_LAG"  # API/sync delays (rare with 6hr grace)
    FAKE_CVE = "FAKE_CVE"  # Suspicious patterns, likely fake
    EMBARGO = "EMBARGO"  # Under coordinated disclosure
    UNKNOWN = "UNKNOWN"  # Can't determine yet


class CVEStatus(Enum):
    """
    CVE lifecycle status (existing enum, re-export for convenience).

    Attributes:
        RESERVED: CVE ID is reserved but details not yet published
        PUBLISHED: CVE details are publicly available
        REJECTED: CVE ID was rejected (duplicate, invalid, etc.)
        NOT_FOUND: CVE ID does not exist in the registry
        GHOST: CVE is referenced in public sources but RESERVED/NOT_FOUND (computed)
        ERROR: Could not determine status due to API error
    """
    RESERVED = "RESERVED"
    PUBLISHED = "PUBLISHED"
    REJECTED = "REJECTED"
    NOT_FOUND = "NOT_FOUND"
    GHOST = "GHOST"
    ERROR = "ERROR"
