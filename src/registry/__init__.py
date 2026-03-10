"""
Registry Module
===============

Handles CVE validation against official registries including
local CVEProject/cvelistV5 repository, local NVD JSON file,
and MITRE CVE API fallback.
"""

from src.models.enums import CVEStatus
from src.registry.validator import CVEValidator
from src.registry.nvd_local import NVDLocalRegistry

__all__ = ["CVEValidator", "CVEStatus", "NVDLocalRegistry"]
