"""
Registry Module
===============

Handles CVE validation against official registries including
local CVEProject/cvelistV5 repository, local NVD JSON file,
and MITRE CVE API fallback.
"""

from src.registry.validator import CVEValidator, CVEStatus
from src.registry.nvd_local import NVDLocalRegistry

__all__ = ["CVEValidator", "CVEStatus", "NVDLocalRegistry"]
