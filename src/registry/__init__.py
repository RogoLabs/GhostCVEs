"""
Registry Module
===============

Handles CVE validation against official registries including
NVD JSON 5.0 format and MITRE CVE API.
"""

from src.registry.validator import CVEValidator, CVEStatus

__all__ = ["CVEValidator", "CVEStatus"]
