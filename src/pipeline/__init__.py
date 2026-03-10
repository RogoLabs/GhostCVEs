"""
Pipeline Module
===============

6-stage pipeline for world-class Ghost CVE detection:
1. Discovery - Find CVE mentions across 23 sources
2. Disclosure Classification - Analyze public disclosure status
3. Multi-Source Validation - CVE.org API + local registries
4. Ghost Analysis - Apply 6-hour grace period and confidence threshold
5. Root Cause Detection - Determine why CVE is a ghost
6. Continuous Learning - Track resolutions and update reliability scores

Author: rogolabs.net
"""

from src.pipeline.orchestrator import (
    PipelineOrchestrator,
    PipelineStats,
    ProcessedCVE,
)

__all__ = [
    "PipelineOrchestrator",
    "PipelineStats",
    "ProcessedCVE",
]