"""
Pipeline Module
===============

Orchestration and coordination of the Ghost CVE detection pipeline.

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
