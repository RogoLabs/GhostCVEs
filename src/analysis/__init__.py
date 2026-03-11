"""
Analysis Module
===============

Tools for analyzing source performance, reliability, and coverage.
"""

from src.analysis.source_audit import (
    SourceMetrics,
    SourceAuditor,
    calculate_reliability_score,
    identify_redundant_sources,
    classify_source,
    generate_audit_report,
)

__all__ = [
    "SourceMetrics",
    "SourceAuditor",
    "calculate_reliability_score",
    "identify_redundant_sources",
    "classify_source",
    "generate_audit_report",
]
