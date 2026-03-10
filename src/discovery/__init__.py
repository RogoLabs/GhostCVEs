"""
Discovery Module
================

Contains scrapers and collectors for identifying CVE mentions across
various public sources including GitHub, RSS feeds, and vendor advisories.
"""

from src.discovery.base import BaseDiscovery, DiscoveryResult
from src.discovery.github_discovery import GitHubDiscovery
from src.discovery.rss_discovery import RSSDiscovery
from src.discovery.vendor_discovery import VendorDiscovery
from src.discovery.exploitdb_discovery import ExploitDBDiscovery

__all__ = [
    "BaseDiscovery",
    "DiscoveryResult",
    "GitHubDiscovery",
    "RSSDiscovery",
    "VendorDiscovery",
    "ExploitDBDiscovery",
]
