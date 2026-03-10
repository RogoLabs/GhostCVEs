"""
Vendor Security Page Scrapers
==============================

Modules for scraping CVE information from vendor security advisory pages.
These are high-confidence sources since vendors authoritatively disclose
vulnerabilities in their own products.
"""

from src.discovery.vendors.base import BaseVendorScraper

__all__ = [
    'BaseVendorScraper',
]
