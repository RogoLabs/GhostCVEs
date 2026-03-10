"""
Vendor Security Page Scrapers
==============================

Modules for scraping CVE information from vendor security advisory pages.
These are high-confidence sources since vendors authoritatively disclose
vulnerabilities in their own products.
"""

from src.discovery.vendors.base import BaseVendorScraper
from src.discovery.vendors.citrix import CitrixScraper
from src.discovery.vendors.ivanti import IvantiScraper
from src.discovery.vendors.palo_alto import PaloAltoScraper
from src.discovery.vendors.fortinet import FortinetScraper
from src.discovery.vendors.vmware import VMwareScraper

__all__ = [
    'BaseVendorScraper',
    'CitrixScraper',
    'IvantiScraper',
    'PaloAltoScraper',
    'FortinetScraper',
    'VMwareScraper',
]
