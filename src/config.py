"""
Ghost Hunter Configuration
==========================

Central configuration module containing RSS feeds, API endpoints,
search patterns, and runtime settings.

Author: rogolabs.net
"""

from dataclasses import dataclass, field
from typing import Final
import re


# =============================================================================
# CVE Pattern Configuration
# =============================================================================

CVE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"CVE-202[5-9]-\d{4,7}",
    re.IGNORECASE
)

CVE_STRICT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\bCVE-202[5-9]-\d{4,7}\b",
    re.IGNORECASE
)


# =============================================================================
# RSS Feed Sources
# =============================================================================

@dataclass(frozen=True)
class RSSFeed:
    """Represents an RSS feed source for CVE intelligence."""
    name: str
    url: str
    source_type: str
    priority: int = 1


RSS_FEEDS: Final[list[RSSFeed]] = [
    # Zero Day Initiative
    RSSFeed(
        name="ZDI Advisories",
        url="https://www.zerodayinitiative.com/rss/published/",
        source_type="vulnerability_broker",
        priority=1
    ),
    RSSFeed(
        name="ZDI Upcoming",
        url="https://www.zerodayinitiative.com/rss/upcoming/",
        source_type="vulnerability_broker",
        priority=1
    ),
    
    # Google Project Zero
    RSSFeed(
        name="Project Zero Blog",
        url="https://googleprojectzero.blogspot.com/feeds/posts/default",
        source_type="research_team",
        priority=1
    ),
    
    # Cisco PSIRT
    RSSFeed(
        name="Cisco PSIRT",
        url="https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        source_type="vendor_advisory",
        priority=2
    ),
    
    # Debian Security
    RSSFeed(
        name="Debian Security Announce",
        url="https://www.debian.org/security/dsa",
        source_type="distro_advisory",
        priority=2
    ),
    RSSFeed(
        name="Debian Security Tracker",
        url="https://security-tracker.debian.org/tracker/data/json",
        source_type="distro_advisory",
        priority=2
    ),
    
    # Ubuntu USN
    RSSFeed(
        name="Ubuntu Security Notices",
        url="https://ubuntu.com/security/notices/rss.xml",
        source_type="distro_advisory",
        priority=2
    ),
    
    # Red Hat RHSA
    RSSFeed(
        name="Red Hat Security Advisories",
        url="https://access.redhat.com/hydra/rest/securitydata/cve.json",
        source_type="vendor_advisory",
        priority=2
    ),
    RSSFeed(
        name="Red Hat RHSA RSS",
        url="https://www.redhat.com/security/data/metrics/rhsa.xml",
        source_type="vendor_advisory",
        priority=2
    ),
    
    # CISA
    RSSFeed(
        name="CISA Known Exploited Vulnerabilities",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        source_type="government_advisory",
        priority=1
    ),
    
    # NVD
    RSSFeed(
        name="NVD CVE Feed",
        url="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
        source_type="registry",
        priority=3
    ),
    
    # Full Disclosure / Security Mailing Lists
    RSSFeed(
        name="Full Disclosure",
        url="https://seclists.org/rss/fulldisclosure.rss",
        source_type="mailing_list",
        priority=2
    ),
    RSSFeed(
        name="OSS Security",
        url="https://seclists.org/rss/oss-sec.rss",
        source_type="mailing_list",
        priority=2
    ),
]


# =============================================================================
# GitHub Search Configuration
# =============================================================================

@dataclass(frozen=True)
class GitHubSearchConfig:
    """Configuration for GitHub code search."""
    base_url: str = "https://api.github.com"
    search_endpoint: str = "/search/code"
    commits_endpoint: str = "/search/commits"
    
    # Search queries for finding CVE mentions
    search_queries: tuple[str, ...] = (
        "CVE-2025",
        "CVE-2026",
    )
    
    # File extensions to prioritize
    priority_extensions: tuple[str, ...] = (
        ".md",
        ".txt",
        ".rst",
        ".yaml",
        ".yml",
        ".json",
        ".xml",
    )
    
    # Rate limiting
    requests_per_minute: int = 30
    search_results_per_page: int = 100
    max_pages: int = 10


GITHUB_CONFIG: Final[GitHubSearchConfig] = GitHubSearchConfig()


# =============================================================================
# CVE Registry API Configuration
# =============================================================================

@dataclass(frozen=True)
class RegistryConfig:
    """Configuration for CVE registry validation."""
    
    # MITRE CVE Services API
    mitre_api_base: str = "https://cveawg.mitre.org/api"
    mitre_cve_endpoint: str = "/cve/{cve_id}"
    
    # NVD API 2.0
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_cve_endpoint: str = "?cveId={cve_id}"
    
    # CVE.org API
    cve_org_api_base: str = "https://cveawg.mitre.org/api/cve"
    
    # Request settings
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    
    # Rate limiting (NVD allows 5 requests per 30 seconds without API key)
    nvd_requests_per_window: int = 5
    nvd_window_seconds: int = 30


REGISTRY_CONFIG: Final[RegistryConfig] = RegistryConfig()


# =============================================================================
# Database Configuration
# =============================================================================

@dataclass
class DatabaseConfig:
    """Configuration for SQLite database."""
    database_path: str = "ghost_log.db"
    echo_sql: bool = False
    pool_size: int = 5
    max_overflow: int = 10


DATABASE_CONFIG: DatabaseConfig = DatabaseConfig()


# =============================================================================
# Application Settings
# =============================================================================

@dataclass
class AppSettings:
    """General application settings."""
    
    # Concurrency
    max_workers: int = 10
    discovery_timeout_seconds: int = 300
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    log_file: str = "ghost_hunter.log"
    
    # Output
    output_dir: str = "reports"
    json_output: bool = True
    csv_output: bool = True
    
    # Ghost CVE thresholds
    limbo_warning_days: int = 7
    limbo_critical_days: int = 30
    
    # User Agent for HTTP requests
    user_agent: str = "GhostHunter/1.0 (rogolabs.net; CVE Research)"


APP_SETTINGS: AppSettings = AppSettings()


# =============================================================================
# Vendor-Specific Scrapers Configuration
# =============================================================================

@dataclass(frozen=True)
class VendorEndpoint:
    """Configuration for vendor-specific security advisory endpoints."""
    name: str
    base_url: str
    advisory_path: str
    source_type: str
    requires_auth: bool = False


VENDOR_ENDPOINTS: Final[list[VendorEndpoint]] = [
    VendorEndpoint(
        name="Microsoft MSRC",
        base_url="https://api.msrc.microsoft.com",
        advisory_path="/cvrf/v2.0/updates",
        source_type="vendor_advisory"
    ),
    VendorEndpoint(
        name="Oracle CPU",
        base_url="https://www.oracle.com",
        advisory_path="/security-alerts/",
        source_type="vendor_advisory"
    ),
    VendorEndpoint(
        name="Apache Security",
        base_url="https://www.apache.org",
        advisory_path="/security/",
        source_type="vendor_advisory"
    ),
    VendorEndpoint(
        name="Mozilla Foundation",
        base_url="https://www.mozilla.org",
        advisory_path="/en-US/security/advisories/",
        source_type="vendor_advisory"
    ),
    VendorEndpoint(
        name="GitHub Security Advisories",
        base_url="https://api.github.com",
        advisory_path="/advisories",
        source_type="platform_advisory",
        requires_auth=True
    ),
]


# =============================================================================
# Status Constants
# =============================================================================

class CVEState:
    """CVE lifecycle states."""
    RESERVED: str = "RESERVED"
    PUBLISHED: str = "PUBLISHED"
    REJECTED: str = "REJECTED"
    NOT_FOUND: str = "NOT_FOUND"
    GHOST: str = "GHOST"  # Found in wild but RESERVED/NOT_FOUND in registry


class SourceType:
    """Classification of discovery sources."""
    GITHUB_COMMIT: str = "github_commit"
    GITHUB_CODE: str = "github_code"
    GITHUB_ISSUE: str = "github_issue"
    RSS_FEED: str = "rss_feed"
    VENDOR_ADVISORY: str = "vendor_advisory"
    MAILING_LIST: str = "mailing_list"
    RESEARCH_BLOG: str = "research_blog"
    DISTRO_ADVISORY: str = "distro_advisory"
    GOVERNMENT_ADVISORY: str = "government_advisory"
