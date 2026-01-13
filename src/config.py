"""
Ghost Hunter Configuration
==========================

Central configuration module containing RSS feeds, API endpoints,
search patterns, and runtime settings.

Author: rogolabs.net
"""

from dataclasses import dataclass, field
from datetime import datetime
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
# CVE ID Validation
# =============================================================================

@dataclass(frozen=True)
class CVEValidationConfig:
    """
    Configuration for CVE ID plausibility validation.
    
    Filters out obviously fake or improbable CVE IDs based on:
    - Year validity (not in the future)
    - ID range plausibility for the given year
    - Pattern detection (all zeros, repeated digits, embedded years)
    """
    
    # Current year for validation (updated at runtime)
    # Maximum reasonable CVE ID numbers by year (approximate, based on historical data)
    # These are rough upper bounds - real counts vary but this catches obvious fakes
    max_id_by_year: dict[int, int] = field(default_factory=lambda: {
        2025: 70000,   # ~60k CVEs expected by end of 2025
        2026: 15000,   # We're in January 2026, so far fewer allocated
        2027: 0,       # Future year - no CVEs yet
        2028: 0,
        2029: 0,
    })
    
    # For current year, maximum plausible ID based on month
    # Roughly ~5000 CVEs/month gets allocated, so month * 6000 is generous
    max_id_per_month: int = 6000
    
    # Suspicious patterns to reject
    reject_all_zeros: bool = True          # CVE-2025-0000000
    reject_all_same_digit: bool = True     # CVE-2025-11111, CVE-2025-99999
    reject_embedded_years: bool = True     # CVE-2025-412026 (contains "2026")
    
    # Minimum ID (CVE IDs start at 0001 typically)
    min_id: int = 1


# Create default config
CVE_VALIDATION_CONFIG: Final[CVEValidationConfig] = CVEValidationConfig()


def validate_cve_id(cve_id: str, config: CVEValidationConfig | None = None) -> tuple[bool, str]:
    """
    Validate a CVE ID for plausibility.
    
    Checks if a CVE ID is structurally valid and plausible given current date
    and historical CVE allocation patterns.
    
    Args:
        cve_id: CVE identifier to validate (e.g., CVE-2025-12345)
        config: Optional validation config (uses default if None)
    
    Returns:
        Tuple of (is_valid, reason) where reason explains rejection
    
    Examples:
        >>> validate_cve_id("CVE-2025-12345")
        (True, "")
        >>> validate_cve_id("CVE-2027-12345")  # Future year
        (False, "Year 2027 is in the future")
        >>> validate_cve_id("CVE-2026-99268")  # Implausibly high for Jan 2026
        (False, "ID 99268 is implausibly high for year 2026")
    """
    if config is None:
        config = CVE_VALIDATION_CONFIG
    
    cve_id = cve_id.upper().strip()
    
    # Basic format check
    if not cve_id.startswith("CVE-"):
        return (False, "Invalid format: must start with CVE-")
    
    parts = cve_id.split("-")
    if len(parts) != 3:
        return (False, "Invalid format: must be CVE-YYYY-NNNNN")
    
    try:
        year = int(parts[1])
        id_num = int(parts[2])
    except ValueError:
        return (False, "Invalid format: year and ID must be numeric")
    
    # Get current date
    now = datetime.utcnow()
    current_year = now.year
    current_month = now.month
    
    # Check year validity
    if year > current_year:
        return (False, f"Year {year} is in the future")
    
    if year < 1999:  # CVEs started in 1999
        return (False, f"Year {year} predates CVE system (started 1999)")
    
    # Check ID minimum
    if id_num < config.min_id:
        return (False, f"ID {id_num} is below minimum ({config.min_id})")
    
    # Check suspicious patterns
    id_str = parts[2]
    
    if config.reject_all_zeros and id_str.replace("0", "") == "":
        return (False, f"ID {id_str} is all zeros (obviously fake)")
    
    if config.reject_all_same_digit and len(set(id_str)) == 1 and len(id_str) >= 4:
        return (False, f"ID {id_str} is all same digit (suspicious pattern)")
    
    if config.reject_embedded_years:
        # Check for embedded years like "2026" in "412026" or "3272025"
        for check_year in range(2024, current_year + 2):
            year_str = str(check_year)
            # Only flag if embedded (not at start) and ID is suspiciously formed
            if year_str in id_str and not id_str.startswith(year_str):
                if len(id_str) >= 6:  # Long IDs with embedded years are suspicious
                    return (False, f"ID {id_str} contains embedded year {check_year} (suspicious)")
    
    # Check plausibility for the given year
    if year == current_year:
        # For current year, estimate based on month
        max_plausible = current_month * config.max_id_per_month
        if id_num > max_plausible:
            return (False, f"ID {id_num} is implausibly high for {year} in month {current_month}")
    elif year in config.max_id_by_year:
        max_for_year = config.max_id_by_year[year]
        if max_for_year == 0:
            return (False, f"Year {year} has no CVEs allocated yet")
        if id_num > max_for_year:
            return (False, f"ID {id_num} exceeds plausible maximum ({max_for_year}) for year {year}")
    
    return (True, "")


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
# GitHub Repository Quality & Blacklist Configuration
# =============================================================================

@dataclass(frozen=True)
class GitHubQualityConfig:
    """Configuration for filtering low-quality or fake GitHub repositories."""
    
    # Blacklisted repositories (known fake or low-quality sources)
    # Format: "owner/repo"
    blacklisted_repos: tuple[str, ...] = (
        "koreatest12/auto",
        "Hex0rc1st/CVE_POC_monitor",
        # Add more as discovered
    )
    
    # Blacklisted users/organizations (prolific fake CVE posters)
    blacklisted_users: tuple[str, ...] = (
        "koreatest12",
        "Hex0rc1st",
        "Abhishek-khowal",  # Fake CVE test repos
        "Abhinandan-Khurana",  # Demo/test data with fake CVE IDs
        # Add more as discovered
    )
    
    # Repository quality thresholds
    min_stars: int = 0  # Minimum stars (0 = no filter, suggest 3+ for stricter)
    min_age_days: int = 1  # Minimum repo age in days (helps filter brand-new spam repos)
    require_description: bool = True  # Repo must have a description
    require_license: bool = False  # Repo should have a license (optional)
    
    # Confidence scoring weights (0.0 to 1.0)
    star_weight: float = 0.3  # Weight for star count in confidence score
    age_weight: float = 0.2  # Weight for repo age
    activity_weight: float = 0.2  # Weight for recent activity
    metadata_weight: float = 0.3  # Weight for metadata quality (description, readme, etc.)
    
    # Activity thresholds for confidence scoring
    good_star_count: int = 10  # Stars indicating a quality repo
    good_age_days: int = 30  # Age indicating established repo
    recent_activity_days: int = 180  # Consider activity within this window


GITHUB_QUALITY_CONFIG: Final[GitHubQualityConfig] = GitHubQualityConfig()


# =============================================================================
# CVE Registry API Configuration
# =============================================================================

@dataclass(frozen=True)
class RegistryConfig:
    """Configuration for CVE registry validation."""
    
    # MITRE CVE Services API (fallback only)
    mitre_api_base: str = "https://cveawg.mitre.org/api"
    mitre_cve_endpoint: str = "/cve/{cve_id}"
    
    # Local NVD JSON file (primary source for NVD data)
    nvd_local_url: str = "https://nvd.handsonhacking.org/nvd.json"
    nvd_local_filename: str = "nvd.json"
    nvd_local_max_age_hours: int = 24  # Re-download if older than this
    
    # Legacy NVD API 2.0 (deprecated - using local file instead)
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_cve_endpoint: str = "?cveId={cve_id}"
    
    # CVE.org API
    cve_org_api_base: str = "https://cveawg.mitre.org/api/cve"
    
    # Request settings
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    
    # Rate limiting (for MITRE API fallback only)
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
