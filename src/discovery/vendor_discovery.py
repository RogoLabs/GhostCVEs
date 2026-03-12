"""
Vendor Discovery Module
=======================

Discovers CVE mentions from vendor-specific security advisory
endpoints including Microsoft MSRC, Oracle CPU, and others.

Author: rogolabs.net
"""

import logging
from datetime import datetime
from typing import Iterator
from urllib.parse import urljoin

import requests

from src.config import (
    CVE_STRICT_PATTERN,
    VENDOR_ENDPOINTS,
    APP_SETTINGS,
    SourceType,
    VendorEndpoint,
)
from src.discovery.base import (
    BaseDiscovery,
    DiscoveryResult,
    DiscoveryError,
)


logger = logging.getLogger(__name__)


class VendorDiscovery(BaseDiscovery):
    """
    Discovery module for finding CVE mentions from vendor advisories.
    
    Queries vendor-specific security advisory APIs and pages to
    extract CVE references.
    
    Attributes:
        endpoints: List of vendor endpoints to query
        session: Requests session for HTTP calls
        github_token: GitHub token for GitHub Security Advisories API
    """
    
    def __init__(
        self,
        endpoints: list[VendorEndpoint] | None = None,
        github_token: str | None = None,
        enabled: bool = True,
        active_vendors: list[str] | None = None,
    ) -> None:
        """
        Initialize the vendor discovery module.

        Args:
            endpoints: List of vendor endpoints to query.
                       Defaults to VENDOR_ENDPOINTS from config.
            github_token: GitHub token for authenticated endpoints
            enabled: Whether this discovery module is active
            active_vendors: List of vendor names to actively scrape.
                          If None, uses default active list.
                          If provided, only these vendors will be scraped.
        """
        super().__init__(
            name="Vendor Discovery",
            source_type=SourceType.VENDOR_ADVISORY,
            enabled=enabled,
        )

        # Default active vendors list (start with high-value, tested vendors)
        default_active_vendors = [
            "Microsoft MSRC",
            "F5 Security Advisories",
            "Juniper Security Bulletins",
            # Additional vendors will be activated as they are tested
        ]

        # Use provided active_vendors or default
        self.active_vendors = active_vendors if active_vendors is not None else default_active_vendors

        # Get all available endpoints
        all_endpoints = endpoints or list(VENDOR_ENDPOINTS)

        # Filter to only active vendors
        self.endpoints = [
            ep for ep in all_endpoints
            if ep.name in self.active_vendors
        ]

        self.github_token = github_token
        self.session = self._create_session()
        self._seen_urls: set[str] = set()

        logger.info(
            f"VendorDiscovery initialized with {len(self.endpoints)} active vendors: "
            f"{', '.join(self.active_vendors)}"
        )
    
    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests session.
        
        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        session.headers.update({
            "User-Agent": APP_SETTINGS.user_agent,
            "Accept": "application/json, application/xml, text/html, */*",
        })
        return session
    
    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Execute vendor discovery and yield results.
        
        Iterates through configured vendor endpoints and extracts CVE mentions.
        
        Yields:
            DiscoveryResult for each unique CVE mention found
        """
        for endpoint in self.endpoints:
            self.logger.info(f"Processing vendor endpoint: {endpoint.name}")
            
            # Skip authenticated endpoints without token
            if endpoint.requires_auth and not self.github_token:
                self.logger.warning(
                    f"Skipping {endpoint.name}: requires authentication"
                )
                continue
            
            try:
                yield from self._process_endpoint(endpoint)
            except Exception as e:
                self.logger.error(
                    f"Failed to process vendor '{endpoint.name}': {e}"
                )
    
    def _process_endpoint(
        self,
        endpoint: VendorEndpoint,
    ) -> Iterator[DiscoveryResult]:
        """
        Process a single vendor endpoint.
        
        Args:
            endpoint: VendorEndpoint configuration object
        
        Yields:
            DiscoveryResult for each CVE found
        """
        url = urljoin(endpoint.base_url, endpoint.advisory_path)
        
        headers = {}
        if endpoint.requires_auth and self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        # Dispatch to appropriate handler based on vendor
        handler_map = {
            "Microsoft MSRC": self._process_msrc,
            "GitHub Security Advisories": self._process_github_advisories,
            "Apache Security": self._process_generic,
            "Mozilla Foundation": self._process_generic,
            "Oracle CPU": self._process_generic,
        }
        
        handler = handler_map.get(endpoint.name, self._process_generic)
        yield from handler(endpoint, url, headers)
    
    def _process_msrc(
        self,
        endpoint: VendorEndpoint,
        url: str,
        headers: dict,
    ) -> Iterator[DiscoveryResult]:
        """
        Process Microsoft MSRC security updates.
        
        Args:
            endpoint: VendorEndpoint configuration object
            url: API URL
            headers: HTTP headers
        
        Yields:
            DiscoveryResult for each CVE found
        """
        try:
            response = self.session.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for update in data.get("value", []):
                update_id = update.get("ID", "")
                update_url = (
                    f"https://msrc.microsoft.com/update-guide/vulnerability/{update_id}"
                )
                
                # Get detailed CVRF document
                cvrf_url = update.get("CvrfUrl", "")
                if cvrf_url:
                    yield from self._process_cvrf(endpoint, cvrf_url)
                
        except requests.RequestException as e:
            self.logger.error(f"MSRC API request failed: {e}")
        except Exception as e:
            self.logger.error(f"MSRC processing error: {e}")
    
    def _process_cvrf(
        self,
        endpoint: VendorEndpoint,
        cvrf_url: str,
    ) -> Iterator[DiscoveryResult]:
        """
        Process a CVRF (Common Vulnerability Reporting Framework) document.
        
        Args:
            endpoint: VendorEndpoint configuration object
            cvrf_url: URL to CVRF document
        
        Yields:
            DiscoveryResult for each CVE found
        """
        try:
            response = self.session.get(cvrf_url, timeout=30)
            response.raise_for_status()
            
            # Parse CVRF XML
            from xml.etree import ElementTree as ET
            
            root = ET.fromstring(response.content)
            
            # CVRF namespace
            ns = {"cvrf": "http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"}
            
            # Find all CVE references
            for vuln in root.findall(".//cvrf:Vulnerability", ns):
                cve_elem = vuln.find("cvrf:CVE", ns)
                if cve_elem is not None and cve_elem.text:
                    cve_id = cve_elem.text.strip()
                    
                    if not CVE_STRICT_PATTERN.match(cve_id):
                        continue
                    
                    # Get title
                    title_elem = vuln.find("cvrf:Title", ns)
                    title = title_elem.text if title_elem is not None else ""
                    
                    yield DiscoveryResult(
                        cve_id=cve_id,
                        source_type=SourceType.VENDOR_ADVISORY,
                        source_name=endpoint.name,
                        evidence_url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                        context=title[:200] if title else None,
                        confidence=1.0,
                        raw_data={
                            "cvrf_url": cvrf_url,
                            "title": title,
                        },
                    )
                    
        except Exception as e:
            self.logger.error(f"CVRF processing error: {e}")
    
    def _process_github_advisories(
        self,
        endpoint: VendorEndpoint,
        url: str,
        headers: dict,
    ) -> Iterator[DiscoveryResult]:
        """
        Process GitHub Security Advisories.
        
        Args:
            endpoint: VendorEndpoint configuration object
            url: API URL
            headers: HTTP headers
        
        Yields:
            DiscoveryResult for each CVE found
        """
        headers["Accept"] = "application/vnd.github+json"
        
        try:
            # Use GraphQL API for security advisories
            graphql_url = "https://api.github.com/graphql"
            
            query = """
            query {
                securityAdvisories(first: 100, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
                    nodes {
                        ghsaId
                        summary
                        description
                        severity
                        publishedAt
                        identifiers {
                            type
                            value
                        }
                        references {
                            url
                        }
                    }
                }
            }
            """
            
            response = self.session.post(
                graphql_url,
                headers=headers,
                json={"query": query},
                timeout=30,
            )
            response.raise_for_status()
            
            data = response.json()
            advisories = (
                data.get("data", {})
                .get("securityAdvisories", {})
                .get("nodes", [])
            )
            
            for advisory in advisories:
                # Extract CVE identifiers
                for identifier in advisory.get("identifiers", []):
                    if identifier.get("type") == "CVE":
                        cve_id = identifier.get("value", "")
                        
                        if not CVE_STRICT_PATTERN.match(cve_id):
                            continue
                        
                        ghsa_id = advisory.get("ghsaId", "")
                        advisory_url = f"https://github.com/advisories/{ghsa_id}"
                        
                        yield DiscoveryResult(
                            cve_id=cve_id,
                            source_type=SourceType.VENDOR_ADVISORY,
                            source_name=endpoint.name,
                            evidence_url=advisory_url,
                            context=advisory.get("summary", "")[:200],
                            confidence=1.0,
                            raw_data={
                                "ghsa_id": ghsa_id,
                                "severity": advisory.get("severity"),
                                "published_at": advisory.get("publishedAt"),
                            },
                        )
                        
        except requests.RequestException as e:
            self.logger.error(f"GitHub Advisories API request failed: {e}")
        except Exception as e:
            self.logger.error(f"GitHub Advisories processing error: {e}")
    
    def _process_generic(
        self,
        endpoint: VendorEndpoint,
        url: str,
        headers: dict,
    ) -> Iterator[DiscoveryResult]:
        """
        Process a generic vendor security page.
        
        Args:
            endpoint: VendorEndpoint configuration object
            url: Page URL
            headers: HTTP headers
        
        Yields:
            DiscoveryResult for each CVE found
        """
        try:
            response = self.session.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # Find all CVE IDs
            cve_ids = set(CVE_STRICT_PATTERN.findall(content))
            
            for cve_id in cve_ids:
                evidence_url = url
                
                # Skip if we've already seen this URL
                seen_key = f"{cve_id}:{evidence_url}"
                if seen_key in self._seen_urls:
                    continue
                self._seen_urls.add(seen_key)
                
                yield DiscoveryResult(
                    cve_id=cve_id,
                    source_type=SourceType.VENDOR_ADVISORY,
                    source_name=endpoint.name,
                    evidence_url=evidence_url,
                    context=None,
                    confidence=0.7,
                    raw_data={
                        "vendor": endpoint.name,
                        "source_url": url,
                    },
                )
                
        except requests.RequestException as e:
            self.logger.error(f"Generic vendor request failed: {e}")
        except Exception as e:
            self.logger.error(f"Generic vendor processing error: {e}")
