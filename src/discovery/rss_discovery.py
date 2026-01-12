"""
RSS Discovery Module
====================

Discovers CVE mentions in RSS feeds from security advisories,
research blogs, and vulnerability disclosure sources.

Author: rogolabs.net
"""

import gzip
import io
import json
import logging
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Iterator
from xml.etree import ElementTree as ET

import requests

from src.config import (
    CVE_STRICT_PATTERN,
    RSS_FEEDS,
    APP_SETTINGS,
    SourceType,
    RSSFeed,
)
from src.discovery.base import (
    BaseDiscovery,
    DiscoveryResult,
    DiscoveryError,
)


logger = logging.getLogger(__name__)


class RSSDiscovery(BaseDiscovery):
    """
    Discovery module for finding CVE mentions in RSS feeds.
    
    Supports standard RSS/Atom feeds as well as JSON-based security
    data feeds from NVD, CISA, and vendor sources.
    
    Attributes:
        feeds: List of RSS feeds to monitor
        session: Requests session for HTTP calls
    """
    
    def __init__(
        self,
        feeds: list[RSSFeed] | None = None,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the RSS discovery module.
        
        Args:
            feeds: List of RSS feeds to monitor. Defaults to RSS_FEEDS from config.
            enabled: Whether this discovery module is active
        """
        super().__init__(
            name="RSS Discovery",
            source_type=SourceType.RSS_FEED,
            enabled=enabled,
        )
        
        self.feeds = feeds or list(RSS_FEEDS)
        self.session = self._create_session()
        self._seen_urls: set[str] = set()
    
    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests session.
        
        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        session.headers.update({
            "User-Agent": APP_SETTINGS.user_agent,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, application/json, text/xml, */*",
        })
        return session
    
    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Execute RSS discovery and yield results.
        
        Iterates through configured feeds and extracts CVE mentions.
        
        Yields:
            DiscoveryResult for each unique CVE mention found
        """
        for feed in self.feeds:
            self.logger.info(f"Processing feed: {feed.name}")
            
            try:
                yield from self._process_feed(feed)
            except Exception as e:
                self.logger.error(f"Failed to process feed '{feed.name}': {e}")
    
    def _process_feed(self, feed: RSSFeed) -> Iterator[DiscoveryResult]:
        """
        Process a single RSS feed.
        
        Args:
            feed: RSSFeed configuration object
        
        Yields:
            DiscoveryResult for each CVE found
        """
        try:
            response = self.session.get(feed.url, timeout=30)
            response.raise_for_status()
            
            content_type = response.headers.get("Content-Type", "").lower()
            content = response.content
            
            # Handle gzipped content
            if feed.url.endswith(".gz"):
                content = gzip.decompress(content)
            
            # Determine format and parse accordingly
            if "json" in content_type or feed.url.endswith(".json"):
                yield from self._parse_json_feed(feed, content)
            else:
                yield from self._parse_xml_feed(feed, content)
                
        except requests.RequestException as e:
            self.logger.error(f"HTTP error fetching {feed.name}: {e}")
            raise DiscoveryError(feed.name, f"HTTP request failed: {e}", e)
    
    def _parse_xml_feed(
        self,
        feed: RSSFeed,
        content: bytes,
    ) -> Iterator[DiscoveryResult]:
        """
        Parse an XML-based RSS/Atom feed.
        
        Args:
            feed: RSSFeed configuration object
            content: Raw XML content bytes
        
        Yields:
            DiscoveryResult for each CVE found
        """
        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            self.logger.error(f"XML parse error for {feed.name}: {e}")
            return
        
        # Determine feed type and extract items
        items = self._extract_feed_items(root)
        
        for item in items:
            yield from self._process_feed_item(feed, item)
    
    def _extract_feed_items(self, root: ET.Element) -> list[dict]:
        """
        Extract items from RSS or Atom feed XML.
        
        Args:
            root: Root element of parsed XML
        
        Returns:
            List of item dictionaries with title, link, description
        """
        items = []
        
        # Define namespaces
        namespaces = {
            "atom": "http://www.w3.org/2005/Atom",
            "content": "http://purl.org/rss/1.0/modules/content/",
        }
        
        # Try RSS 2.0 format
        for item in root.findall(".//item"):
            items.append({
                "title": self._get_element_text(item, "title"),
                "link": self._get_element_text(item, "link"),
                "description": self._get_element_text(item, "description"),
                "content": self._get_element_text(
                    item, "content:encoded", namespaces
                ),
                "pubDate": self._get_element_text(item, "pubDate"),
            })
        
        # Try Atom format
        for entry in root.findall(".//atom:entry", namespaces):
            link_elem = entry.find("atom:link[@href]", namespaces)
            link = link_elem.get("href") if link_elem is not None else ""
            
            items.append({
                "title": self._get_element_text(entry, "atom:title", namespaces),
                "link": link,
                "description": self._get_element_text(
                    entry, "atom:summary", namespaces
                ),
                "content": self._get_element_text(
                    entry, "atom:content", namespaces
                ),
                "pubDate": self._get_element_text(
                    entry, "atom:updated", namespaces
                ),
            })
        
        # Try plain Atom without namespace
        if not items:
            for entry in root.findall(".//entry"):
                link_elem = entry.find("link[@href]")
                link = link_elem.get("href") if link_elem is not None else ""
                
                items.append({
                    "title": self._get_element_text(entry, "title"),
                    "link": link,
                    "description": self._get_element_text(entry, "summary"),
                    "content": self._get_element_text(entry, "content"),
                    "pubDate": self._get_element_text(entry, "updated"),
                })
        
        return items
    
    def _get_element_text(
        self,
        parent: ET.Element,
        tag: str,
        namespaces: dict | None = None,
    ) -> str:
        """
        Safely get text content of an XML element.
        
        Args:
            parent: Parent element to search in
            tag: Tag name to find
            namespaces: Optional namespace mapping
        
        Returns:
            Element text or empty string
        """
        elem = parent.find(tag, namespaces) if namespaces else parent.find(tag)
        return elem.text.strip() if elem is not None and elem.text else ""
    
    def _parse_date(self, date_str: str | None) -> datetime | None:
        """
        Parse various date formats from RSS/Atom feeds.
        
        Supports RFC 2822 (RSS), ISO 8601 (Atom), and common variants.
        
        Args:
            date_str: Date string to parse
        
        Returns:
            datetime object or None if parsing fails
        """
        if not date_str:
            return None
        
        date_str = date_str.strip()
        
        # Try RFC 2822 format (common in RSS)
        # e.g., "Thu, 09 Jan 2026 12:00:00 GMT"
        try:
            return parsedate_to_datetime(date_str)
        except (ValueError, TypeError):
            pass
        
        # Try ISO 8601 formats (common in Atom)
        iso_formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]
        
        for fmt in iso_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        # Try with timezone suffix stripped
        if date_str.endswith("Z"):
            try:
                return datetime.fromisoformat(date_str[:-1])
            except ValueError:
                pass
        
        self.logger.debug(f"Could not parse date: {date_str}")
        return None
    
    def _process_feed_item(
        self,
        feed: RSSFeed,
        item: dict,
    ) -> Iterator[DiscoveryResult]:
        """
        Process a single feed item and extract CVE mentions.
        
        Args:
            feed: RSSFeed configuration object
            item: Parsed feed item dictionary
        
        Yields:
            DiscoveryResult for each CVE found
        """
        # Combine all text fields for CVE search
        searchable_text = " ".join([
            item.get("title", ""),
            item.get("description", ""),
            item.get("content", ""),
        ])
        
        link = item.get("link", feed.url)
        
        if link in self._seen_urls:
            return
        self._seen_urls.add(link)
        
        # Parse publication date from source
        pub_date = self._parse_date(item.get("pubDate"))
        
        # Find all CVE IDs
        cve_ids = set(CVE_STRICT_PATTERN.findall(searchable_text))
        
        for cve_id in cve_ids:
            # Map source type
            source_type = self._map_source_type(feed.source_type)
            
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=source_type,
                source_name=feed.name,
                evidence_url=link,
                discovered_at=pub_date or datetime.utcnow(),
                context=item.get("title", "")[:200],
                confidence=0.85,
                raw_data={
                    "feed_name": feed.name,
                    "feed_url": feed.url,
                    "item_title": item.get("title", ""),
                    "pub_date": item.get("pubDate", ""),
                },
            )
    
    def _parse_json_feed(
        self,
        feed: RSSFeed,
        content: bytes,
    ) -> Iterator[DiscoveryResult]:
        """
        Parse a JSON-based security feed.
        
        Args:
            feed: RSSFeed configuration object
            content: Raw JSON content bytes
        
        Yields:
            DiscoveryResult for each CVE found
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parse error for {feed.name}: {e}")
            return
        
        # Handle different JSON structures
        if "vulnerabilities" in data:
            # CISA KEV format
            yield from self._parse_cisa_kev(feed, data)
        elif "CVE_Items" in data:
            # NVD JSON 1.1 format
            yield from self._parse_nvd_json(feed, data)
        elif isinstance(data, list):
            # Generic list of items
            for item in data:
                yield from self._parse_json_item(feed, item)
        elif isinstance(data, dict):
            # Single item or nested structure
            yield from self._parse_json_item(feed, data)
    
    def _parse_cisa_kev(
        self,
        feed: RSSFeed,
        data: dict,
    ) -> Iterator[DiscoveryResult]:
        """
        Parse CISA Known Exploited Vulnerabilities format.
        
        Args:
            feed: RSSFeed configuration object
            data: Parsed JSON data
        
        Yields:
            DiscoveryResult for each CVE found
        """
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            
            if not CVE_STRICT_PATTERN.match(cve_id):
                continue
            
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=SourceType.GOVERNMENT_ADVISORY,
                source_name=feed.name,
                evidence_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                context=f"{vuln.get('vendorProject', '')} - {vuln.get('product', '')}",
                confidence=1.0,
                raw_data={
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerability_name": vuln.get("vulnerabilityName"),
                    "date_added": vuln.get("dateAdded"),
                    "short_description": vuln.get("shortDescription"),
                },
            )
    
    def _parse_nvd_json(
        self,
        feed: RSSFeed,
        data: dict,
    ) -> Iterator[DiscoveryResult]:
        """
        Parse NVD JSON 1.1 format.
        
        Args:
            feed: RSSFeed configuration object
            data: Parsed JSON data
        
        Yields:
            DiscoveryResult for each CVE found
        """
        for item in data.get("CVE_Items", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")
            
            if not CVE_STRICT_PATTERN.match(cve_id):
                continue
            
            # Extract description
            description = ""
            desc_data = cve_data.get("description", {}).get("description_data", [])
            if desc_data:
                description = desc_data[0].get("value", "")
            
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=SourceType.RSS_FEED,
                source_name=feed.name,
                evidence_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                context=description[:200] if description else None,
                confidence=1.0,
                raw_data={
                    "published_date": item.get("publishedDate"),
                    "last_modified_date": item.get("lastModifiedDate"),
                },
            )
    
    def _parse_json_item(
        self,
        feed: RSSFeed,
        item: dict,
    ) -> Iterator[DiscoveryResult]:
        """
        Parse a generic JSON item for CVE mentions.
        
        Args:
            feed: RSSFeed configuration object
            item: JSON item dictionary
        
        Yields:
            DiscoveryResult for each CVE found
        """
        # Convert item to string for CVE search
        item_str = json.dumps(item)
        
        cve_ids = set(CVE_STRICT_PATTERN.findall(item_str))
        
        for cve_id in cve_ids:
            # Try to extract a URL from the item
            url = (
                item.get("url") or
                item.get("link") or
                item.get("advisory_url") or
                feed.url
            )
            
            # Try to extract context
            context = (
                item.get("title") or
                item.get("description") or
                item.get("summary") or
                ""
            )[:200]
            
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=self._map_source_type(feed.source_type),
                source_name=feed.name,
                evidence_url=url,
                context=context if context else None,
                confidence=0.8,
                raw_data={
                    "feed_name": feed.name,
                    "item_title": item.get("title", "")[:100] if item.get("title") else None,
                },
            )
    
    def _map_source_type(self, feed_source_type: str) -> str:
        """
        Map feed source type to SourceType constant.
        
        Args:
            feed_source_type: Source type from feed configuration
        
        Returns:
            Mapped SourceType constant
        """
        mapping = {
            "vulnerability_broker": SourceType.VENDOR_ADVISORY,
            "research_team": SourceType.RESEARCH_BLOG,
            "vendor_advisory": SourceType.VENDOR_ADVISORY,
            "distro_advisory": SourceType.DISTRO_ADVISORY,
            "government_advisory": SourceType.GOVERNMENT_ADVISORY,
            "mailing_list": SourceType.MAILING_LIST,
            "registry": SourceType.RSS_FEED,
        }
        return mapping.get(feed_source_type, SourceType.RSS_FEED)
