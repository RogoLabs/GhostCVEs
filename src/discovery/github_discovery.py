"""
GitHub Discovery Module
=======================

Discovers CVE mentions in GitHub repositories through code search,
commit messages, and issue tracking.

Author: rogolabs.net
"""

import logging
import os
import time
from datetime import datetime
from typing import Iterator
from urllib.parse import urlencode

import requests

from src.config import (
    CVE_PATTERN,
    CVE_STRICT_PATTERN,
    GITHUB_CONFIG,
    APP_SETTINGS,
    SourceType,
)
from src.discovery.base import (
    BaseDiscovery,
    DiscoveryResult,
    DiscoveryError,
    RateLimiter,
)


logger = logging.getLogger(__name__)


class GitHubDiscovery(BaseDiscovery):
    """
    Discovery module for finding CVE mentions on GitHub.
    
    Searches GitHub's code search API and commits API for references
    to CVE identifiers. Requires a GitHub token for authentication.
    
    Attributes:
        token: GitHub API token for authentication
        session: Requests session for HTTP calls
        rate_limiter: Rate limiter for API requests
    """
    
    def __init__(
        self,
        token: str | None = None,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the GitHub discovery module.
        
        Args:
            token: GitHub API token. If not provided, attempts to read
                   from GITHUB_TOKEN environment variable.
            enabled: Whether this discovery module is active
        
        Raises:
            DiscoveryError: If no token is available
        """
        super().__init__(
            name="GitHub Discovery",
            source_type=SourceType.GITHUB_CODE,
            enabled=enabled,
        )
        
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            self.logger.warning(
                "No GitHub token provided. GitHub discovery will be limited."
            )
        
        self.session = self._create_session()
        self.rate_limiter = RateLimiter(
            requests_per_window=GITHUB_CONFIG.requests_per_minute,
            window_seconds=60,
        )
        self._seen_urls: set[str] = set()
    
    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests session.
        
        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": APP_SETTINGS.user_agent,
        })
        
        if self.token:
            session.headers["Authorization"] = f"token {self.token}"
        
        return session
    
    def _wait_for_rate_limit(self) -> None:
        """Wait if necessary to respect rate limits."""
        wait_time = self.rate_limiter.acquire()
        if wait_time > 0:
            self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
    
    def _check_github_rate_limit(self, response: requests.Response) -> None:
        """
        Check and log GitHub API rate limit status.
        
        Args:
            response: Response object from GitHub API
        """
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_time = response.headers.get("X-RateLimit-Reset")
        
        if remaining and int(remaining) < 10:
            self.logger.warning(
                f"GitHub API rate limit low: {remaining} remaining"
            )
            if reset_time:
                reset_dt = datetime.fromtimestamp(int(reset_time))
                self.logger.warning(f"Rate limit resets at: {reset_dt}")
    
    def discover(self) -> Iterator[DiscoveryResult]:
        """
        Execute GitHub discovery and yield results.
        
        Searches both code and commits for CVE mentions.
        
        Yields:
            DiscoveryResult for each unique CVE mention found
        """
        # Search code for CVE mentions
        yield from self._search_code()
        
        # Search commits for CVE mentions
        yield from self._search_commits()
    
    def _search_code(self) -> Iterator[DiscoveryResult]:
        """
        Search GitHub code for CVE mentions.
        
        Yields:
            DiscoveryResult for each CVE found in code
        """
        for query in GITHUB_CONFIG.search_queries:
            self.logger.info(f"Searching GitHub code for: {query}")
            
            try:
                yield from self._execute_code_search(query)
            except Exception as e:
                self.logger.error(f"Code search failed for '{query}': {e}")
    
    def _execute_code_search(self, query: str) -> Iterator[DiscoveryResult]:
        """
        Execute a single code search query.
        
        Args:
            query: Search query string
        
        Yields:
            DiscoveryResult for each match
        """
        page = 1
        
        while page <= GITHUB_CONFIG.max_pages:
            self._wait_for_rate_limit()
            
            params = {
                "q": query,
                "per_page": GITHUB_CONFIG.search_results_per_page,
                "page": page,
            }
            
            url = f"{GITHUB_CONFIG.base_url}{GITHUB_CONFIG.search_endpoint}"
            
            try:
                response = self.session.get(url, params=params, timeout=30)
                self._check_github_rate_limit(response)
                
                if response.status_code == 403:
                    self.logger.warning("GitHub API rate limit exceeded")
                    break
                
                if response.status_code == 422:
                    self.logger.warning("GitHub search validation failed")
                    break
                
                response.raise_for_status()
                data = response.json()
                
                items = data.get("items", [])
                if not items:
                    break
                
                for item in items:
                    yield from self._process_code_item(item)
                
                # Check if there are more pages
                if len(items) < GITHUB_CONFIG.search_results_per_page:
                    break
                
                page += 1
                
            except requests.RequestException as e:
                self.logger.error(f"GitHub API request failed: {e}")
                break
    
    def _process_code_item(self, item: dict) -> Iterator[DiscoveryResult]:
        """
        Process a single code search result item.
        
        Args:
            item: Code search result from GitHub API
        
        Yields:
            DiscoveryResult for each CVE found in the item
        """
        html_url = item.get("html_url", "")
        
        if html_url in self._seen_urls:
            return
        self._seen_urls.add(html_url)
        
        repo = item.get("repository", {})
        repo_name = repo.get("full_name", "unknown")
        file_path = item.get("path", "")
        
        # Extract CVE IDs from the file name and path
        text_to_search = f"{file_path} {item.get('name', '')}"
        
        # Fetch file content for more context
        content_url = item.get("url")
        content = ""
        
        if content_url:
            try:
                self._wait_for_rate_limit()
                content_response = self.session.get(content_url, timeout=15)
                if content_response.ok:
                    content_data = content_response.json()
                    # Content is base64 encoded
                    import base64
                    encoded_content = content_data.get("content", "")
                    if encoded_content:
                        content = base64.b64decode(encoded_content).decode(
                            "utf-8", errors="ignore"
                        )
            except Exception as e:
                self.logger.debug(f"Could not fetch file content: {e}")
        
        text_to_search += f" {content}"
        
        # Find all CVE IDs
        cve_ids = set(CVE_STRICT_PATTERN.findall(text_to_search))
        
        for cve_id in cve_ids:
            # Extract context around the CVE mention
            context = self._extract_context(content, cve_id)
            
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=SourceType.GITHUB_CODE,
                source_name=f"GitHub Code: {repo_name}",
                evidence_url=html_url,
                context=context,
                confidence=0.9,
                raw_data={
                    "repository": repo_name,
                    "file_path": file_path,
                },
            )
    
    def _search_commits(self) -> Iterator[DiscoveryResult]:
        """
        Search GitHub commits for CVE mentions.
        
        Yields:
            DiscoveryResult for each CVE found in commits
        """
        for query in GITHUB_CONFIG.search_queries:
            self.logger.info(f"Searching GitHub commits for: {query}")
            
            try:
                yield from self._execute_commit_search(query)
            except Exception as e:
                self.logger.error(f"Commit search failed for '{query}': {e}")
    
    def _execute_commit_search(self, query: str) -> Iterator[DiscoveryResult]:
        """
        Execute a single commit search query.
        
        Args:
            query: Search query string
        
        Yields:
            DiscoveryResult for each match
        """
        page = 1
        
        while page <= GITHUB_CONFIG.max_pages:
            self._wait_for_rate_limit()
            
            params = {
                "q": query,
                "per_page": GITHUB_CONFIG.search_results_per_page,
                "page": page,
            }
            
            url = f"{GITHUB_CONFIG.base_url}{GITHUB_CONFIG.commits_endpoint}"
            
            # Commits search requires special accept header
            headers = {
                "Accept": "application/vnd.github.cloak-preview+json"
            }
            
            try:
                response = self.session.get(
                    url, params=params, headers=headers, timeout=30
                )
                self._check_github_rate_limit(response)
                
                if response.status_code == 403:
                    self.logger.warning("GitHub API rate limit exceeded")
                    break
                
                if response.status_code == 422:
                    self.logger.warning("GitHub search validation failed")
                    break
                
                response.raise_for_status()
                data = response.json()
                
                items = data.get("items", [])
                if not items:
                    break
                
                for item in items:
                    yield from self._process_commit_item(item)
                
                if len(items) < GITHUB_CONFIG.search_results_per_page:
                    break
                
                page += 1
                
            except requests.RequestException as e:
                self.logger.error(f"GitHub commits API request failed: {e}")
                break
    
    def _process_commit_item(self, item: dict) -> Iterator[DiscoveryResult]:
        """
        Process a single commit search result item.
        
        Args:
            item: Commit search result from GitHub API
        
        Yields:
            DiscoveryResult for each CVE found in the commit
        """
        html_url = item.get("html_url", "")
        
        if html_url in self._seen_urls:
            return
        self._seen_urls.add(html_url)
        
        repo = item.get("repository", {})
        repo_name = repo.get("full_name", "unknown")
        
        commit = item.get("commit", {})
        message = commit.get("message", "")
        
        # Extract commit date from the API response
        author_info = commit.get("author", {})
        commit_date = self._parse_github_date(author_info.get("date"))
        
        # Find all CVE IDs in the commit message
        cve_ids = set(CVE_STRICT_PATTERN.findall(message))
        
        for cve_id in cve_ids:
            yield DiscoveryResult(
                cve_id=cve_id,
                source_type=SourceType.GITHUB_COMMIT,
                source_name=f"GitHub Commit: {repo_name}",
                evidence_url=html_url,
                discovered_at=commit_date or datetime.utcnow(),
                context=message[:500] if message else None,
                confidence=0.95,
                raw_data={
                    "repository": repo_name,
                    "commit_sha": item.get("sha"),
                    "author": author_info.get("name"),
                    "commit_date": author_info.get("date"),
                },
            )
    
    def _extract_context(
        self,
        content: str,
        cve_id: str,
        context_chars: int = 200,
    ) -> str | None:
        """
        Extract context around a CVE mention.
        
        Args:
            content: Full text content
            cve_id: CVE identifier to find
            context_chars: Number of characters of context on each side
        
        Returns:
            Context string or None if not found
        """
        if not content:
            return None
        
        # Find position of CVE ID (case insensitive)
        content_lower = content.lower()
        cve_lower = cve_id.lower()
        
        pos = content_lower.find(cve_lower)
        if pos == -1:
            return None
        
        start = max(0, pos - context_chars)
        end = min(len(content), pos + len(cve_id) + context_chars)
        
        context = content[start:end].strip()
        
        # Clean up whitespace
        import re
        context = re.sub(r"\s+", " ", context)
        
        if start > 0:
            context = "..." + context
        if end < len(content):
            context = context + "..."
        
        return context
