"""Web crawler agent for discovering security threats."""

from .base_agent import BaseAgent
from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup, SoupStrainer
from urllib.parse import urljoin, urlparse
import re
from datetime import datetime
import json
import time
from PyQt6.QtCore import QObject, pyqtSignal
from queue import Queue, Empty
from threading import Thread
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Disable SSL verification warnings since we're intentionally not verifying
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityFinding:
    """Class to represent a security finding."""
    
    def __init__(self, url, finding_type, description, severity, indicators=None, recommendations=None):
        self.url = url
        self.finding_type = finding_type
        self.description = description
        self.severity = severity
        self.indicators = indicators or []
        self.recommendations = recommendations or []
        
    def to_dict(self):
        """Convert finding to dictionary format."""
        return {
            'url': self.url,
            'finding_type': self.finding_type,
            'description': self.description,
            'severity': self.severity,
            'indicators': self.indicators,
            'recommendations': self.recommendations
        }

class CrawlerAgent(BaseAgent, QObject):
    # Define signals for thread-safe GUI updates
    finding_signal = pyqtSignal(str, dict)
    status_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, seed_urls=None, config=None):
        BaseAgent.__init__(
            self,
            name="Crawler",
            role="Security Intelligence Gatherer",
            goal="Discover and analyze potential security threats from web sources"
        )
        QObject.__init__(self)
        
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.findings = []
        self.gui = None
        self._is_crawling = False  # Use private variable for state
        
        # Initialize from config or parameters
        if seed_urls:
            self.seed_urls = self._validate_urls(seed_urls)
        else:
            self.seed_urls = self._validate_urls(self.config.get('seed_urls', [
                'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                'https://www.cisa.gov/news-events/cybersecurity-advisories'
            ]))
            
        self.max_indicators = self.config.get('max_indicators', 100)
        
        # Configure session with retries but without SSL verification
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False  # Disable SSL verification
        
        # Add rate limiting and timeouts
        self.request_delay = self.config.get('request_delay', 1)  # Reduced delay
        self.timeout = self.config.get('timeout', 5)  # Shorter timeout
        self.max_retries = self.config.get('max_retries', 2)
        self.max_content_length = self.config.get('max_content_length', 1024 * 1024)  # 1MB limit
        self.allowed_domains = [urlparse(url).netloc for url in self.seed_urls]
        
        # Security patterns to look for
        self.security_patterns = {
            'CVE': {
                'pattern': r'CVE-\d{4}-\d{4,7}',
                'severity': 'HIGH',
                'recommendations': [
                    "Check if affected systems are in your infrastructure",
                    "Apply available patches immediately",
                    "Monitor systems for exploitation attempts"
                ]
            },
            'VULNERABILITY': {
                'pattern': r'vulnerability|exploit|zero-day|0day',
                'severity': 'MEDIUM',
                'recommendations': [
                    "Review affected components",
                    "Implement available mitigations",
                    "Update security policies"
                ]
            },
            'THREAT': {
                'pattern': r'(malware|ransomware|trojan|virus|threat actor)',
                'severity': 'MEDIUM',
                'recommendations': [
                    "Update antivirus signatures",
                    "Scan systems for indicators of compromise",
                    "Review network traffic for suspicious patterns"
                ]
            },
            'ADVISORY': {
                'pattern': r'advisory|alert|warning|security\s+notice',
                'severity': 'LOW',
                'recommendations': [
                    "Review the advisory details",
                    "Assess if systems are affected",
                    "Plan appropriate action based on risk"
                ]
            }
        }
        
    @property
    def is_crawling(self):
        """Thread-safe access to crawling state."""
        return self._is_crawling
        
    @is_crawling.setter
    def is_crawling(self, value):
        """Thread-safe update of crawling state."""
        self._is_crawling = value
        # Emit status signal when state changes
        if value:
            self.status_signal.emit("Crawler is running")
        else:
            self.status_signal.emit("Crawler is stopped")
            
    def _validate_urls(self, urls: List[str]) -> List[str]:
        """Validate and filter seed URLs."""
        valid_urls = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme in ('http', 'https') and parsed.netloc:
                    # Test if the URL is accessible
                    response = self.session.head(url, timeout=5, allow_redirects=True)
                    if response.status_code == 200:
                        valid_urls.append(url)
                        self.status_signal.emit(f"Validated URL: {url}")
                    else:
                        self.error_signal.emit(f"URL not accessible: {url} (Status: {response.status_code})")
                else:
                    self.error_signal.emit(f"Invalid URL scheme: {url}")
            except requests.exceptions.RequestException as e:
                self.error_signal.emit(f"Error validating URL {url}: {str(e)}")
            except Exception as e:
                self.error_signal.emit(f"Unexpected error validating URL {url}: {str(e)}")
        
        if not valid_urls:
            self.error_signal.emit("No valid seed URLs found. Crawler will be inactive.")
        
        return valid_urls
    
    def reset(self):
        """Reset the crawler state."""
        self._is_crawling = False
        self.findings = []
        # Emit status signal
        self.status_signal.emit("Crawler reset")
        self.logger.info("Crawler reset")
        
    def analyze_content(self, url, content):
        """Analyze content for security indicators and generate findings."""
        findings = []
        
        # Add basic security analysis for any webpage
        meta_findings = []
        
        # Check for SSL/TLS
        if url.startswith('https://'):
            meta_findings.append("Site uses HTTPS for secure communication")
        else:
            meta_findings.append("Site does not use HTTPS - potential security risk")
            
        # Check for basic security headers in content
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            'Strict-Transport-Security'
        ]
        
        for header in security_headers:
            if header.lower() in content.lower():
                meta_findings.append(f"Implements {header} security header")
                
        if meta_findings:
            finding = SecurityFinding(
                url=url,
                finding_type='SECURITY_CONFIG',
                description="Security configuration analysis",
                severity='LOW',
                indicators=meta_findings,
                recommendations=[
                    "Review security headers implementation",
                    "Ensure HTTPS is properly configured",
                    "Implement missing security headers"
                ]
            )
            findings.append(finding)
        
        # Check for specific security patterns
        for finding_type, config in self.security_patterns.items():
            matches = re.findall(config['pattern'], content, re.IGNORECASE)
            if matches:
                # Extract surrounding context for each match
                contexts = []
                for match in matches:
                    # Find the sentence containing the match
                    sentences = re.split(r'[.!?]+', content)
                    for sentence in sentences:
                        if match.lower() in sentence.lower():
                            contexts.append(sentence.strip())
                
                if contexts:
                    description = f"Found {finding_type} indicators: {', '.join(matches)}"
                    finding = SecurityFinding(
                        url=url,
                        finding_type=finding_type,
                        description=description,
                        severity=config['severity'],
                        indicators=contexts,
                        recommendations=config['recommendations']
                    )
                    findings.append(finding)
        
        return findings
        
    def store_finding(self, finding):
        """Store a finding and convert it to dictionary format."""
        try:
            if isinstance(finding, SecurityFinding):
                finding_dict = finding.to_dict()
                self.findings.append(finding_dict)
                # Emit signal for UI update
                self.finding_signal.emit('crawler', finding_dict)
                self.logger.info(f"Found {finding.finding_type} with severity {finding.severity}")
            else:
                self.findings.append(finding)
                self.finding_signal.emit('crawler', finding)
                
        except Exception as e:
            self.logger.error(f"Error storing finding: {str(e)}")
            self.error_signal.emit(f"Error storing finding: {str(e)}")
            
    def crawl(self, url=None, max_pages=50):
        """
        Crawl security feeds for new information.
        
        Args:
            url: Optional URL to crawl. If not provided, uses seed_urls
            max_pages: Maximum number of pages to crawl
        """
        if self._is_crawling:
            self.logger.warning("Crawler is already running")
            self.status_signal.emit("Crawler is already running")
            return
            
        try:
            self.reset()  # Reset state before starting
            self._is_crawling = True
            self.status_signal.emit("Starting crawler...")
            self.logger.info("Starting crawler...")
            visited = set()
            queue = Queue()
            
            # Add the URL to crawl
            if url:
                queue.put(url)
                # Add the domain to allowed domains if not already present
                domain = urlparse(url).netloc
                if domain not in self.allowed_domains:
                    self.allowed_domains.append(domain)
            else:
                for seed_url in self.seed_urls:
                    queue.put(seed_url)
            
            def worker():
                while self._is_crawling and not queue.empty() and len(self.findings) < max_pages:
                    try:
                        url = queue.get(timeout=1)  # 1 second timeout to check stop flag
                    except Empty:
                        continue
                        
                    if url in visited:
                        queue.task_done()
                        continue
                    
                    try:
                        self.logger.info(f"Crawling {url}")
                        self.status_signal.emit(f"Crawling {url}")
                        
                        # Add delay to respect server load
                        time.sleep(self.request_delay)
                        
                        # Make request with timeout
                        try:
                            response = self.session.get(url, timeout=self.timeout)
                            response.raise_for_status()  # Raise exception for bad status codes
                        except requests.exceptions.RequestException as e:
                            self.logger.warning(f"Error fetching {url}: {str(e)}")
                            queue.task_done()
                            continue
                        
                        if response.status_code == 200:
                            # Check content length
                            content_length = int(response.headers.get('content-length', 0))
                            if content_length > self.max_content_length:
                                self.logger.warning(f"Skipping large page: {url}")
                                queue.task_done()
                                continue
                            
                            # Parse content
                            try:
                                soup = BeautifulSoup(response.text, 'html.parser', parse_only=SoupStrainer('a'))
                                
                                # Analyze content for security indicators
                                findings = self.analyze_content(url, response.text)
                                for finding in findings:
                                    if len(self.findings) >= max_pages:
                                        self.logger.info(f"Reached max pages limit ({max_pages})")
                                        self._is_crawling = False
                                        break
                                    self.store_finding(finding)
                                
                                if not self._is_crawling:
                                    break
                                
                                # Extract new links (only process 'a' tags)
                                for link in soup.find_all('a', href=True):
                                    if not self._is_crawling:
                                        break
                                    href = link.get('href')
                                    if href:
                                        # Handle relative URLs
                                        if href.startswith('/'):
                                            parsed_base = urlparse(url)
                                            href = f"{parsed_base.scheme}://{parsed_base.netloc}{href}"
                                        elif not href.startswith(('http://', 'https://')):
                                            continue
                                        
                                        # Only add URLs from allowed domains
                                        if any(domain in href for domain in self.allowed_domains):
                                            queue.put(href)
                                            
                            except Exception as e:
                                self.logger.error(f"Error parsing {url}: {str(e)}")
                        
                        visited.add(url)
                        
                    except Exception as e:
                        self.logger.error(f"Error crawling {url}: {str(e)}")
                        self.error_signal.emit(f"Error crawling {url}: {str(e)}")
                    
                    queue.task_done()
            
            # Start worker threads
            threads = []
            for _ in range(2):  # Reduced number of threads
                thread = Thread(target=worker)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Wait for completion or max_pages
            while self._is_crawling and any(t.is_alive() for t in threads):
                time.sleep(0.1)  # Shorter sleep interval
            
            self.logger.info("Crawler finished")
            self._is_crawling = False
            self.status_signal.emit(f"Crawler finished. Found {len(self.findings)} findings.")
            
        except Exception as e:
            self.logger.error(f"Crawler error: {str(e)}")
            self.error_signal.emit(f"Crawler error: {str(e)}")
            self._is_crawling = False
    
    def stop_crawling(self):
        """Stop the crawler gracefully."""
        if self._is_crawling:
            self.logger.info("Stopping crawler...")
            self._is_crawling = False
            self.status_signal.emit("Crawler stopped")
    
    def get_recent_discoveries(self, limit=50):
        """Get recent security discoveries with severity filtering."""
        sorted_findings = sorted(self.findings, key=lambda x: x['timestamp'], reverse=True)
        return sorted_findings[:limit]
        
    def get_findings_by_severity(self, severity):
        """Get findings filtered by severity level."""
        return [f for f in self.findings if f['severity'] == severity]
        
    def get_findings_summary(self):
        """Get a summary of findings by type and severity."""
        summary = {
            'total': len(self.findings),
            'by_severity': {
                'HIGH': len(self.get_findings_by_severity('HIGH')),
                'MEDIUM': len(self.get_findings_by_severity('MEDIUM')),
                'LOW': len(self.get_findings_by_severity('LOW'))
            },
            'by_type': {}
        }
        
        for finding in self.findings:
            finding_type = finding['metadata']['type']
            if finding_type not in summary['by_type']:
                summary['by_type'][finding_type] = 0
            summary['by_type'][finding_type] += 1
            
        return summary
