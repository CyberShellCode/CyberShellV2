"""
Unified Scanning and Mapping System with SmartWebCrawler Integration
====================================================================
Enhanced version that integrates JavaScript-aware crawling and advanced
API discovery capabilities.
"""

import asyncio
import json
import re
import time
import subprocess
import jwt
import hashlib
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Tuple, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import logging
import random
import requests
from bs4 import BeautifulSoup
import networkx as nx

# Optional imports for enhanced functionality
try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.proxy import Proxy, ProxyType
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Try to import SmartWebCrawler
try:
    from .enhanced.js_aware_crawler import SmartWebCrawler, CrawlResult
    SMART_CRAWLER_AVAILABLE = True
except ImportError:
    SMART_CRAWLER_AVAILABLE = False
    # Define stubs if not available
    @dataclass
    class CrawlResult:
        endpoints_discovered: List[Any] = field(default_factory=list)
        javascript_files: List[str] = field(default_factory=list)
        api_endpoints: List[str] = field(default_factory=list)
        forms: List[Dict] = field(default_factory=list)
        vulnerabilities_hints: List[Dict] = field(default_factory=list)
        websocket_endpoints: List[str] = field(default_factory=list)
        graphql_endpoints: List[str] = field(default_factory=list)
        total_pages_crawled: int = 0
        total_time: float = 0.0

logger = logging.getLogger(__name__)

# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """Enhanced rate limiter with adaptive throttling"""
    
    def __init__(self, requests_per_second: float = 5, burst_size: int = 10, 
                 respect_headers: bool = True, adaptive: bool = True):
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.respect_headers = respect_headers
        self.adaptive = adaptive
        self.last_request_time = 0
        self.request_count = 0
        self.retry_after = 0
        
        # Adaptive throttling
        self.response_times = deque(maxlen=20)
        self.error_count = 0
        self.last_error_time = 0
    
    async def acquire(self):
        """Acquire permission to make a request with adaptive throttling"""
        current_time = time.time()
        
        # Check if we need to wait for retry-after
        if self.retry_after > current_time:
            await asyncio.sleep(self.retry_after - current_time)
            self.retry_after = 0
        
        # Adaptive rate adjustment
        if self.adaptive:
            self._adjust_rate()
        
        # Simple rate limiting
        time_since_last = current_time - self.last_request_time
        if time_since_last < (1.0 / self.requests_per_second):
            await asyncio.sleep((1.0 / self.requests_per_second) - time_since_last)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def update_from_response(self, response_headers: Dict, response_time: float = None):
        """Update rate limits based on response"""
        if response_time:
            self.response_times.append(response_time)
        
        if not self.respect_headers:
            return
        
        # Check for rate limit headers
        if 'X-RateLimit-Remaining' in response_headers:
            remaining = int(response_headers['X-RateLimit-Remaining'])
            if remaining <= 0:
                retry_after = response_headers.get('X-RateLimit-Reset', 
                                                  response_headers.get('Retry-After', 60))
                self.retry_after = time.time() + float(retry_after)
        
        # Check for 429 status (handled by caller)
        if response_headers.get('status') == '429':
            self.error_count += 1
            self.last_error_time = time.time()
    
    def _adjust_rate(self):
        """Adaptively adjust request rate based on performance"""
        # Too many errors - slow down
        if self.error_count > 3 and time.time() - self.last_error_time < 60:
            self.requests_per_second = max(1, self.requests_per_second * 0.5)
            self.error_count = 0
            logger.info(f"Slowing down to {self.requests_per_second} req/s due to errors")
        
        # Response times increasing - slow down
        elif len(self.response_times) >= 10:
            avg_time = sum(self.response_times) / len(self.response_times)
            if avg_time > 2.0:  # Responses taking too long
                self.requests_per_second = max(1, self.requests_per_second * 0.8)
                logger.debug(f"Adjusting rate to {self.requests_per_second} req/s")

# ============================================================================
# FINGERPRINTING
# ============================================================================

@dataclass
class TargetFingerprint:
    """Enhanced target fingerprint information"""
    product: Optional[str] = None
    version: Optional[str] = None
    cms: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    javascript_libraries: List[str] = field(default_factory=list)
    api_type: Optional[str] = None  # REST, GraphQL, WebSocket
    frameworks: List[str] = field(default_factory=list)
    waf: Optional[str] = None

# ============================================================================
# ENHANCED DATA STRUCTURES
# ============================================================================

@dataclass
class Endpoint:
    """Enhanced endpoint representation with JavaScript awareness"""
    url: str
    method: str = "GET"
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    response_code: int = 0
    content_type: str = ""
    auth_required: bool = False
    user_role: str = "anonymous"
    forms: List[Dict] = field(default_factory=list)
    javascript_events: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    potential_vulns: List[str] = field(default_factory=list)
    object_references: List[str] = field(default_factory=list)
    requires_csrf: bool = False
    graphql_endpoint: bool = False
    discovered_at: float = field(default_factory=time.time)
    
    # Enhanced fields for JS-aware crawling
    javascript_rendered: bool = False
    dynamic_content: bool = False
    websocket_endpoint: bool = False
    ajax_endpoints: List[str] = field(default_factory=list)
    dom_xss_sinks: List[str] = field(default_factory=list)
    client_side_routes: List[str] = field(default_factory=list)
    api_documentation: Optional[str] = None

@dataclass
class ScanResult:
    """Enhanced scan result structure"""
    target: str
    timestamp: float
    endpoints: List[Endpoint]
    vulnerabilities: Dict[str, List[Any]]
    services: Dict[str, Any]
    credentials: Dict[str, Any]
    fingerprint: TargetFingerprint
    evidence: List[Any]
    
    # Enhanced fields
    javascript_analysis: Dict[str, Any] = field(default_factory=dict)
    api_schema: Optional[Dict] = None
    graphql_schema: Optional[str] = None
    websocket_messages: List[Dict] = field(default_factory=list)
    spa_routes: List[str] = field(default_factory=list)
    client_storage: Dict[str, List] = field(default_factory=dict)

# ============================================================================
# ENHANCED WEB APPLICATION MAPPER
# ============================================================================

@dataclass
class WebAppMap:
    """Enhanced web application map with JavaScript awareness"""
    endpoints: Dict[str, Endpoint] = field(default_factory=dict)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    technologies: Set[str] = field(default_factory=set)
    authentication_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    file_upload_endpoints: List[str] = field(default_factory=list)
    admin_endpoints: List[str] = field(default_factory=list)
    vulnerability_map: Dict[str, List[Endpoint]] = field(default_factory=dict)
    
    # Enhanced fields
    javascript_files: List[str] = field(default_factory=list)
    api_documentation: Dict[str, Any] = field(default_factory=dict)
    graphql_endpoints: List[str] = field(default_factory=list)
    websocket_endpoints: List[str] = field(default_factory=list)
    spa_routes: List[str] = field(default_factory=list)
    client_side_vulns: Dict[str, List] = field(default_factory=dict)

class WebApplicationMapper:
    """Enhanced web application mapper with SmartWebCrawler integration"""
    
    def __init__(self, rate_limiter: RateLimiter, proxy_port: int = 8080):
        self.rate_limiter = rate_limiter
        self.proxy_port = proxy_port
        self.webapp_map = WebAppMap()
        self.discovered_urls = set()
        self.vuln_patterns = self._init_vuln_patterns()
        
        # Initialize SmartWebCrawler if available
        self.smart_crawler = None
        if SMART_CRAWLER_AVAILABLE:
            try:
                self.smart_crawler = SmartWebCrawler(max_depth=3, max_pages=100)
                logger.info("SmartWebCrawler integrated successfully")
            except Exception as e:
                logger.warning(f"Could not initialize SmartWebCrawler: {e}")
    
    def _init_vuln_patterns(self) -> Dict[str, List[Dict]]:
        """Enhanced vulnerability detection patterns"""
        return {
            'sqli': [
                {'param_pattern': r'(id|user|account|number|order)', 'weight': 0.7},
                {'param_pattern': r'(select|search|filter|sort)', 'weight': 0.6},
                {'endpoint_pattern': r'/api/.*/(users|products|orders)', 'weight': 0.8},
                {'param_pattern': r'(query|q|sql)', 'weight': 0.5}
            ],
            'xss': [
                {'param_pattern': r'(q|query|search|message|comment|name)', 'weight': 0.7},
                {'param_pattern': r'(input|text|data|content)', 'weight': 0.5},
                {'content_type': 'text/html', 'weight': 0.8},
                {'javascript_rendered': True, 'weight': 0.6}
            ],
            'dom_xss': [
                {'client_side_route': True, 'weight': 0.8},
                {'dom_sink': True, 'weight': 0.9},
                {'javascript_rendered': True, 'weight': 0.7}
            ],
            'idor': [
                {'param_pattern': r'(id|uid|userid|doc|file)=\d+', 'weight': 0.9},
                {'endpoint_pattern': r'/api/.*/\d+', 'weight': 0.8},
                {'endpoint_pattern': r'/(profile|account|user)/\d+', 'weight': 0.9},
                {'graphql': True, 'weight': 0.7}
            ],
            'lfi': [
                {'param_pattern': r'(file|path|template|page|include)', 'weight': 0.8},
                {'param_pattern': r'(load|read|download)', 'weight': 0.7}
            ],
            'rce': [
                {'param_pattern': r'(cmd|exec|command|run|ping)', 'weight': 0.9},
                {'endpoint_pattern': r'/(admin|debug|test)', 'weight': 0.6},
                {'websocket': True, 'weight': 0.5}
            ],
            'xxe': [
                {'content_type': 'application/xml', 'weight': 0.9},
                {'content_type': 'text/xml', 'weight': 0.9},
                {'param_pattern': r'(xml|data|import)', 'weight': 0.5}
            ],
            'ssrf': [
                {'param_pattern': r'(url|uri|target|host|proxy)', 'weight': 0.8},
                {'param_pattern': r'(callback|webhook|fetch)', 'weight': 0.7},
                {'graphql': True, 'weight': 0.6}
            ],
            'upload': [
                {'endpoint_pattern': r'/(upload|import|file)', 'weight': 0.9},
                {'param_pattern': r'(file|upload|attachment)', 'weight': 0.8}
            ],
            'api_key_exposure': [
                {'javascript_file': True, 'weight': 0.9},
                {'client_storage': True, 'weight': 0.8}
            ]
        }
    
    async def map_application(self, target: str, duration: int = 300, 
                             use_browser: bool = True, use_smart_crawler: bool = True) -> WebAppMap:
        """Enhanced application mapping with SmartWebCrawler"""
        tasks = []
        
        # Use SmartWebCrawler if available and enabled
        if use_smart_crawler and self.smart_crawler:
            logger.info("Starting SmartWebCrawler for JavaScript-aware crawling")
            crawl_result = await self._smart_crawl(target)
            self._process_smart_crawl_results(crawl_result)
        
        # Start HTTP proxy if available
        if MITMPROXY_AVAILABLE:
            tasks.append(self._start_proxy())
        
        # Traditional browser-based crawling (as fallback or complement)
        if use_browser and PLAYWRIGHT_AVAILABLE and not self.smart_crawler:
            tasks.append(self._browser_crawl_playwright(target))
        
        # API discovery
        tasks.append(self._discover_apis(target))
        
        # JavaScript analysis
        tasks.append(self._analyze_javascript(target))
        
        # GraphQL introspection
        tasks.append(self._introspect_graphql(target))
        
        # Run tasks
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Analyze collected data
        self._analyze_relationships()
        self._categorize_endpoints()
        self._detect_client_side_vulns()
        
        return self.webapp_map
    
    async def _smart_crawl(self, target: str) -> CrawlResult:
        """Use SmartWebCrawler for enhanced crawling"""
        try:
            result = await self.smart_crawler.crawl(target)
            logger.info(f"SmartWebCrawler discovered {len(result.endpoints_discovered)} endpoints")
            return result
        except Exception as e:
            logger.error(f"SmartWebCrawler error: {e}")
            return CrawlResult()
    
    def _process_smart_crawl_results(self, crawl_result: CrawlResult):
        """Process results from SmartWebCrawler"""
        # Process discovered endpoints
        for endpoint_data in crawl_result.endpoints_discovered:
            endpoint = Endpoint(
                url=endpoint_data.get('url', ''),
                method=endpoint_data.get('method', 'GET'),
                javascript_rendered=True,
                dynamic_content=True
            )
            
            # Extract parameters from URL
            parsed = urlparse(endpoint.url)
            if parsed.query:
                endpoint.parameters = parse_qs(parsed.query)
            
            # Mark as API endpoint if applicable
            if '/api/' in endpoint.url or endpoint.url in crawl_result.api_endpoints:
                endpoint.api_calls.append(endpoint.url)
            
            # Check for GraphQL
            if endpoint.url in crawl_result.graphql_endpoints:
                endpoint.graphql_endpoint = True
                self.webapp_map.graphql_endpoints.append(endpoint.url)
            
            # Check for WebSocket
            if endpoint.url in crawl_result.websocket_endpoints:
                endpoint.websocket_endpoint = True
                self.webapp_map.websocket_endpoints.append(endpoint.url)
            
            # Detect potential vulnerabilities
            endpoint.potential_vulns = self._detect_vulnerabilities(endpoint)
            
            endpoint_key = f"{endpoint.method}:{urlparse(endpoint.url).path}"
            self.webapp_map.endpoints[endpoint_key] = endpoint
            self.discovered_urls.add(endpoint.url)
        
        # Process JavaScript files
        self.webapp_map.javascript_files.extend(crawl_result.javascript_files)
        
        # Process API endpoints
        self.webapp_map.api_endpoints.extend(crawl_result.api_endpoints)
        
        # Process forms
        for form in crawl_result.forms:
            self._process_form(form.get('action', ''), form)
        
        # Process vulnerability hints
        for hint in crawl_result.vulnerabilities_hints:
            vuln_type = hint.get('type')
            if vuln_type not in self.webapp_map.vulnerability_map:
                self.webapp_map.vulnerability_map[vuln_type] = []
            
            # Create endpoint for vulnerability
            vuln_endpoint = Endpoint(
                url=hint.get('location', ''),
                potential_vulns=[vuln_type]
            )
            self.webapp_map.vulnerability_map[vuln_type].append(vuln_endpoint)
    
    async def _analyze_javascript(self, target: str):
        """Analyze JavaScript files for security issues"""
        js_files = self.webapp_map.javascript_files[:20]  # Limit analysis
        
        for js_url in js_files:
            await self.rate_limiter.acquire()
            
            try:
                response = requests.get(js_url, timeout=10, verify=False)
                if response.status_code == 200:
                    self._analyze_js_content(response.text, js_url)
            except:
                continue
    
    def _analyze_js_content(self, content: str, url: str):
        """Analyze JavaScript content for security issues"""
        # API key patterns
        api_key_patterns = [
            r'["\']api[_-]?key["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']apiKey["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']access[_-]?token["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']secret["\']\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in api_key_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                if 'api_key_exposure' not in self.webapp_map.client_side_vulns:
                    self.webapp_map.client_side_vulns['api_key_exposure'] = []
                
                self.webapp_map.client_side_vulns['api_key_exposure'].append({
                    'file': url,
                    'keys_found': len(matches)
                })
        
        # DOM XSS sinks
        dom_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function', 'location.href'
        ]
        
        for sink in dom_sinks:
            if sink in content:
                if 'dom_xss' not in self.webapp_map.client_side_vulns:
                    self.webapp_map.client_side_vulns['dom_xss'] = []
                
                self.webapp_map.client_side_vulns['dom_xss'].append({
                    'file': url,
                    'sink': sink
                })
        
        # Extract API endpoints from JavaScript
        api_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[get|post|put|delete]\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.startswith('/'):
                    api_url = urljoin(url, match)
                    if api_url not in self.webapp_map.api_endpoints:
                        self.webapp_map.api_endpoints.append(api_url)
    
    async def _introspect_graphql(self, target: str):
        """Attempt GraphQL introspection"""
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        types {
                            name
                            fields {
                                name
                                type { name }
                            }
                        }
                    }
                }
            """
        }
        
        for path in graphql_paths:
            await self.rate_limiter.acquire()
            
            full_url = urljoin(target, path)
            try:
                response = requests.post(
                    full_url,
                    json=introspection_query,
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and '__schema' in data['data']:
                            self.webapp_map.graphql_endpoints.append(full_url)
                            self.webapp_map.api_documentation['graphql_schema'] = data['data']
                            logger.info(f"GraphQL introspection successful at {full_url}")
                    except:
                        pass
            except:
                continue
    
    async def _start_proxy(self):
        """Start mitmproxy for HTTP interception"""
        if not MITMPROXY_AVAILABLE:
            return
        
        class InterceptAddon:
            def __init__(self, mapper):
                self.mapper = mapper
            
            def request(self, flow: http.HTTPFlow):
                self.mapper._process_request(flow)
            
            def response(self, flow: http.HTTPFlow):
                self.mapper._process_response(flow)
            
            def websocket_message(self, flow: http.HTTPFlow):
                self.mapper._process_websocket(flow)
        
        opts = options.Options(listen_port=self.proxy_port)
        proxy_master = DumpMaster(opts)
        proxy_master.addons.add(InterceptAddon(self))
        
        try:
            await proxy_master.run()
        except KeyboardInterrupt:
            proxy_master.shutdown()
    
    def _process_request(self, flow: http.HTTPFlow):
        """Process intercepted HTTP request"""
        request = flow.request
        url = request.pretty_url
        
        endpoint = Endpoint(
            url=url,
            method=request.method,
            headers=dict(request.headers),
            cookies=dict(request.cookies)
        )
        
        # Extract parameters
        if request.method == "GET":
            parsed = urlparse(url)
            endpoint.parameters = parse_qs(parsed.query)
        elif request.method == "POST" and request.content:
            try:
                if 'application/json' in request.headers.get('Content-Type', ''):
                    endpoint.parameters = json.loads(request.content)
                else:
                    endpoint.parameters = parse_qs(request.content.decode())
            except:
                pass
        
        # Check for GraphQL
        if 'graphql' in url.lower() or request.content and b'query' in request.content:
            endpoint.graphql_endpoint = True
        
        endpoint.potential_vulns = self._detect_vulnerabilities(endpoint)
        
        endpoint_key = f"{request.method}:{urlparse(url).path}"
        self.webapp_map.endpoints[endpoint_key] = endpoint
        self.discovered_urls.add(url)
    
    def _process_response(self, flow: http.HTTPFlow):
        """Enhanced response processing"""
        request = flow.request
        response = flow.response
        
        endpoint_key = f"{request.method}:{urlparse(request.pretty_url).path}"
        
        if endpoint_key in self.webapp_map.endpoints:
            endpoint = self.webapp_map.endpoints[endpoint_key]
            endpoint.response_code = response.status_code
            endpoint.content_type = response.headers.get("Content-Type", "")
            
            if response.status_code in [401, 403]:
                endpoint.auth_required = True
            
            # Extract forms and JavaScript references
            if "text/html" in endpoint.content_type:
                endpoint.forms = self._extract_forms(response.content)
                self._extract_js_references(response.content)
            
            # Check for API documentation
            if response.status_code == 200:
                if '/swagger' in request.pretty_url or '/openapi' in request.pretty_url:
                    try:
                        self.webapp_map.api_documentation['swagger'] = json.loads(response.content)
                    except:
                        pass
    
    def _process_websocket(self, flow: http.HTTPFlow):
        """Process WebSocket messages"""
        endpoint_key = f"WS:{urlparse(flow.request.pretty_url).path}"
        
        if endpoint_key not in self.webapp_map.endpoints:
            endpoint = Endpoint(
                url=flow.request.pretty_url,
                method="WEBSOCKET",
                websocket_endpoint=True
            )
            self.webapp_map.endpoints[endpoint_key] = endpoint
            self.webapp_map.websocket_endpoints.append(flow.request.pretty_url)
    
    def _extract_js_references(self, content: bytes):
        """Extract JavaScript file references from HTML"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Find script tags
            for script in soup.find_all('script'):
                src = script.get('src')
                if src and src not in self.webapp_map.javascript_files:
                    self.webapp_map.javascript_files.append(src)
        except:
            pass
    
    async def _browser_crawl_playwright(self, target: str):
        """Enhanced browser crawling with JavaScript execution tracking"""
        if not PLAYWRIGHT_AVAILABLE:
            return
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            
            # Enable request interception
            await context.route('**/*', self._intercept_request)
            
            page = await context.new_page()
            
            # Monitor console for errors and API calls
            page.on('console', self._handle_console)
            
            await self._crawl_page(page, target)
            await browser.close()
    
    async def _intercept_request(self, route):
        """Intercept and analyze browser requests"""
        request = route.request
        
        # Track AJAX/API calls
        if request.resource_type in ['xhr', 'fetch']:
            url = request.url
            if url not in self.webapp_map.api_endpoints:
                self.webapp_map.api_endpoints.append(url)
        
        await route.continue_()
    
    def _handle_console(self, message):
        """Handle console messages for error detection"""
        if message.type in ['error', 'warning']:
            text = message.text
            
            # Check for security-relevant errors
            if any(keyword in text.lower() for keyword in ['cors', 'csp', 'mixed content']):
                if 'console_errors' not in self.webapp_map.client_side_vulns:
                    self.webapp_map.client_side_vulns['console_errors'] = []
                
                self.webapp_map.client_side_vulns['console_errors'].append({
                    'type': message.type,
                    'text': text[:200]
                })
    
    async def _crawl_page(self, page, url: str, depth: int = 0, max_depth: int = 3):
        """Enhanced page crawling with client-side analysis"""
        if depth > max_depth:
            return
        
        try:
            await page.goto(url, wait_until="networkidle")
            
            # Extract client-side routes (for SPAs)
            spa_routes = await page.evaluate("""
                () => {
                    const routes = [];
                    // Check for React Router
                    if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
                        // Extract routes if accessible
                    }
                    // Check for Vue Router
                    if (window.$nuxt || window.__VUE__) {
                        // Extract routes if accessible
                    }
                    // Check for Angular
                    if (window.ng) {
                        // Extract routes if accessible
                    }
                    return routes;
                }
            """)
            
            if spa_routes:
                self.webapp_map.spa_routes.extend(spa_routes)
            
            # Extract localStorage and sessionStorage
            storage_data = await page.evaluate("""
                () => ({
                    localStorage: Object.keys(localStorage || {}),
                    sessionStorage: Object.keys(sessionStorage || {})
                })
            """)
            
            if storage_data['localStorage'] or storage_data['sessionStorage']:
                if 'client_storage' not in self.webapp_map.client_side_vulns:
                    self.webapp_map.client_side_vulns['client_storage'] = []
                
                self.webapp_map.client_side_vulns['client_storage'].append({
                    'url': url,
                    'localStorage_keys': storage_data['localStorage'],
                    'sessionStorage_keys': storage_data['sessionStorage']
                })
            
            # Extract links and forms
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href.startsWith('http'))
            """)
            
            forms = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                        name: input.name,
                        type: input.type,
                        value: input.value
                    }))
                }))
            """)
            
            for form in forms:
                self._process_form(url, form)
            
            # Crawl discovered links
            for link in links:
                if link not in self.discovered_urls and self._is_same_origin(link, url):
                    await self._crawl_page(page, link, depth + 1, max_depth)
                    
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
    
    async def _discover_apis(self, target: str):
        """Enhanced API discovery"""
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2',
            '/graphql', '/api/graphql',
            '/swagger', '/swagger-ui', '/api-docs', '/openapi',
            '/ws', '/websocket', '/socket.io',
            '/.well-known/openapi.json'
        ]
        
        # Common API documentation paths
        doc_paths = [
            '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/openapi.yaml',
            '/api-docs.json', '/api/swagger.json'
        ]
        
        for path in common_paths:
            await self.rate_limiter.acquire()
            
            full_url = urljoin(target, path)
            try:
                response = requests.get(full_url, timeout=10, verify=False)
                if response.status_code in [200, 201, 401, 403]:
                    self.webapp_map.api_endpoints.append(full_url)
                    
                    # Check if it's GraphQL
                    if 'graphql' in path.lower():
                        self.webapp_map.graphql_endpoints.append(full_url)
            except:
                continue
        
        # Try to fetch API documentation
        for doc_path in doc_paths:
            await self.rate_limiter.acquire()
            
            doc_url = urljoin(target, doc_path)
            try:
                response = requests.get(doc_url, timeout=10, verify=False)
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    if 'json' in content_type:
                        self.webapp_map.api_documentation['openapi'] = response.json()
                        self._parse_openapi_spec(response.json())
                    elif 'yaml' in content_type:
                        # Would need yaml parser
                        pass
            except:
                continue
    
    def _parse_openapi_spec(self, spec: Dict):
        """Parse OpenAPI/Swagger specification"""
        if 'paths' in spec:
            for path, methods in spec['paths'].items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint = Endpoint(
                            url=path,
                            method=method.upper(),
                            api_documentation=json.dumps(details)
                        )
                        
                        # Extract parameters
                        if 'parameters' in details:
                            for param in details['parameters']:
                                param_name = param.get('name', '')
                                if param_name:
                                    if param_name not in endpoint.parameters:
                                        endpoint.parameters[param_name] = []
                        
                        endpoint_key = f"{method.upper()}:{path}"
                        self.webapp_map.endpoints[endpoint_key] = endpoint
    
    def _detect_vulnerabilities(self, endpoint: Endpoint) -> List[str]:
        """Enhanced vulnerability detection with JavaScript awareness"""
        potential_vulns = []
        
        for vuln_type, patterns in self.vuln_patterns.items():
            total_weight = 0.0
            
            for pattern in patterns:
                # Parameter pattern matching
                if 'param_pattern' in pattern:
                    param_regex = re.compile(pattern['param_pattern'], re.I)
                    for param_name in endpoint.parameters.keys():
                        if param_regex.search(str(param_name)):
                            total_weight += pattern['weight']
                
                # Endpoint pattern matching
                if 'endpoint_pattern' in pattern:
                    endpoint_regex = re.compile(pattern['endpoint_pattern'], re.I)
                    if endpoint_regex.search(endpoint.url):
                        total_weight += pattern['weight']
                
                # Content type matching
                if 'content_type' in pattern:
                    if pattern['content_type'] in endpoint.content_type:
                        total_weight += pattern['weight']
                
                # JavaScript-specific checks
                if 'javascript_rendered' in pattern and endpoint.javascript_rendered:
                    total_weight += pattern['weight']
                
                if 'client_side_route' in pattern and endpoint.client_side_routes:
                    total_weight += pattern['weight']
                
                if 'dom_sink' in pattern and endpoint.dom_xss_sinks:
                    total_weight += pattern['weight']
                
                if 'graphql' in pattern and endpoint.graphql_endpoint:
                    total_weight += pattern['weight']
                
                if 'websocket' in pattern and endpoint.websocket_endpoint:
                    total_weight += pattern['weight']
                
                if 'javascript_file' in pattern and endpoint.url.endswith('.js'):
                    total_weight += pattern['weight']
            
            if total_weight >= 0.6:
                potential_vulns.append(vuln_type)
                
                if vuln_type not in self.webapp_map.vulnerability_map:
                    self.webapp_map.vulnerability_map[vuln_type] = []
                self.webapp_map.vulnerability_map[vuln_type].append(endpoint)
        
        return potential_vulns
    
    def _detect_client_side_vulns(self):
        """Detect client-side vulnerabilities"""
        # DOM XSS detection
        for endpoint in self.webapp_map.endpoints.values():
            if endpoint.dom_xss_sinks:
                if 'dom_xss' not in self.webapp_map.vulnerability_map:
                    self.webapp_map.vulnerability_map['dom_xss'] = []
                self.webapp_map.vulnerability_map['dom_xss'].append(endpoint)
        
        # Exposed API keys
        if 'api_key_exposure' in self.webapp_map.client_side_vulns:
            if 'api_key_exposure' not in self.webapp_map.vulnerability_map:
                self.webapp_map.vulnerability_map['api_key_exposure'] = []
            
            for exposure in self.webapp_map.client_side_vulns['api_key_exposure']:
                endpoint = Endpoint(
                    url=exposure['file'],
                    potential_vulns=['api_key_exposure']
                )
                self.webapp_map.vulnerability_map['api_key_exposure'].append(endpoint)
    
    def _analyze_relationships(self):
        """Analyze relationships between endpoints"""
        for endpoint_key, endpoint in self.webapp_map.endpoints.items():
            self.webapp_map.graph.add_node(endpoint_key, endpoint=endpoint)
            
            for other_key, other_endpoint in self.webapp_map.endpoints.items():
                if endpoint_key != other_key:
                    # Check parameter overlap
                    shared_params = set(endpoint.parameters.keys()) & set(other_endpoint.parameters.keys())
                    if shared_params:
                        self.webapp_map.graph.add_edge(
                            endpoint_key, 
                            other_key,
                            shared_params=list(shared_params)
                        )
                    
                    # Check API call relationships
                    if endpoint.url in other_endpoint.api_calls:
                        self.webapp_map.graph.add_edge(
                            other_key,
                            endpoint_key,
                            relationship='api_call'
                        )
    
    def _categorize_endpoints(self):
        """Enhanced endpoint categorization"""
        for endpoint_key, endpoint in self.webapp_map.endpoints.items():
            url_lower = endpoint.url.lower()
            
            # Authentication endpoints
            if any(auth in url_lower for auth in ['login', 'signin', 'auth', 'oauth', 'jwt', 'token']):
                self.webapp_map.authentication_endpoints.append(endpoint.url)
            
            # Admin endpoints
            if any(admin in url_lower for admin in ['admin', 'manage', 'dashboard', 'control']):
                self.webapp_map.admin_endpoints.append(endpoint.url)
            
            # API endpoints
            if '/api/' in url_lower or '/v1/' in url_lower or '/v2/' in url_lower or endpoint.graphql_endpoint:
                if endpoint.url not in self.webapp_map.api_endpoints:
                    self.webapp_map.api_endpoints.append(endpoint.url)
            
            # File upload endpoints
            if any(upload in url_lower for upload in ['upload', 'import', 'file', 'attachment']):
                self.webapp_map.file_upload_endpoints.append(endpoint.url)
    
    def _extract_forms(self, content: bytes) -> List[Dict]:
        """Extract and analyze forms from HTML content"""
        forms = []
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'inputs': [],
                    'csrf_token': False
                }
                
                for input_elem in form.find_all(['input', 'select', 'textarea']):
                    input_data = {
                        'name': input_elem.get('name', ''),
                        'type': input_elem.get('type', 'text'),
                        'value': input_elem.get('value', '')
                    }
                    form_data['inputs'].append(input_data)
                    
                    # Check for CSRF token
                    if 'csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower():
                        form_data['csrf_token'] = True
                
                forms.append(form_data)
        except:
            pass
        return forms
    
    def _process_form(self, url: str, form: Dict):
        """Process discovered form"""
        endpoint = Endpoint(
            url=form.get('action', url),
            method=form.get('method', 'POST').upper(),
            forms=[form],
            requires_csrf=form.get('csrf_token', False)
        )
        
        for input_field in form.get('inputs', []):
            param_name = input_field.get('name')
            if param_name:
                if param_name not in endpoint.parameters:
                    endpoint.parameters[param_name] = []
                endpoint.parameters[param_name].append(input_field.get('value', ''))
        
        endpoint.potential_vulns = self._detect_vulnerabilities(endpoint)
        
        endpoint_key = f"{endpoint.method}:{urlparse(endpoint.url).path}"
        self.webapp_map.endpoints[endpoint_key] = endpoint
    
    def _is_same_origin(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same origin"""
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        return parsed1.netloc == parsed2.netloc


# ============================================================================
# IDOR HUNTER (kept from original)
# ============================================================================

@dataclass
class Credential:
    """User credential pair"""
    username: str
    password: str
    realm: Optional[str] = None
    source: str = "manual"


@dataclass
class AuthSession:
    """Authenticated session information"""
    session_id: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    jwt_token: Optional[str] = None
    jwt_claims: Dict[str, Any] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None
    authenticated: bool = False


@dataclass
class IDOREvidence:
    """Evidence of IDOR vulnerability"""
    endpoint: str
    method: str
    original_request: Dict[str, Any]
    modified_request: Dict[str, Any]
    original_response: Dict[str, Any]
    modified_response: Dict[str, Any]
    evidence_type: str
    severity: str
    confidence: float
    unauthorized_data: Dict[str, Any] = field(default_factory=dict)


class CredentialManager:
    """Manages authentication credentials and sessions"""
    
    def __init__(self):
        self.default_credentials = self._load_default_credentials()
        self.weak_credentials = self._load_weak_credentials()
        self.active_sessions: Dict[str, AuthSession] = {}
        self.lockout_tracker: Dict[str, Dict] = {}
    
    def _load_default_credentials(self) -> Dict[str, List[Credential]]:
        """Load default credentials by product"""
        return {
            'apache': [
                Credential('admin', 'admin', 'Apache'),
                Credential('admin', 'password', 'Apache'),
            ],
            'nginx': [
                Credential('admin', 'admin', 'Nginx'),
                Credential('nginx', 'nginx', 'Nginx'),
            ],
            'wordpress': [
                Credential('admin', 'admin', 'WordPress'),
                Credential('admin', 'password', 'WordPress'),
                Credential('user', 'user', 'WordPress'),
            ],
            'drupal': [
                Credential('admin', 'admin', 'Drupal'),
                Credential('admin', 'password', 'Drupal'),
            ],
        }
    
    def _load_weak_credentials(self) -> List[Credential]:
        """Load common weak credential pairs"""
        weak_pairs = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('user', 'user'), ('user', 'password'), ('guest', 'guest'),
            ('test', 'test'), ('demo', 'demo'), ('root', 'root'),
        ]
        
        return [Credential(u, p, source="weak") for u, p in weak_pairs]
    
    def get_credential_candidates(self, fingerprint: Optional[TargetFingerprint] = None) -> List[Credential]:
        """Get credential candidates based on fingerprint"""
        candidates = []
        
        if fingerprint and fingerprint.product:
            product_creds = self.default_credentials.get(fingerprint.product.lower(), [])
            candidates.extend(product_creds)
            
            if fingerprint.cms:
                cms_creds = self.default_credentials.get(fingerprint.cms.lower(), [])
                candidates.extend(cms_creds)
        
        candidates.extend(self.weak_credentials[:10])
        return candidates
    
    def is_locked_out(self, target: str, username: str) -> bool:
        """Check if username is locked out for target"""
        key = f"{target}:{username}"
        if key not in self.lockout_tracker:
            return False
        
        tracker = self.lockout_tracker[key]
        
        if tracker.get('locked_until'):
            if datetime.now() < tracker['locked_until']:
                return True
            else:
                del self.lockout_tracker[key]
                return False
        
        return tracker.get('failure_count', 0) >= 3
    
    def record_auth_attempt(self, target: str, username: str, success: bool):
        """Record authentication attempt result"""
        key = f"{target}:{username}"
        
        if key not in self.lockout_tracker:
            self.lockout_tracker[key] = {'failure_count': 0, 'last_attempt': datetime.now()}
        
        tracker = self.lockout_tracker[key]
        tracker['last_attempt'] = datetime.now()
        
        if success:
            tracker['failure_count'] = 0
            if 'locked_until' in tracker:
                del tracker['locked_until']
        else:
            tracker['failure_count'] += 1
            
            if tracker['failure_count'] >= 3:
                lockout_duration = min(300, tracker['failure_count'] * 60)
                tracker['locked_until'] = datetime.now() + timedelta(seconds=lockout_duration)


class JWTAnalyzer:
    """Analyzes and manipulates JWT tokens"""
    
    @staticmethod
    def decode_jwt_safe(token: str) -> Optional[Dict[str, Any]]:
        """Safely decode JWT without verification"""
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except:
            return None
    
    @staticmethod
    def extract_user_claims(token: str) -> Dict[str, Any]:
        """Extract user-related claims from JWT"""
        decoded = JWTAnalyzer.decode_jwt_safe(token)
        if not decoded:
            return {}
        
        user_claims = {}
        
        user_fields = ['sub', 'uid', 'user_id', 'id', 'username', 'email']
        for field in user_fields:
            if field in decoded:
                user_claims[field] = decoded[field]
        
        role_fields = ['role', 'roles', 'permissions', 'scope', 'groups']
        for field in role_fields:
            if field in decoded:
                user_claims[field] = decoded[field]
        
        return user_claims
    
    @staticmethod
    def is_expired(token: str) -> bool:
        """Check if JWT is expired"""
        decoded = JWTAnalyzer.decode_jwt_safe(token)
        if not decoded:
            return True
        
        exp = decoded.get('exp')
        if exp:
            return datetime.fromtimestamp(exp) < datetime.now()
        
        return False


class IDORHunter:
    """IDOR vulnerability hunter"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.credential_manager = CredentialManager()
        self.evidence_found: List[IDOREvidence] = []
    
    async def hunt_idor(self, target: str, endpoints: List[Endpoint], 
                        fingerprint: Optional[TargetFingerprint] = None) -> List[IDOREvidence]:
        """Hunt for IDOR vulnerabilities"""
        
        # Attempt authentication
        session = await self._attempt_authentication(target, fingerprint)
        
        if not session or not session.authenticated:
            logger.warning("Could not authenticate for IDOR testing")
            return []
        
        # Test each endpoint
        for endpoint in endpoints:
            if 'idor' in endpoint.potential_vulns or endpoint.auth_required:
                evidence = await self._test_idor_endpoint(endpoint, session)
                if evidence:
                    self.evidence_found.append(evidence)
        
        return self.evidence_found
    
    async def _attempt_authentication(self, target: str, 
                                     fingerprint: Optional[TargetFingerprint]) -> Optional[AuthSession]:
        """Attempt to authenticate with target"""
        candidates = self.credential_manager.get_credential_candidates(fingerprint)
        
        for credential in candidates[:5]:
            if self.credential_manager.is_locked_out(target, credential.username):
                continue
            
            await asyncio.sleep(random.uniform(1, 3))
            
            session = await self._try_login(target, credential)
            
            success = session and session.authenticated
            self.credential_manager.record_auth_attempt(target, credential.username, success)
            
            if success:
                return session
        
        return None
    
    async def _try_login(self, target: str, credential: Credential) -> Optional[AuthSession]:
        """Try to login with credentials"""
        await self.rate_limiter.acquire()
        
        login_endpoints = ['/login', '/api/login', '/auth/login', '/signin']
        
        for login_path in login_endpoints:
            login_url = urljoin(target, login_path)
            
            try:
                # Try JSON login
                response = requests.post(
                    login_url,
                    json={'username': credential.username, 'password': credential.password},
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    session = self._create_session_from_response(response)
                    if session.authenticated:
                        return session
                
                # Try form login
                response = requests.post(
                    login_url,
                    data={'username': credential.username, 'password': credential.password},
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    session = self._create_session_from_response(response)
                    if session.authenticated:
                        return session
                        
            except:
                continue
        
        return None
    
    def _create_session_from_response(self, response: requests.Response) -> AuthSession:
        """Create session object from authentication response"""
        session = AuthSession(
            session_id=hashlib.md5(f"{response.url}{time.time()}".encode()).hexdigest(),
            cookies=dict(response.cookies),
            headers={}
        )
        
        try:
            json_data = response.json()
            
            jwt_fields = ['token', 'access_token', 'jwt', 'authToken']
            for field in jwt_fields:
                if field in json_data:
                    session.jwt_token = json_data[field]
                    session.headers['Authorization'] = f'Bearer {session.jwt_token}'
                    break
            
            if 'user' in json_data:
                user_info = json_data['user']
                session.user_id = user_info.get('id') or user_info.get('user_id')
                session.role = user_info.get('role')
                
        except:
            pass
        
        if any(cookie_name in session.cookies for cookie_name in ['JSESSIONID', 'PHPSESSID', 'session']):
            session.authenticated = True
        
        if session.jwt_token:
            session.jwt_claims = JWTAnalyzer.extract_user_claims(session.jwt_token)
            session.user_id = session.jwt_claims.get('sub') or session.jwt_claims.get('uid')
            session.authenticated = True
        
        return session
    
    async def _test_idor_endpoint(self, endpoint: Endpoint, 
                                 session: AuthSession) -> Optional[IDOREvidence]:
        """Test single endpoint for IDOR"""
        await self.rate_limiter.acquire()
        
        current_user_id = session.user_id or '1'
        test_ids = self._generate_test_ids(current_user_id)
        
        for test_id in test_ids:
            evidence = await self._check_idor(endpoint, session, test_id, current_user_id)
            if evidence:
                return evidence
        
        return None
    
    def _generate_test_ids(self, current_id: str) -> List[str]:
        """Generate test IDs for IDOR testing"""
        test_ids = []
        
        try:
            current_int = int(current_id)
            test_ids.extend([
                str(current_int - 1),
                str(current_int + 1),
                str(current_int - 10),
                str(current_int + 10),
                '1', '2', '100'
            ])
        except ValueError:
            test_ids.extend(['admin', 'administrator', 'user1', 'user2', '1', '2'])
        
        return list(set(test_ids))
    
    async def _check_idor(self, endpoint: Endpoint, session: AuthSession,
                         test_id: str, current_id: str) -> Optional[IDOREvidence]:
        """Check for IDOR vulnerability"""
        headers = session.headers.copy()
        
        # Build test URL
        test_url = endpoint.url
        if '{id}' in test_url:
            test_url = test_url.replace('{id}', test_id)
        elif endpoint.url.endswith('/'):
            test_url = f"{endpoint.url}{test_id}"
        else:
            test_url = f"{endpoint.url}/{test_id}"
        
        try:
            original_url = test_url.replace(test_id, current_id)
            original_response = requests.get(original_url, headers=headers, timeout=10, verify=False)
            test_response = requests.get(test_url, headers=headers, timeout=10, verify=False)
            
            if self._is_idor_vulnerable(original_response, test_response):
                return IDOREvidence(
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    original_request={'url': original_url, 'user_id': current_id},
                    modified_request={'url': test_url, 'test_id': test_id},
                    original_response={'status': original_response.status_code},
                    modified_response={'status': test_response.status_code},
                    evidence_type='object_access',
                    severity='High' if test_response.status_code == 200 else 'Medium',
                    confidence=0.8 if test_response.status_code == 200 else 0.6
                )
                
        except:
            pass
        
        return None
    
    def _is_idor_vulnerable(self, original: requests.Response, 
                           test: requests.Response) -> bool:
        """Check if responses indicate IDOR vulnerability"""
        if test.status_code == 200 and original.status_code == 200:
            size_diff = abs(len(test.content) - len(original.content))
            if size_diff < 100:
                return True
            
            try:
                test_data = test.json()
                orig_data = original.json()
                
                user_fields = ['id', 'user_id', 'username', 'email']
                for field in user_fields:
                    if field in orig_data and field in test_data:
                        if orig_data[field] != test_data[field]:
                            return True
            except:
                pass
        
        return False


# ============================================================================
# EXTERNAL TOOLS (kept from original)
# ============================================================================

@dataclass
class NmapResult:
    """Structured Nmap scan results"""
    host: str
    ports: List[Dict[str, Any]]
    os_info: Optional[Dict[str, str]] = None
    services: List[Dict[str, Any]] = None
    scripts: Dict[str, Any] = None
    scan_time: float = 0.0


@dataclass
class SQLMapResult:
    """Structured SQLMap results"""
    target: str
    vulnerable: bool
    database_type: Optional[str] = None
    injection_points: List[Dict[str, Any]] = None
    risk_level: str = "Unknown"
    scan_time: float = 0.0


class ExternalToolsManager:
    """Manager for external security tools"""
    
    def __init__(self, rate_limiter: RateLimiter, output_dir: Path = Path('./tool_output')):
        self.rate_limiter = rate_limiter
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
        
        self.nmap_path = 'nmap'
        self.sqlmap_path = 'sqlmap'
        
        self._verify_tools()
    
    def _verify_tools(self):
        """Verify external tools are available"""
        tools = {'nmap': self.nmap_path, 'sqlmap': self.sqlmap_path}
        
        for tool_name, tool_path in tools.items():
            try:
                result = subprocess.run(
                    [tool_path, '--version'], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"{tool_name} verified")
                else:
                    logger.warning(f"{tool_name} not found")
            except:
                logger.warning(f"{tool_name} not available")
    
    async def nmap_scan(self, target: str, scan_type: str = "light") -> Optional[NmapResult]:
        """Perform Nmap scan"""
        await self.rate_limiter.acquire()
        
        start_time = time.time()
        
        try:
            cmd = self._build_nmap_command(target, scan_type)
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=300)
            
            if result.returncode != 0:
                logger.error(f"Nmap scan failed: {stderr.decode()}")
                return None
            
            nmap_result = self._parse_nmap_output(stdout.decode(), target)
            nmap_result.scan_time = time.time() - start_time
            
            return nmap_result
            
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timed out for {target}")
            return None
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return None
    
    def _build_nmap_command(self, target: str, scan_type: str) -> List[str]:
        """Build Nmap command"""
        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.hostname or target
        
        base_cmd = [
            self.nmap_path,
            '--host-timeout', '120s',
            '--max-retries', '1',
            '-T2',  # Polite timing
            '-oX', '-'  # XML output to stdout
        ]
        
        if scan_type == "light":
            cmd = base_cmd + ['--top-ports', '100', '-sV', host]
        elif scan_type == "service_detection":
            cmd = base_cmd + ['-sV', '-sC', host]
        elif scan_type == "full":
            cmd = base_cmd + ['-sV', '-sC', '-O', host]
        else:
            cmd = base_cmd + ['--top-ports', '100', host]
        
        return cmd
    
    def _parse_nmap_output(self, xml_output: str, target: str) -> NmapResult:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            
            host_elem = root.find('.//host')
            if host_elem is None:
                return NmapResult(host=target, ports=[])
            
            ports = []
            for port_elem in host_elem.findall('.//port'):
                port_info = {
                    'port': port_elem.get('portid'),
                    'protocol': port_elem.get('protocol'),
                    'state': port_elem.find('state').get('state') if port_elem.find('state') is not None else 'unknown'
                }
                
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    port_info.update({
                        'service': service_elem.get('name', ''),
                        'product': service_elem.get('product', ''),
                        'version': service_elem.get('version', '')
                    })
                
                ports.append(port_info)
            
            os_info = {}
            os_elem = host_elem.find('.//os')
            if os_elem is not None:
                osmatch_elem = os_elem.find('osmatch')
                if osmatch_elem is not None:
                    os_info = {
                        'name': osmatch_elem.get('name', ''),
                        'accuracy': osmatch_elem.get('accuracy', '')
                    }
            
            scripts = {}
            for script_elem in host_elem.findall('.//script'):
                scripts[script_elem.get('id')] = script_elem.get('output', '')
            
            return NmapResult(
                host=target,
                ports=ports,
                os_info=os_info if os_info else None,
                services=[p for p in ports if p.get('service')],
                scripts=scripts if scripts else None
            )
            
        except ET.ParseError:
            return NmapResult(host=target, ports=[])
    
    async def sqlmap_scan(self, target: str, scan_level: int = 1, 
                         risk_level: int = 1) -> Optional[SQLMapResult]:
        """Perform SQLMap scan"""
        await self.rate_limiter.acquire()
        
        start_time = time.time()
        
        try:
            cmd = self._build_sqlmap_command(target, scan_level, risk_level)
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=600)
            
            sqlmap_result = self._parse_sqlmap_output(stdout.decode(), target)
            sqlmap_result.scan_time = time.time() - start_time
            
            return sqlmap_result
            
        except asyncio.TimeoutError:
            logger.error(f"SQLMap scan timed out for {target}")
            return None
        except Exception as e:
            logger.error(f"SQLMap scan error: {e}")
            return None
    
    def _build_sqlmap_command(self, target: str, scan_level: int, risk_level: int) -> List[str]:
        """Build SQLMap command"""
        return [
            self.sqlmap_path,
            '-u', target,
            '--level', str(scan_level),
            '--risk', str(risk_level),
            '--timeout', '30',
            '--retries', '1',
            '--delay', '2',
            '--batch',
            '--flush-session',
            '--threads', '1'
        ]
    
    def _parse_sqlmap_output(self, output: str, target: str) -> SQLMapResult:
        """Parse SQLMap output"""
        vulnerable = 'Parameter:' in output and 'is vulnerable' in output
        
        database_type = None
        db_patterns = {
            'MySQL': r'MySQL',
            'PostgreSQL': r'PostgreSQL',
            'Microsoft SQL Server': r'Microsoft SQL Server',
            'Oracle': r'Oracle',
            'SQLite': r'SQLite'
        }
        
        for db_name, pattern in db_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                database_type = db_name
                break
        
        injection_points = []
        injection_matches = re.findall(
            r'Parameter: ([^\s]+).*?Type: ([^\n]+).*?Payload: ([^\n]+)',
            output,
            re.DOTALL
        )
        
        for match in injection_matches:
            injection_points.append({
                'parameter': match[0],
                'injection_type': match[1],
                'payload': match[2]
            })
        
        risk_level = "Unknown"
        if vulnerable:
            if 'time-based' in output.lower():
                risk_level = "Medium"
            elif 'union' in output.lower() or 'error-based' in output.lower():
                risk_level = "High"
            else:
                risk_level = "Low"
        
        return SQLMapResult(
            target=target,
            vulnerable=vulnerable,
            database_type=database_type,
            injection_points=injection_points,
            risk_level=risk_level
        )


# ============================================================================
# UNIFIED SCANNER
# ============================================================================

class UnifiedScanner:
    """Enhanced unified scanning and mapping system with SmartWebCrawler"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Initialize enhanced rate limiter
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('requests_per_second', 5),
            burst_size=self.config.get('burst_size', 10),
            respect_headers=self.config.get('respect_headers', True),
            adaptive=self.config.get('adaptive_throttling', True)
        )
        
        # Initialize components
        self.web_mapper = WebApplicationMapper(self.rate_limiter)
        self.idor_hunter = IDORHunter(self.rate_limiter)
        self.external_tools = ExternalToolsManager(
            self.rate_limiter,
            Path(self.config.get('output_dir', './scan_output'))
        )
        
        self.fingerprint = TargetFingerprint()
        
        # SmartWebCrawler reference (if available)
        self.smart_crawler = self.web_mapper.smart_crawler
    
    async def comprehensive_scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Enhanced comprehensive scan with JavaScript awareness
        
        Args:
            target: Target URL/IP to scan
            options: Scanning options
                - scan_type: 'light', 'normal', 'aggressive'
                - enable_nmap: Enable Nmap scanning
                - enable_sqlmap: Enable SQLMap testing
                - enable_idor: Enable IDOR hunting
                - use_browser: Use browser automation
                - use_smart_crawler: Use SmartWebCrawler
                
        Returns:
            Comprehensive scan results
        """
        options = options or {}
        scan_type = options.get('scan_type', 'normal')
        
        result = ScanResult(
            target=target,
            timestamp=time.time(),
            endpoints=[],
            vulnerabilities={},
            services={},
            credentials={},
            fingerprint=self.fingerprint,
            evidence=[]
        )
        
        # Phase 1: Network reconnaissance (Nmap)
        if options.get('enable_nmap', True):
            logger.info(f"Starting Nmap scan on {target}")
            nmap_result = await self.external_tools.nmap_scan(target, scan_type="service_detection")
            if nmap_result:
                result.services['nmap'] = {
                    'ports': nmap_result.ports,
                    'services': nmap_result.services,
                    'os_info': nmap_result.os_info
                }
                self._update_fingerprint_from_nmap(nmap_result)
        
        # Phase 2: Enhanced web application mapping
        logger.info(f"Starting enhanced web application mapping on {target}")
        webapp_map = await self.web_mapper.map_application(
            target,
            duration=300 if scan_type == 'aggressive' else 60,
            use_browser=options.get('use_browser', True),
            use_smart_crawler=options.get('use_smart_crawler', True)
        )
        
        # Convert webapp endpoints to unified format
        for endpoint_key, endpoint in webapp_map.endpoints.items():
            result.endpoints.append(endpoint)
        
        # Store vulnerability map
        result.vulnerabilities.update(webapp_map.vulnerability_map)
        
        # Store JavaScript analysis results
        result.javascript_analysis = {
            'javascript_files': webapp_map.javascript_files,
            'client_side_vulns': webapp_map.client_side_vulns,
            'spa_routes': webapp_map.spa_routes,
            'graphql_endpoints': webapp_map.graphql_endpoints,
            'websocket_endpoints': webapp_map.websocket_endpoints
        }
        
        # Store API documentation if found
        if webapp_map.api_documentation:
            result.api_schema = webapp_map.api_documentation
        
        # Phase 3: SQL injection testing
        if options.get('enable_sqlmap', True) and webapp_map.endpoints:
            logger.info("Starting SQLMap testing")
            
            # Test high-priority endpoints
            sqli_targets = self._get_sqli_targets(webapp_map.endpoints.values())
            for target_endpoint in sqli_targets[:3]:  # Limit to 3 targets
                sqlmap_result = await self.external_tools.sqlmap_scan(
                    target_endpoint.url,
                    scan_level=2 if scan_type == 'aggressive' else 1
                )
                if sqlmap_result and sqlmap_result.vulnerable:
                    if 'sqli' not in result.vulnerabilities:
                        result.vulnerabilities['sqli'] = []
                    result.vulnerabilities['sqli'].append({
                        'url': sqlmap_result.target,
                        'injection_points': sqlmap_result.injection_points,
                        'database_type': sqlmap_result.database_type,
                        'risk_level': sqlmap_result.risk_level
                    })
        
        # Phase 4: IDOR hunting
        if options.get('enable_idor', True) and webapp_map.endpoints:
            logger.info("Starting IDOR hunting")
            
            # Get potential IDOR endpoints
            idor_targets = [e for e in result.endpoints if 'idor' in e.potential_vulns]
            
            if idor_targets:
                idor_evidence = await self.idor_hunter.hunt_idor(
                    target,
                    idor_targets,
                    self.fingerprint
                )
                
                if idor_evidence:
                    result.evidence.extend(idor_evidence)
                    if 'idor' not in result.vulnerabilities:
                        result.vulnerabilities['idor'] = []
                    for evidence in idor_evidence:
                        result.vulnerabilities['idor'].append({
                            'endpoint': evidence.endpoint,
                            'severity': evidence.severity,
                            'confidence': evidence.confidence
                        })
        
        # Generate enhanced summary
        result.summary = self._generate_enhanced_summary(result)
        
        return result
    
    def _update_fingerprint_from_nmap(self, nmap_result: NmapResult):
        """Update fingerprint from Nmap results"""
        for service in nmap_result.services or []:
            if service.get('service') in ['http', 'https']:
                if service.get('product'):
                    self.fingerprint.product = service['product']
                if service.get('version'):
                    self.fingerprint.version = service['version']
        
        if nmap_result.os_info:
            self.fingerprint.technologies.append(nmap_result.os_info.get('name', ''))
    
    def _get_sqli_targets(self, endpoints) -> List[Endpoint]:
        """Get high-priority SQLi targets"""
        targets = []
        
        for endpoint in endpoints:
            if 'sqli' in endpoint.potential_vulns:
                targets.append(endpoint)
            elif any(param in str(endpoint.parameters.keys()) 
                    for param in ['id', 'user', 'search', 'filter']):
                targets.append(endpoint)
        
        # Prioritize API endpoints
        targets.sort(key=lambda e: 1 if e.api_calls else 0, reverse=True)
        
        return targets
    
    def _generate_enhanced_summary(self, result: ScanResult) -> Dict[str, Any]:
        """Generate enhanced scan summary"""
        return {
            'total_endpoints': len(result.endpoints),
            'api_endpoints': len([e for e in result.endpoints if e.api_calls]),
            'javascript_files': len(result.javascript_analysis.get('javascript_files', [])),
            'graphql_endpoints': len(result.javascript_analysis.get('graphql_endpoints', [])),
            'websocket_endpoints': len(result.javascript_analysis.get('websocket_endpoints', [])),
            'open_ports': len(result.services.get('nmap', {}).get('ports', [])),
            'vulnerability_types': list(result.vulnerabilities.keys()),
            'high_risk_findings': sum(
                1 for vuln_list in result.vulnerabilities.values()
                for vuln in vuln_list
                if isinstance(vuln, dict) and vuln.get('risk_level') == 'High'
            ),
            'client_side_vulns': list(result.javascript_analysis.get('client_side_vulns', {}).keys()),
            'idor_evidence_count': len([e for e in result.evidence if isinstance(e, IDOREvidence)]),
            'technologies_detected': self.fingerprint.technologies,
            'javascript_libraries': self.fingerprint.javascript_libraries,
            'api_documentation_found': bool(result.api_schema)
        }
    
    def export_results(self, result: ScanResult, filename: str = "scan_results.json"):
        """Export enhanced scan results to file"""
        export_data = {
            'target': result.target,
            'timestamp': result.timestamp,
            'summary': getattr(result, 'summary', {}),
            'endpoints': [
                {
                    'url': e.url,
                    'method': e.method,
                    'parameters': e.parameters,
                    'potential_vulns': e.potential_vulns,
                    'auth_required': e.auth_required,
                    'javascript_rendered': e.javascript_rendered,
                    'dynamic_content': e.dynamic_content,
                    'graphql': e.graphql_endpoint,
                    'websocket': e.websocket_endpoint,
                    'dom_xss_sinks': e.dom_xss_sinks
                }
                for e in result.endpoints
            ],
            'vulnerabilities': result.vulnerabilities,
            'services': result.services,
            'javascript_analysis': result.javascript_analysis,
            'api_schema': result.api_schema,
            'fingerprint': {
                'product': self.fingerprint.product,
                'version': self.fingerprint.version,
                'cms': self.fingerprint.cms,
                'technologies': self.fingerprint.technologies,
                'javascript_libraries': self.fingerprint.javascript_libraries,
                'api_type': self.fingerprint.api_type,
                'waf': self.fingerprint.waf
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Results exported to {filename}")
        
        return export_data


# For backward compatibility
AdaptiveLearningMapper = WebApplicationMapper
EnhancedWebMapper = WebApplicationMapper
EndpointMapper = WebApplicationMapper

__all__ = [
    'UnifiedScanner',
    'WebApplicationMapper',
    'IDORHunter',
    'ExternalToolsManager',
    'RateLimiter',
    'Endpoint',
    'ScanResult',
    'WebAppMap',
    'NmapResult',
    'SQLMapResult',
    'IDOREvidence',
    'CredentialManager',
    'JWTAnalyzer',
    'TargetFingerprint'
]
