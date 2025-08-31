"""
Advanced JavaScript-Aware Web Crawler
Enhanced crawler with JavaScript parsing and dynamic content discovery
"""

import asyncio
import re
import json
import time
import hashlib
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from collections import defaultdict
import logging
import networkx as nx
from bs4 import BeautifulSoup
import esprima  # For JavaScript parsing

# Browser automation
try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class JavaScriptAsset:
    """JavaScript asset found during crawling"""
    url: str
    content: str
    source_page: str
    apis_found: List[str] = field(default_factory=list)
    endpoints_found: List[str] = field(default_factory=list)
    secrets_found: List[Dict] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    event_handlers: List[str] = field(default_factory=list)


@dataclass
class DynamicContent:
    """Dynamic content loaded via JavaScript"""
    url: str
    trigger: str  # What triggered the content (click, scroll, etc.)
    content_type: str
    data: Any
    timestamp: float


@dataclass
class APIEndpoint:
    """API endpoint discovered through JavaScript analysis"""
    url: str
    method: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[str] = None
    discovered_in: str = ""  # Which JS file or page
    request_body_schema: Optional[Dict] = None
    response_schema: Optional[Dict] = None


@dataclass
class CrawlResult:
    """Enhanced crawl result with JavaScript analysis"""
    pages_crawled: int
    endpoints_discovered: List[APIEndpoint]
    javascript_files: List[JavaScriptAsset]
    dynamic_content: List[DynamicContent]
    site_map: nx.DiGraph
    technologies_detected: Set[str]
    vulnerabilities_hints: List[Dict]
    forms: List[Dict]
    websocket_endpoints: List[str]
    graphql_endpoints: List[str]


class JavaScriptParser:
    """Parser for JavaScript code analysis"""
    
    def __init__(self):
        self.api_patterns = [
            r'fetch\([\'"`]([^\'"`]+)[\'"`]',
            r'\.ajax\(\{[^}]*url:\s*[\'"`]([^\'"`]+)[\'"`]',
            r'axios\.[get|post|put|delete]+\([\'"`]([^\'"`]+)[\'"`]',
            r'XMLHttpRequest.*open\([\'"`]\w+[\'"`],\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.get\([\'"`]([^\'"`]+)[\'"`]',
            r'\.post\([\'"`]([^\'"`]+)[\'"`]'
        ]
        
        self.secret_patterns = {
            'api_key': r'[\'"`](api[_-]?key|apikey)[\'"`]\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
            'secret': r'[\'"`](secret|token|auth)[\'"`]\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
            'password': r'[\'"`]password[\'"`]\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
            'aws': r'AKIA[0-9A-Z]{16}',
            'github': r'ghp_[a-zA-Z0-9]{36}',
            'slack': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}'
        }
        
        self.framework_signatures = {
            'react': ['React.', 'ReactDOM', 'useState', 'useEffect'],
            'angular': ['angular.', 'ng-', '$scope', '$http'],
            'vue': ['Vue.', 'v-if', 'v-for', 'v-model'],
            'jquery': ['jQuery', '$(', '$.ajax'],
            'webpack': ['__webpack_require__', 'webpackJsonp']
        }
    
    def parse_javascript(self, js_code: str, source_url: str) -> JavaScriptAsset:
        """Parse JavaScript code for endpoints and secrets"""
        asset = JavaScriptAsset(
            url=source_url,
            content=js_code[:1000],  # Store first 1000 chars
            source_page=source_url
        )
        
        # Find API endpoints
        for pattern in self.api_patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if self._is_valid_endpoint(match):
                    asset.endpoints_found.append(match)
        
        # Find secrets
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    secret_value = match[1] if len(match) > 1 else match[0]
                else:
                    secret_value = match
                
                if self._is_likely_secret(secret_value):
                    asset.secrets_found.append({
                        'type': secret_type,
                        'value': secret_value[:20] + '...' if len(secret_value) > 20 else secret_value,
                        'pattern': pattern
                    })
        
        # Parse with esprima for deeper analysis
        try:
            tree = esprima.parseScript(js_code, tolerant=True)
            asset.functions = self._extract_functions(tree)
            asset.event_handlers = self._extract_event_handlers(tree)
            asset.apis_found = self._extract_api_calls(tree)
        except:
            # Fallback to regex if parsing fails
            pass
        
        return asset
    
    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is valid"""
        if not endpoint:
            return False
        
        # Filter out common false positives
        invalid_patterns = [
            r'^#', r'^\?', r'^javascript:', r'^data:',
            r'^blob:', r'^about:', r'^\$\{', r'^\{', r'^//'
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, endpoint):
                return False
        
        return True
    
    def _is_likely_secret(self, value: str) -> bool:
        """Check if value is likely a real secret"""
        if not value or len(value) < 8:
            return False
        
        # Filter out common placeholders
        placeholders = [
            'your-api-key', 'api_key_here', 'xxxxxx',
            'example', 'test', 'demo', 'placeholder'
        ]
        
        value_lower = value.lower()
        return not any(placeholder in value_lower for placeholder in placeholders)
    
    def _extract_functions(self, ast) -> List[str]:
        """Extract function names from AST"""
        functions = []
        
        def visit(node):
            if node.type == 'FunctionDeclaration' and hasattr(node, 'id'):
                functions.append(node.id.name)
            elif node.type == 'FunctionExpression' and hasattr(node, 'id') and node.id:
                functions.append(node.id.name)
            
            for key in node.__dict__:
                child = getattr(node, key)
                if isinstance(child, list):
                    for item in child:
                        if hasattr(item, 'type'):
                            visit(item)
                elif hasattr(child, 'type'):
                    visit(child)
        
        visit(ast)
        return functions
    
    def _extract_event_handlers(self, ast) -> List[str]:
        """Extract event handler registrations"""
        handlers = []
        
        def visit(node):
            if node.type == 'CallExpression':
                if hasattr(node, 'callee') and hasattr(node.callee, 'property'):
                    prop_name = getattr(node.callee.property, 'name', '')
                    if prop_name in ['addEventListener', 'on', 'bind']:
                        if node.arguments and hasattr(node.arguments[0], 'value'):
                            handlers.append(node.arguments[0].value)
            
            for key in node.__dict__:
                child = getattr(node, key)
                if isinstance(child, list):
                    for item in child:
                        if hasattr(item, 'type'):
                            visit(item)
                elif hasattr(child, 'type'):
                    visit(child)
        
        visit(ast)
        return handlers
    
    def _extract_api_calls(self, ast) -> List[str]:
        """Extract API call patterns from AST"""
        api_calls = []
        
        def visit(node):
            if node.type == 'CallExpression':
                if hasattr(node, 'callee'):
                    callee = node.callee
                    
                    # Check for fetch, axios, etc.
                    if hasattr(callee, 'name') and callee.name in ['fetch', 'axios']:
                        if node.arguments and hasattr(node.arguments[0], 'value'):
                            api_calls.append(node.arguments[0].value)
                    
                    # Check for jQuery.ajax, $.get, etc.
                    elif hasattr(callee, 'property') and hasattr(callee.property, 'name'):
                        if callee.property.name in ['ajax', 'get', 'post', 'put', 'delete']:
                            if node.arguments and hasattr(node.arguments[0], 'value'):
                                api_calls.append(node.arguments[0].value)
            
            for key in node.__dict__:
                child = getattr(node, key)
                if isinstance(child, list):
                    for item in child:
                        if hasattr(item, 'type'):
                            visit(item)
                elif hasattr(child, 'type'):
                    visit(child)
        
        visit(ast)
        return api_calls
    
    def detect_frameworks(self, js_code: str) -> Set[str]:
        """Detect JavaScript frameworks"""
        detected = set()
        
        for framework, signatures in self.framework_signatures.items():
            for signature in signatures:
                if signature in js_code:
                    detected.add(framework)
                    break
        
        return detected


class SmartWebCrawler:
    """Advanced web crawler with JavaScript awareness"""
    
    def __init__(self, max_depth: int = 3, max_pages: int = 100):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.js_parser = JavaScriptParser()
        self.crawled_urls = set()
        self.discovered_endpoints = []
        self.javascript_assets = []
        self.dynamic_content = []
        self.site_graph = nx.DiGraph()
        self.technologies = set()
        self.forms = []
        self.websocket_endpoints = []
        self.graphql_endpoints = []
        self.vulnerability_hints = []
    
    async def crawl(self, start_url: str) -> CrawlResult:
        """Start crawling from URL"""
        if not PLAYWRIGHT_AVAILABLE:
            logger.error("Playwright not available for JavaScript crawling")
            return self._empty_result()
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True
            )
            
            # Set up request interception
            await self._setup_interception(context)
            
            # Start crawling
            await self._crawl_page(context, start_url, 0)
            
            await browser.close()
        
        return CrawlResult(
            pages_crawled=len(self.crawled_urls),
            endpoints_discovered=self.discovered_endpoints,
            javascript_files=self.javascript_assets,
            dynamic_content=self.dynamic_content,
            site_map=self.site_graph,
            technologies_detected=self.technologies,
            vulnerabilities_hints=self.vulnerability_hints,
            forms=self.forms,
            websocket_endpoints=self.websocket_endpoints,
            graphql_endpoints=self.graphql_endpoints
        )
    
    async def _setup_interception(self, context: BrowserContext):
        """Set up request/response interception"""
        
        async def handle_route(route):
            request = route.request
            url = request.url
            
            # Track API calls
            if '/api/' in url or url.endswith('.json'):
                self._process_api_request(request)
            
            # Track WebSocket
            if url.startswith('ws://') or url.startswith('wss://'):
                self.websocket_endpoints.append(url)
            
            # Track GraphQL
            if '/graphql' in url:
                self.graphql_endpoints.append(url)
                self._process_graphql_request(request)
            
            await route.continue_()
        
        await context.route('**/*', handle_route)
        
        # Listen to console messages
        async def handle_console(msg):
            if msg.type == 'error':
                self._analyze_console_error(msg.text)
        
        context.on('console', handle_console)
    
    async def _crawl_page(self, context: BrowserContext, url: str, depth: int):
        """Crawl a single page"""
        if depth > self.max_depth or len(self.crawled_urls) >= self.max_pages:
            return
        
        if url in self.crawled_urls:
            return
        
        self.crawled_urls.add(url)
        logger.info(f"Crawling: {url} (depth: {depth})")
        
        try:
            page = await context.new_page()
            
            # Navigate to page
            response = await page.goto(url, wait_until='networkidle', timeout=30000)
            
            if response:
                # Add to site graph
                self.site_graph.add_node(url, status=response.status)
                
                # Extract and analyze JavaScript
                await self._extract_javascript(page, url)
                
                # Extract forms
                await self._extract_forms(page, url)
                
                # Perform dynamic interactions
                await self._perform_dynamic_interactions(page, url)
                
                # Extract links and continue crawling
                links = await self._extract_links(page)
                
                for link in links:
                    if self._should_crawl(link, url):
                        self.site_graph.add_edge(url, link)
                        await self._crawl_page(context, link, depth + 1)
            
            await page.close()
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
    
    async def _extract_javascript(self, page: Page, url: str):
        """Extract and analyze JavaScript from page"""
        
        # Get inline scripts
        inline_scripts = await page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script').forEach(script => {
                    if (script.innerHTML && !script.src) {
                        scripts.push(script.innerHTML);
                    }
                });
                return scripts;
            }
        """)
        
        for script in inline_scripts:
            asset = self.js_parser.parse_javascript(script, url)
            self.javascript_assets.append(asset)
            
            # Detect technologies
            self.technologies.update(self.js_parser.detect_frameworks(script))
            
            # Process discovered endpoints
            for endpoint in asset.endpoints_found:
                self._add_api_endpoint(endpoint, url)
        
        # Get external scripts
        external_scripts = await page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script[src]').forEach(script => {
                    scripts.push(script.src);
                });
                return scripts;
            }
        """)
        
        for script_url in external_scripts:
            await self._fetch_and_analyze_script(script_url, url)
    
    async def _fetch_and_analyze_script(self, script_url: str, source_page: str):
        """Fetch and analyze external JavaScript"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(script_url) as response:
                    if response.status == 200:
                        js_content = await response.text()
                        asset = self.js_parser.parse_javascript(js_content, script_url)
                        asset.source_page = source_page
                        self.javascript_assets.append(asset)
                        
                        # Process discovered endpoints
                        for endpoint in asset.endpoints_found:
                            full_url = urljoin(source_page, endpoint)
                            self._add_api_endpoint(full_url, script_url)
        except:
            pass
    
    async def _extract_forms(self, page: Page, url: str):
        """Extract forms from page"""
        forms = await page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    form.querySelectorAll('input, select, textarea').forEach(input => {
                        inputs.push({
                            name: input.name,
                            type: input.type || 'text',
                            required: input.required,
                            value: input.value
                        });
                    });
                    
                    forms.push({
                        action: form.action,
                        method: form.method || 'GET',
                        inputs: inputs,
                        id: form.id,
                        classes: form.className
                    });
                });
                return forms;
            }
        """)
        
        for form in forms:
            form['source_page'] = url
            self.forms.append(form)
            
            # Check for potential vulnerabilities
            self._analyze_form_vulnerabilities(form)
    
    async def _perform_dynamic_interactions(self, page: Page, url: str):
        """Perform dynamic interactions to discover content"""
        
        # Click on elements that might load dynamic content
        clickable_selectors = [
            'button:not([type="submit"])',
            'a[href="#"]',
            '[onclick]',
            '[data-toggle]',
            '.load-more',
            '.show-more'
        ]
        
        for selector in clickable_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for element in elements[:5]:  # Limit to 5 per type
                    # Record network activity
                    network_events = []
                    
                    async def capture_request(request):
                        network_events.append(request.url)
                    
                    page.on('request', capture_request)
                    
                    # Click element
                    await element.click()
                    await page.wait_for_timeout(1000)
                    
                    # Check for new content
                    for event_url in network_events:
                        if event_url not in self.crawled_urls:
                            self.dynamic_content.append(DynamicContent(
                                url=event_url,
                                trigger=f'click:{selector}',
                                content_type='ajax',
                                data=None,
                                timestamp=time.time()
                            ))
                    
                    page.remove_listener('request', capture_request)
                    
            except:
                continue
        
        # Scroll to trigger lazy loading
        await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
        await page.wait_for_timeout(1000)
    
    async def _extract_links(self, page: Page) -> List[str]:
        """Extract all links from page"""
        links = await page.evaluate("""
            () => {
                const links = new Set();
                
                // Regular links
                document.querySelectorAll('a[href]').forEach(a => {
                    links.add(a.href);
                });
                
                // JavaScript navigation
                document.querySelectorAll('[data-href], [data-url]').forEach(el => {
                    const url = el.dataset.href || el.dataset.url;
                    if (url) links.add(url);
                });
                
                // Router links (React, Vue, etc.)
                document.querySelectorAll('[to]').forEach(el => {
                    if (el.getAttribute('to')) {
                        links.add(el.getAttribute('to'));
                    }
                });
                
                return Array.from(links);
            }
        """)
        
        # Normalize links
        page_url = page.url
        normalized_links = []
        
        for link in links:
            normalized = urljoin(page_url, link)
            normalized_links.append(normalized)
        
        return normalized_links
    
    def _should_crawl(self, url: str, source_url: str) -> bool:
        """Check if URL should be crawled"""
        if url in self.crawled_urls:
            return False
        
        if len(self.crawled_urls) >= self.max_pages:
            return False
        
        # Check same origin
        source_parsed = urlparse(source_url)
        url_parsed = urlparse(url)
        
        if source_parsed.netloc != url_parsed.netloc:
            return False
        
        # Skip certain file types
        skip_extensions = ['.pdf', '.zip', '.exe', '.dmg', '.jpg', '.png', '.gif']
        for ext in skip_extensions:
            if url.lower().endswith(ext):
                return False
        
        return True
    
    def _add_api_endpoint(self, url: str, discovered_in: str):
        """Add discovered API endpoint"""
        # Try to determine method and parameters
        method = 'GET'
        params = {}
        
        # Parse URL for parameters
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
        
        # Check if it's already discovered
        for endpoint in self.discovered_endpoints:
            if endpoint.url == url:
                return
        
        endpoint = APIEndpoint(
            url=url,
            method=method,
            parameters=params,
            discovered_in=discovered_in
        )
        
        self.discovered_endpoints.append(endpoint)
    
    def _process_api_request(self, request):
        """Process intercepted API request"""
        endpoint = APIEndpoint(
            url=request.url,
            method=request.method,
            headers=dict(request.headers),
            discovered_in='network_intercept'
        )
        
        # Extract parameters
        if request.method == 'GET':
            parsed = urlparse(request.url)
            if parsed.query:
                endpoint.parameters = parse_qs(parsed.query)
        
        # Check for authentication
        auth_header = request.headers.get('authorization', '')
        if auth_header:
            if auth_header.startswith('Bearer'):
                endpoint.authentication = 'Bearer'
            elif auth_header.startswith('Basic'):
                endpoint.authentication = 'Basic'
            else:
                endpoint.authentication = 'Custom'
        
        self.discovered_endpoints.append(endpoint)
    
    def _process_graphql_request(self, request):
        """Process GraphQL request"""
        # GraphQL specific processing
        endpoint = APIEndpoint(
            url=request.url,
            method='POST',
            discovered_in='graphql_intercept'
        )
        
        # Try to extract query
        if request.post_data:
            try:
                data = json.loads(request.post_data)
                if 'query' in data:
                    endpoint.request_body_schema = {
                        'query': data.get('query', ''),
                        'variables': data.get('variables', {}),
                        'operationName': data.get('operationName', '')
                    }
            except:
                pass
        
        self.discovered_endpoints.append(endpoint)
    
    def _analyze_form_vulnerabilities(self, form: Dict):
        """Analyze form for potential vulnerabilities"""
        hints = []
        
        # Check for CSRF token
        has_csrf = any(
            'csrf' in input_field.get('name', '').lower() or 
            'token' in input_field.get('name', '').lower()
            for input_field in form.get('inputs', [])
        )
        
        if not has_csrf and form.get('method', '').upper() == 'POST':
            hints.append({
                'type': 'CSRF',
                'location': form.get('action', ''),
                'details': 'POST form without CSRF token',
                'confidence': 0.7
            })
        
        # Check for file upload
        has_file_upload = any(
            input_field.get('type') == 'file'
            for input_field in form.get('inputs', [])
        )
        
        if has_file_upload:
            hints.append({
                'type': 'File Upload',
                'location': form.get('action', ''),
                'details': 'File upload form found',
                'confidence': 0.8
            })
        
        # Check for potential SQL injection points
        for input_field in form.get('inputs', []):
            name = input_field.get('name', '').lower()
            if any(keyword in name for keyword in ['id', 'user', 'search', 'filter']):
                hints.append({
                    'type': 'SQLi',
                    'location': form.get('action', ''),
                    'parameter': input_field.get('name'),
                    'details': f'Potential injection point: {name}',
                    'confidence': 0.5
                })
        
        self.vulnerability_hints.extend(hints)
    
    def _analyze_console_error(self, error_text: str):
        """Analyze console errors for information disclosure"""
        
        # Check for stack traces
        if 'at ' in error_text and '(' in error_text:
            self.vulnerability_hints.append({
                'type': 'Information Disclosure',
                'details': 'Stack trace in console',
                'content': error_text[:200],
                'confidence': 0.6
            })
        
        # Check for API keys or secrets
        secret_patterns = ['api', 'key', 'token', 'secret', 'password']
        for pattern in secret_patterns:
            if pattern in error_text.lower():
                self.vulnerability_hints.append({
                    'type': 'Sensitive Data Exposure',
                    'details': f'Possible {pattern} in console error',
                    'confidence': 0.5
                })
    
    def _empty_result(self) -> CrawlResult:
        """Return empty result when crawling fails"""
        return CrawlResult(
            pages_crawled=0,
            endpoints_discovered=[],
            javascript_files=[],
            dynamic_content=[],
            site_map=nx.DiGraph(),
            technologies_detected=set(),
            vulnerabilities_hints=[],
            forms=[],
            websocket_endpoints=[],
            graphql_endpoints=[]
        )


# Export main crawler
smart_crawler = SmartWebCrawler()
