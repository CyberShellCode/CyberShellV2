"""
WAF-Aware HTTP Engine with Integrated Bypass System
Bridges the gap by integrating bypass_system.py into the HTTP request flow
"""

import requests
import time
import json
import hashlib
import asyncio
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
from dataclasses import dataclass, field
from enum import Enum

# Import the bypass system
from cybershell.bypass_system import UnifiedBypassSystem, ProtectionDetection

# Optional browser automation
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

logger = logging.getLogger(__name__)


class ProtectionType(Enum):
    """Types of protection mechanisms"""
    WAF = "WAF"
    RATE_LIMIT = "Rate Limiting"
    BOT_DETECTION = "Bot Detection"
    CAPTCHA = "CAPTCHA"
    CLOUDFLARE = "Cloudflare"
    CUSTOM = "Custom"


@dataclass
class RequestContext:
    """Context for HTTP requests"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    data: Any = None
    json_data: Dict[str, Any] = None
    timeout: int = 10
    allow_redirects: bool = True
    bypass_attempts: int = 0
    max_bypass_attempts: int = 10
    detected_protections: List[ProtectionType] = field(default_factory=list)


@dataclass
class EnhancedEvidence:
    """Enhanced evidence with WAF bypass information"""
    id: str
    timestamp: float
    request: Dict[str, Any]
    response: Dict[str, Any]
    analysis: Dict[str, Any]
    bypass_used: Optional[str] = None
    protection_bypassed: Optional[str] = None
    javascript_rendered: bool = False
    browser_evidence: Optional[Dict] = None


class WAFAwareHTTPEngine:
    """HTTP Engine with integrated WAF detection and bypass"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.session = self._create_session()
        self.bypass_system = UnifiedBypassSystem(config)
        self.evidence = []
        self.request_history = []
        self.protection_cache = {}
        self.successful_bypasses = {}
        self.browser_pool = []
        
        # Initialize browser if available
        if PLAYWRIGHT_AVAILABLE:
            self.playwright = None
            self.browser = None
            asyncio.create_task(self._init_browser())
    
    def _create_session(self) -> requests.Session:
        """Create session with retry strategy"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': self.config.get('user_agent', 
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    async def _init_browser(self):
        """Initialize Playwright browser"""
        if PLAYWRIGHT_AVAILABLE:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
    
    async def send_payload_with_bypass(self, target: str, payload: str, 
                                      method: str = "GET", param: Optional[str] = None,
                                      **kwargs) -> Dict[str, Any]:
        """
        Send payload with automatic WAF detection and bypass
        
        This is the main entry point that integrates bypass_system
        """
        context = RequestContext(
            url=target,
            method=method,
            params={param: payload} if param and method == "GET" else {},
            data={param: payload} if param and method == "POST" else payload,
            **kwargs
        )
        
        # Check protection cache
        protection_key = urlparse(target).netloc
        if protection_key not in self.protection_cache:
            # Detect protections
            logger.info(f"Detecting protections for {protection_key}")
            protections = self.bypass_system.detect_protections(target)
            self.protection_cache[protection_key] = protections
            
            # Update context with detected protections
            for p in protections['protections']:
                if p['detected']:
                    context.detected_protections.append(ProtectionType(p['type']))
        else:
            protections = self.protection_cache[protection_key]
        
        # Try direct request first
        result = await self._execute_request(context)
        
        # If blocked, attempt bypass
        if self._is_blocked(result) and context.bypass_attempts < context.max_bypass_attempts:
            logger.info(f"Request blocked, attempting bypass (protections: {context.detected_protections})")
            result = await self._attempt_bypass(context, payload, param)
        
        # If still blocked and JavaScript rendering might help
        if self._is_blocked(result) and self._needs_javascript(result):
            logger.info("Attempting browser-based bypass")
            result = await self._browser_bypass(context, payload)
        
        return result
    
    async def _execute_request(self, context: RequestContext) -> Dict[str, Any]:
        """Execute HTTP request with context"""
        start_time = time.time()
        
        try:
            # Prepare request parameters
            kwargs = {
                'timeout': context.timeout,
                'allow_redirects': context.allow_redirects,
                'headers': context.headers,
                'cookies': context.cookies
            }
            
            if context.method.upper() == "GET":
                kwargs['params'] = context.params
                response = self.session.get(context.url, **kwargs)
            elif context.method.upper() == "POST":
                if context.json_data:
                    kwargs['json'] = context.json_data
                else:
                    kwargs['data'] = context.data
                response = self.session.post(context.url, **kwargs)
            else:
                kwargs['data'] = context.data
                response = self.session.request(context.method, context.url, **kwargs)
            
            # Analyze response
            analysis = self._analyze_response(response, str(context.data or context.params))
            
            # Collect evidence
            evidence = self._create_evidence(context, response, analysis, time.time() - start_time)
            self.evidence.append(evidence)
            
            return {
                'success': not self._is_blocked_response(response),
                'evidence_id': evidence.id,
                'status_code': response.status_code,
                'response': response.text,
                'headers': dict(response.headers),
                'analysis': analysis,
                'response_time': time.time() - start_time,
                'raw_response': response
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'evidence_id': None
            }
    
    async def _attempt_bypass(self, context: RequestContext, payload: str, 
                            param: Optional[str]) -> Dict[str, Any]:
        """Attempt to bypass detected protections"""
        
        # Get bypass recommendations
        base_request = {
            'method': context.method,
            'path': urlparse(context.url).path,
            'headers': context.headers,
            'params': context.params,
            'body': context.data
        }
        
        # Generate bypass payloads
        bypasses = self.bypass_system.generate_bypasses(
            target=context.url,
            path=urlparse(context.url).path,
            method=context.method,
            params=context.params
        )
        
        # Try bypasses in order of likelihood
        for bypass in bypasses[:context.max_bypass_attempts]:
            context.bypass_attempts += 1
            
            # Apply bypass technique
            if bypass.get('technique', '').startswith('header_'):
                # Header-based bypass
                context.headers.update(bypass.get('headers', {}))
            elif bypass.get('technique', '').startswith('encoding_'):
                # Encoding-based bypass
                if param:
                    context.params[param] = bypass.get('modified_payload', payload)
            elif bypass.get('technique', '').startswith('path_'):
                # Path-based bypass
                parsed = urlparse(context.url)
                context.url = f"{parsed.scheme}://{parsed.netloc}{bypass.get('path', parsed.path)}"
            
            # Add identity rotation for bot detection
            if ProtectionType.BOT_DETECTION in context.detected_protections:
                identity = self.bypass_system.rotate_identity()
                context.headers.update(identity.get('headers', {}))
                context.cookies.update(identity.get('cookies', {}))
            
            # Execute request with bypass
            result = await self._execute_request(context)
            
            if not self._is_blocked(result):
                logger.info(f"Bypass successful: {bypass.get('technique')}")
                
                # Cache successful bypass
                protection_key = urlparse(context.url).netloc
                self.successful_bypasses[protection_key] = bypass.get('technique')
                
                # Update evidence with bypass info
                if result.get('evidence_id'):
                    for evidence in self.evidence:
                        if evidence.id == result['evidence_id']:
                            evidence.bypass_used = bypass.get('technique')
                            evidence.protection_bypassed = str(context.detected_protections)
                            break
                
                return result
            
            # Add delay to avoid rate limiting
            await asyncio.sleep(random.uniform(1, 3))
        
        return result
    
    async def _browser_bypass(self, context: RequestContext, payload: str) -> Dict[str, Any]:
        """Use browser automation for JavaScript-heavy sites"""
        if not PLAYWRIGHT_AVAILABLE or not self.browser:
            return {'success': False, 'error': 'Browser automation not available'}
        
        start_time = time.time()
        
        try:
            # Create new browser context
            browser_context = await self.browser.new_context(
                user_agent=context.headers.get('User-Agent'),
                ignore_https_errors=True,
                java_script_enabled=True
            )
            
            # Create page
            page = await browser_context.new_page()
            
            # Set cookies
            if context.cookies:
                await browser_context.add_cookies([
                    {'name': k, 'value': v, 'domain': urlparse(context.url).netloc, 'path': '/'}
                    for k, v in context.cookies.items()
                ])
            
            # Navigate to page
            await page.goto(context.url, wait_until='networkidle')
            
            # Wait for any challenges to resolve
            await asyncio.sleep(3)
            
            # Execute payload in browser context
            if context.method == "GET" and context.params:
                # Modify URL with parameters
                url_with_params = f"{context.url}?{urlencode(context.params)}"
                await page.goto(url_with_params, wait_until='networkidle')
            elif context.method == "POST":
                # Find and submit form
                await self._submit_form_with_payload(page, payload)
            
            # Get page content
            content = await page.content()
            
            # Take screenshot for evidence
            screenshot = await page.screenshot()
            
            # Get console logs
            console_logs = []
            page.on('console', lambda msg: console_logs.append(msg.text))
            
            # Extract cookies
            cookies = await browser_context.cookies()
            
            # Create browser evidence
            browser_evidence = {
                'screenshot': screenshot,
                'console_logs': console_logs,
                'cookies': cookies,
                'url': page.url,
                'title': await page.title()
            }
            
            # Close context
            await browser_context.close()
            
            # Analyze content
            analysis = self._analyze_browser_response(content, payload)
            
            # Create evidence
            evidence = EnhancedEvidence(
                id=hashlib.md5(f"{context.url}{payload}{time.time()}".encode()).hexdigest()[:8],
                timestamp=time.time(),
                request={'url': context.url, 'method': 'BROWSER', 'payload': payload},
                response={'content': content[:5000]},
                analysis=analysis,
                javascript_rendered=True,
                browser_evidence=browser_evidence
            )
            
            self.evidence.append(evidence)
            
            return {
                'success': True,
                'evidence_id': evidence.id,
                'response': content,
                'analysis': analysis,
                'response_time': time.time() - start_time,
                'javascript_rendered': True,
                'browser_evidence': browser_evidence
            }
            
        except Exception as e:
            logger.error(f"Browser bypass failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'javascript_rendered': True
            }
    
    async def _submit_form_with_payload(self, page, payload: str):
        """Submit form with payload in browser"""
        # Find first form
        forms = await page.query_selector_all('form')
        if not forms:
            # Try to find input fields
            inputs = await page.query_selector_all('input[type="text"], textarea')
            if inputs:
                await inputs[0].fill(payload)
                # Try to submit
                await page.keyboard.press('Enter')
        else:
            # Fill first form
            form = forms[0]
            inputs = await form.query_selector_all('input[type="text"], textarea')
            if inputs:
                await inputs[0].fill(payload)
            
            # Submit form
            submit_button = await form.query_selector('button[type="submit"], input[type="submit"]')
            if submit_button:
                await submit_button.click()
            else:
                await form.evaluate('form => form.submit()')
        
        # Wait for navigation
        await page.wait_for_load_state('networkidle')
    
    def _is_blocked(self, result: Dict) -> bool:
        """Check if request was blocked"""
        if not result.get('success'):
            return True
        
        status_code = result.get('status_code', 0)
        if status_code in [403, 406, 419, 429, 503]:
            return True
        
        response_text = result.get('response', '').lower()
        blocked_indicators = [
            'access denied', 'forbidden', 'blocked', 
            'security check', 'cloudflare', 'challenge',
            'captcha', 'rate limit', 'too many requests'
        ]
        
        return any(indicator in response_text for indicator in blocked_indicators)
    
    def _is_blocked_response(self, response: requests.Response) -> bool:
        """Check if response indicates blocking"""
        if response.status_code in [403, 406, 419, 429, 503]:
            return True
        
        response_text = response.text.lower() if response.text else ""
        blocked_indicators = [
            'access denied', 'forbidden', 'blocked',
            'security check', 'captcha', 'challenge'
        ]
        
        return any(indicator in response_text for indicator in blocked_indicators)
    
    def _needs_javascript(self, result: Dict) -> bool:
        """Check if JavaScript rendering might help"""
        response_text = result.get('response', '').lower()
        
        js_indicators = [
            'javascript', 'please enable', 'noscript',
            'challenge-platform', 'cf-challenge', 'ddos-guard'
        ]
        
        return any(indicator in response_text for indicator in js_indicators)
    
    def _analyze_response(self, response: requests.Response, payload: str) -> Dict[str, Any]:
        """Enhanced response analysis"""
        vulnerable = False
        confidence = 0.0
        indicators = []
        
        # Check for payload reflection
        if payload in response.text:
            indicators.append('payload_reflected')
            confidence += 0.3
        
        # Check for SQL errors
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
            'SQLite', 'Microsoft SQL', 'Incorrect syntax',
            'Unknown column', 'Table .* doesn\'t exist'
        ]
        for error in sql_errors:
            if error.lower() in response.text.lower():
                indicators.append(f'sql_error:{error}')
                vulnerable = True
                confidence += 0.5
                break
        
        # Check for XSS indicators
        xss_indicators = ['<script>alert', 'onerror=', 'onclick=']
        for xss in xss_indicators:
            if xss in response.text:
                indicators.append(f'xss:{xss}')
                vulnerable = True
                confidence += 0.4
                break
        
        # Check for command injection
        cmd_indicators = ['uid=', 'gid=', 'groups=', '/bin/', '/etc/passwd']
        for cmd in cmd_indicators:
            if cmd in response.text:
                indicators.append(f'cmd_injection:{cmd}')
                vulnerable = True
                confidence += 0.6
                break
        
        # Time-based detection
        if response.elapsed.total_seconds() > 5:
            indicators.append('time_delay')
            confidence += 0.2
        
        # Status code analysis
        if response.status_code == 500:
            indicators.append('server_error')
            confidence += 0.1
        elif response.status_code == 200 and vulnerable:
            confidence += 0.1
        
        # WAF detection indicators
        waf_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai', 'akamai-cache'],
            'aws_waf': ['x-amzn-requestid', 'x-amzn-trace-id'],
            'modsecurity': ['mod_security', '406 not acceptable']
        }
        
        detected_waf = None
        for waf, signs in waf_indicators.items():
            for sign in signs:
                if sign.lower() in str(response.headers).lower() or sign.lower() in response.text.lower():
                    detected_waf = waf
                    indicators.append(f'waf_detected:{waf}')
                    break
        
        confidence = min(confidence, 1.0)
        
        return {
            'vulnerable': vulnerable,
            'confidence': confidence,
            'indicators': indicators,
            'content_length': len(response.text),
            'response_time': response.elapsed.total_seconds(),
            'detected_waf': detected_waf
        }
    
    def _analyze_browser_response(self, content: str, payload: str) -> Dict[str, Any]:
        """Analyze browser-rendered content"""
        analysis = {
            'vulnerable': False,
            'confidence': 0.0,
            'indicators': [],
            'javascript_executed': True
        }
        
        # Check for payload execution
        if payload in content:
            analysis['indicators'].append('payload_in_dom')
            analysis['confidence'] += 0.3
        
        # Check for XSS execution indicators
        xss_success = ['XSS', 'alert', 'prompt', 'confirm']
        for indicator in xss_success:
            if f'>{indicator}<' in content or f'"{indicator}"' in content:
                analysis['vulnerable'] = True
                analysis['confidence'] += 0.5
                analysis['indicators'].append(f'xss_executed:{indicator}')
        
        return analysis
    
    def _create_evidence(self, context: RequestContext, response: requests.Response,
                        analysis: Dict, response_time: float) -> EnhancedEvidence:
        """Create enhanced evidence object"""
        evidence_id = hashlib.md5(
            f"{context.url}{context.data or context.params}{time.time()}".encode()
        ).hexdigest()[:8]
        
        return EnhancedEvidence(
            id=evidence_id,
            timestamp=time.time(),
            request={
                'method': context.method,
                'url': context.url,
                'headers': dict(context.headers),
                'params': context.params,
                'data': str(context.data) if context.data else None
            },
            response={
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:5000],
                'time': response_time
            },
            analysis=analysis,
            bypass_used=self.successful_bypasses.get(urlparse(context.url).netloc),
            protection_bypassed=str(context.detected_protections) if context.detected_protections else None
        )
    
    def get_evidence(self, evidence_id: str) -> Optional[EnhancedEvidence]:
        """Retrieve specific evidence by ID"""
        for ev in self.evidence:
            if ev.id == evidence_id:
                return ev
        return None
    
    def get_all_evidence(self) -> List[EnhancedEvidence]:
        """Get all collected evidence"""
        return self.evidence
    
    def get_bypass_statistics(self) -> Dict[str, Any]:
        """Get statistics about bypass attempts"""
        stats = {
            'total_requests': len(self.evidence),
            'bypasses_used': len([e for e in self.evidence if e.bypass_used]),
            'protections_detected': {},
            'successful_techniques': {},
            'javascript_rendered': len([e for e in self.evidence if e.javascript_rendered])
        }
        
        # Count protection types
        for evidence in self.evidence:
            if evidence.protection_bypassed:
                for protection in evidence.protection_bypassed:
                    stats['protections_detected'][protection] = stats['protections_detected'].get(protection, 0) + 1
        
        # Count successful techniques
        for evidence in self.evidence:
            if evidence.bypass_used:
                technique = evidence.bypass_used
                stats['successful_techniques'][technique] = stats['successful_techniques'].get(technique, 0) + 1
        
        return stats
    
    async def cleanup(self):
        """Cleanup resources"""
        if PLAYWRIGHT_AVAILABLE and self.browser:
            await self.browser.close()
        if PLAYWRIGHT_AVAILABLE and self.playwright:
            await self.playwright.stop()


# Create singleton instance
waf_aware_engine = WAFAwareHTTPEngine()

# Export main function for backward compatibility
async def send_payload(target: str, payload: str, method: str = "GET", 
                       param: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Main entry point for sending payloads with WAF bypass"""
    return await waf_aware_engine.send_payload_with_bypass(
        target, payload, method, param, **kwargs
    )
