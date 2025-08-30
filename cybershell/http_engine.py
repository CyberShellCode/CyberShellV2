"""
Real HTTP Exploitation Engine
Replaces simulated responses with actual HTTP requests
"""

import requests
import time
import json
import hashlib
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urlencode, parse_qs
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging

logger = logging.getLogger(__name__)

class HTTPEngine:
    """Real HTTP request engine with evidence collection"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.session = self._create_session()
        self.evidence = []
        self.request_history = []
        
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
            'User-Agent': self.config.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
        })
        
        return session
    
    def send_payload(self, target: str, payload: str, method: str = "GET", 
                     param: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Send actual payload and analyze response
        
        Returns:
            Dict with success, evidence, response details
        """
        start_time = time.time()
        
        try:
            # Prepare request
            if method.upper() == "GET":
                if param:
                    parsed = urlparse(target)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                response = self.session.get(target, timeout=10, **kwargs)
                
            elif method.upper() == "POST":
                data = {param: payload} if param else payload
                response = self.session.post(target, data=data, timeout=10, **kwargs)
                
            else:
                response = self.session.request(method, target, data=payload, timeout=10, **kwargs)
            
            # Analyze response
            analysis = self._analyze_response(response, payload)
            
            # Collect evidence
            evidence_id = hashlib.md5(f"{target}{payload}{time.time()}".encode()).hexdigest()[:8]
            
            evidence = {
                'id': evidence_id,
                'timestamp': time.time(),
                'request': {
                    'method': method,
                    'url': target,
                    'payload': payload,
                    'param': param,
                    'headers': dict(self.session.headers)
                },
                'response': {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text[:5000],  # Limit body size
                    'time': time.time() - start_time
                },
                'analysis': analysis
            }
            
            self.evidence.append(evidence)
            self.request_history.append(evidence_id)
            
            return {
                'success': analysis['vulnerable'],
                'evidence_id': evidence_id,
                'status_code': response.status_code,
                'response_time': time.time() - start_time,
                'analysis': analysis,
                'raw_response': response
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'evidence_id': None
            }
    
    def _analyze_response(self, response: requests.Response, payload: str) -> Dict[str, Any]:
        """Analyze response for vulnerability indicators"""
        
        vulnerable = False
        confidence = 0.0
        indicators = []
        
        # Check for payload reflection
        if payload in response.text:
            indicators.append('payload_reflected')
            confidence += 0.3
            
        # Check for error messages (SQLi)
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
            'SQLite', 'Microsoft SQL', 'Incorrect syntax'
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
        
        confidence = min(confidence, 1.0)
        
        return {
            'vulnerable': vulnerable,
            'confidence': confidence,
            'indicators': indicators,
            'content_length': len(response.text),
            'response_time': response.elapsed.total_seconds()
        }
    
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


# Patch existing plugins to use real HTTP
def patch_plugin_with_http(plugin_class):
    """Decorator to add real HTTP capabilities to existing plugins"""
    
    original_run = plugin_class.run
    
    def new_run(self, **kwargs):
        # Check if we should use real HTTP
        if kwargs.get('use_real_http', True):
            
            # Initialize HTTP engine if not exists
            if not hasattr(self, 'http_engine'):
                self.http_engine = HTTPEngine()
            
            target = kwargs.get('target', '')
            payload = kwargs.get('payload', '')
            
            # Send real request
            result = self.http_engine.send_payload(
                target=target,
                payload=payload,
                method=kwargs.get('method', 'GET'),
                param=kwargs.get('param')
            )
            
            if result['success']:
                # Return real result
                from cybershell.plugin_runtime import PluginResult
                return PluginResult(
                    name=self.name,
                    success=True,
                    details={
                        'vulnerable': True,
                        'evidence_id': result['evidence_id'],
                        'confidence': result['analysis']['confidence'],
                        'indicators': result['analysis']['indicators'],
                        'response_time': result['response_time']
                    },
                    evidence_score=result['analysis']['confidence']
                )
        
        # Fallback to original implementation
        return original_run(self, **kwargs)
    
    plugin_class.run = new_run
    return plugin_class
