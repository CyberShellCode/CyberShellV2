"""
Utility classes and functions for CyberShell
Consolidates simple dataclasses and helper functions
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# ========== Signal Events (used by HITL/ML feedback) ==========

@dataclass
class SignalEvent:
    """
    Event signals from exploitation attempts
    Used by ML mapper and HITL feedback systems
    """
    status_code: int = 0
    length_delta: float = 0.0
    time_delta_ms: float = 0.0
    error_tokens: List[str] = field(default_factory=list)
    reflections: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    tokens_seen: List[str] = field(default_factory=list)
    url_path: str = ''
    dom_snippets: List[str] = field(default_factory=list)
    notes: str = ''
    
    def as_text(self) -> str:
        """Convert signal to text representation for ML processing"""
        pieces = [
            f"status:{self.status_code}",
            f"len_delta:{self.length_delta:.3f}",
            f"time_delta_ms:{self.time_delta_ms:.1f}",
            "errors:" + " | ".join(self.error_tokens) if self.error_tokens else "errors:none",
            "reflect:" + " | ".join(self.reflections) if self.reflections else "reflect:none",
            "headers:" + " | ".join([f"{k}:{v}" for k,v in self.headers.items()]) if self.headers else "headers:none",
            "cookies:" + " | ".join(self.cookies.keys()) if self.cookies else "cookies:none",
            "tokens:" + " | ".join(self.tokens_seen) if self.tokens_seen else "tokens:none",
            "path:" + self.url_path if self.url_path else "path:none",
            "dom:" + " | ".join(self.dom_snippets) if self.dom_snippets else "dom:none",
            "notes:" + self.notes if self.notes else "notes:none",
        ]
        return "\n".join(pieces)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'status_code': self.status_code,
            'length_delta': self.length_delta,
            'time_delta_ms': self.time_delta_ms,
            'error_tokens': self.error_tokens,
            'reflections': self.reflections,
            'headers': self.headers,
            'cookies': self.cookies,
            'tokens_seen': self.tokens_seen,
            'url_path': self.url_path,
            'dom_snippets': self.dom_snippets,
            'notes': self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignalEvent':
        """Create from dictionary"""
        return cls(**data)


# ========== Strategy/Planning Schemas ==========

@dataclass
class Tactic:
    """
    Represents an exploitation tactic/technique
    """
    name: str
    description: str
    conditions: Dict[str, Any]
    steps: List[str]
    priority: int = 0
    success_rate: float = 0.0
    
    def matches_conditions(self, context: Dict[str, Any]) -> bool:
        """Check if tactic conditions match current context"""
        for key, expected in self.conditions.items():
            if key not in context:
                return False
            if isinstance(expected, list):
                if context[key] not in expected:
                    return False
            elif context[key] != expected:
                return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'conditions': self.conditions,
            'steps': self.steps,
            'priority': self.priority,
            'success_rate': self.success_rate
        }


@dataclass
class Evidence:
    """
    Evidence collected during exploitation
    """
    kind: str  # Type of evidence (e.g., 'xss', 'sqli', 'ssrf')
    summary: str
    artifacts: Dict[str, str]  # artifact_name -> artifact_content/path
    confidence: float = 0.0  # 0.0 to 1.0
    timestamp: Optional[str] = None
    target: Optional[str] = None
    
    def is_high_confidence(self) -> bool:
        """Check if evidence is high confidence"""
        return self.confidence >= 0.8
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'kind': self.kind,
            'summary': self.summary,
            'artifacts': self.artifacts,
            'confidence': self.confidence,
            'timestamp': self.timestamp,
            'target': self.target
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Evidence':
        """Create from dictionary"""
        return cls(**data)


# ========== Exploitation Result Schema ==========

@dataclass
class ExploitResult:
    """
    Result from an exploitation attempt
    """
    success: bool
    vulnerability_type: str
    target: str
    evidence: Optional[Evidence] = None
    error: Optional[str] = None
    payload_used: Optional[str] = None
    response_time: float = 0.0
    status_code: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'vulnerability_type': self.vulnerability_type,
            'target': self.target,
            'evidence': self.evidence.to_dict() if self.evidence else None,
            'error': self.error,
            'payload_used': self.payload_used,
            'response_time': self.response_time,
            'status_code': self.status_code
        }


# ========== Target/Fingerprint Schema ==========

@dataclass
class TargetFingerprint:
    """
    Target fingerprint information
    """
    url: str
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    server: Optional[str] = None
    waf: Optional[str] = None
    cms: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
    
    def has_waf(self) -> bool:
        """Check if WAF is detected"""
        return self.waf is not None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'url': self.url,
            'technologies': self.technologies,
            'headers': self.headers,
            'server': self.server,
            'waf': self.waf,
            'cms': self.cms,
            'language': self.language,
            'framework': self.framework,
            'vulnerabilities': self.vulnerabilities
        }


# ========== Validation Schema ==========

@dataclass 
class ValidationResult:
    """
    Result from vulnerability validation
    """
    is_valid: bool
    confidence: float
    evidence: Optional[Evidence] = None
    false_positive_indicators: List[str] = field(default_factory=list)
    validation_method: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'is_valid': self.is_valid,
            'confidence': self.confidence,
            'evidence': self.evidence.to_dict() if self.evidence else None,
            'false_positive_indicators': self.false_positive_indicators,
            'validation_method': self.validation_method
        }


# ========== Helper Functions ==========

def parse_scope(scope_string: str) -> List[str]:
    """
    Parse scope string into list of domains/URLs
    """
    if not scope_string:
        return []
    
    # Split by common delimiters
    import re
    parts = re.split(r'[,;\s]+', scope_string)
    
    # Clean and validate each part
    scope = []
    for part in parts:
        part = part.strip()
        if part and (part.startswith('http') or '.' in part):
            scope.append(part)
    
    return scope


def is_in_scope(url: str, scope: List[str]) -> bool:
    """
    Check if URL is in scope
    """
    if not scope:
        return False
    
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.path
    
    for scope_item in scope:
        # Handle wildcards
        if scope_item.startswith('*.'):
            domain = scope_item[2:]
            if hostname.endswith(domain):
                return True
        # Exact match
        elif hostname == scope_item or url.startswith(scope_item):
            return True
    
    return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system usage
    """
    import re
    # Remove/replace unsafe characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    return safe[:200]


def generate_report_filename(target: str, vuln_type: str) -> str:
    """
    Generate a report filename
    """
    from datetime import datetime
    from urllib.parse import urlparse
    
    parsed = urlparse(target)
    hostname = parsed.hostname or 'unknown'
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{hostname}_{vuln_type}_{timestamp}.md"
    
    return sanitize_filename(filename)


def calculate_severity(evidence: Evidence) -> str:
    """
    Calculate severity based on evidence
    """
    if not evidence:
        return "info"
    
    # High severity indicators
    high_severity_types = ['rce', 'sqli', 'xxe', 'ssrf', 'authentication_bypass']
    if evidence.kind.lower() in high_severity_types:
        return "critical" if evidence.confidence > 0.9 else "high"
    
    # Medium severity
    medium_severity_types = ['xss', 'csrf', 'idor', 'open_redirect']
    if evidence.kind.lower() in medium_severity_types:
        return "high" if evidence.confidence > 0.9 else "medium"
    
    # Low severity
    return "medium" if evidence.confidence > 0.8 else "low"


def format_evidence_summary(evidence: Evidence) -> str:
    """
    Format evidence into a human-readable summary
    """
    lines = [
        f"## {evidence.kind.upper()} Vulnerability",
        f"**Confidence:** {evidence.confidence:.1%}",
        f"**Summary:** {evidence.summary}",
    ]
    
    if evidence.target:
        lines.append(f"**Target:** {evidence.target}")
    
    if evidence.artifacts:
        lines.append("\n### Artifacts")
        for name, content in evidence.artifacts.items():
            lines.append(f"- **{name}:** {content[:200]}..." if len(content) > 200 else f"- **{name}:** {content}")
    
    return "\n".join(lines)
