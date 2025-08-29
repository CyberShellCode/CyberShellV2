"""
Unified Planning and Strategy System for CyberShellV2
Combines simple planning, multiple strategies, outcome-directed search, and autonomous orchestration
"""

import asyncio
import json
import time
import heapq
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from abc import ABC, abstractmethod
from collections import deque, defaultdict
from pathlib import Path
import networkx as nx


# ============================================================================
# COMMON DATA STRUCTURES
# ============================================================================

@dataclass
class PlanStep:
    """Unified plan step structure"""
    plugin: str
    rationale: str
    params: Dict[str, Any]
    priority: Optional[float] = None
    expected_reward: Optional[float] = None
    cost: Optional[float] = None


class ExploitationPhase(Enum):
    """Phases of exploitation"""
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    TESTING = "testing"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    ESCALATION = "escalation"
    PIVOTING = "pivoting"
    PERSISTENCE = "persistence"
    CHAINING = "chaining"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"


class DecisionPriority(Enum):
    """Priority levels for decisions"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    OPTIONAL = 5


# ============================================================================
# SIMPLE PLANNER (from planner.py)
# ============================================================================

class SimplePlanner:
    """Simple planner that can be guided by mapper and LLM"""
    
    def __init__(self, kb=None, mapper=None, llm=None):
        self.kb = kb
        self.mapper = mapper
        self.llm = llm
    
    def make_plan(self, target: str, recon: Dict[str, Any], 
                  signals_text: Optional[str] = None) -> List[PlanStep]:
        """Create simple exploitation plan"""
        steps: List[PlanStep] = []
        
        # Always start with safe discovery
        steps.append(PlanStep(
            plugin='HttpFingerprintPlugin',
            rationale='Identify headers/banners in lab',
            params={'target': target}
        ))
        steps.append(PlanStep(
            plugin='FormDiscoveryPlugin',
            rationale='Map basic forms/inputs in lab',
            params={'target': target}
        ))
        
        # Mapper-guided tactics
        if self.mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = self.mapper.map(evt)
            for fam, score in m.top_families[:3]:
                steps.append(PlanStep(
                    plugin='HeuristicAnalyzerPlugin',
                    rationale=f"Mapper suggests family={fam} score={score:.2f}",
                    params={'target': target, 'hint': fam}
                ))
        
        # LLM suggestions
        if self.llm:
            suggestion = self.llm.suggest_steps(target=target, recon=recon)
            for s in suggestion:
                steps.append(PlanStep(
                    plugin=s['plugin'],
                    rationale=s['why'],
                    params={'target': target, **s.get('params', {})}
                ))
        
        return steps


# ============================================================================
# STRATEGY-BASED PLANNING (from strategies.py)
# ============================================================================

class BasePlannerStrategy(ABC):
    """Base class for planning strategies"""
    name: str = "base"
    
    @abstractmethod
    def plan(self, target: str, recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None, llm: Any = None, kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None, llm_step_budget: int = 3) -> List[PlanStep]:
        """Generate exploitation plan"""
        pass
    
    def _add_exploitation_steps(self, steps: List[PlanStep], target: str,
                               vuln_class: str, confidence: float = 0.7):
        """Add exploitation steps for a vulnerability class"""
        exploit_map = {
            'sqli': [
                ('SQLiTestPlugin', f'Test for SQL injection (confidence: {confidence:.2f})'),
                ('SQLiExploitPlugin', 'Exploit SQL injection for data extraction')
            ],
            'xss': [
                ('XSSTestPlugin', f'Test for XSS vulnerabilities (confidence: {confidence:.2f})'),
                ('XSSExploitPlugin', 'Exploit XSS for session hijacking')
            ],
            'rce': [
                ('RCETestPlugin', f'Test for remote code execution (confidence: {confidence:.2f})'),
                ('RCEExploitPlugin', 'Exploit RCE for system access')
            ],
            'idor': [
                ('IDORTestPlugin', f'Test for IDOR vulnerabilities (confidence: {confidence:.2f})'),
                ('IDORExploitPlugin', 'Exploit IDOR for data access')
            ],
            'ssrf': [
                ('SSRFTestPlugin', f'Test for SSRF (confidence: {confidence:.2f})'),
                ('SSRFExploitPlugin', 'Exploit SSRF for internal access')
            ],
            'ssti': [
                ('SSTITestPlugin', f'Test for template injection (confidence: {confidence:.2f})'),
                ('SSTIExploitPlugin', 'Exploit SSTI for code execution')
            ],
            'auth': [
                ('AuthBypassTestPlugin', f'Test authentication bypass (confidence: {confidence:.2f})'),
                ('AuthBypassExploitPlugin', 'Exploit auth bypass for admin access')
            ]
        }
        
        if vuln_class in exploit_map:
            for plugin, rationale in exploit_map[vuln_class]:
                steps.append(PlanStep(
                    plugin=plugin,
                    rationale=rationale,
                    params={'target': target, 'confidence': confidence}
                ))


class DepthFirstPlanner(BasePlannerStrategy):
    """Depth-first exploitation strategy"""
    name = "depth_first"
    
    def plan(self, target: str, recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None, llm: Any = None, kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None, llm_step_budget: int = 3) -> List[PlanStep]:
        
        steps: List[PlanStep] = []
        
        # Phase 1: Initial recon
        steps.append(PlanStep(
            plugin='HttpFingerprintPlugin',
            rationale='Identify headers/banners for depth analysis',
            params={'target': target}
        ))
        steps.append(PlanStep(
            plugin='FormDiscoveryPlugin',
            rationale='Map forms/inputs for deep testing',
            params={'target': target}
        ))
        
        # Phase 2: Technology-specific deep testing
        if recon:
            tech_stack = recon.get('technologies', [])
            
            if any(db in str(tech_stack).lower() for db in ['mysql', 'postgres', 'mssql']):
                self._add_exploitation_steps(steps, target, 'sqli', confidence=0.9)
                steps.append(PlanStep(
                    plugin='AdvancedSQLiPlugin',
                    rationale='Deep SQLi exploitation with advanced techniques',
                    params={'target': target, 'technique': 'union_based', 'extract_data': True}
                ))
            
            if recon.get('forms'):
                steps.append(PlanStep(
                    plugin='BusinessLogicPlugin',
                    rationale='Deep business logic testing on forms',
                    params={'target': target, 'forms': recon['forms']}
                ))
                self._add_exploitation_steps(steps, target, 'xss', confidence=0.8)
        
        # Phase 3: Mapper-informed deep dive
        if mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)
            
            for fam, score in m.top_families[:2]:
                steps.append(PlanStep(
                    plugin='HeuristicAnalyzerPlugin',
                    rationale=f'Deep analysis for {fam} (mapper score: {score:.2f})',
                    params={'target': target, 'hint': fam, 'depth': 'deep'}
                ))
                
                if score > 0.7:
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        self._add_exploitation_steps(steps, target, vuln_class, score)
        
        # Phase 4: LLM-guided deep exploitation
        if llm and llm_step_budget > 0:
            try:
                suggestions = llm.suggest_steps(target=target, recon=recon or {})
                for s in suggestions[:llm_step_budget]:
                    steps.append(PlanStep(
                        plugin=s.get('plugin', 'HeuristicAnalyzerPlugin'),
                        rationale=s.get('why', 'LLM-suggested deep exploitation'),
                        params={'target': target, **s.get('params', {})}
                    ))
            except:
                pass
        
        # Phase 5: Chaining attempts
        steps.append(PlanStep(
            plugin='ExploitationChainPlugin',
            rationale='Attempt vulnerability chaining for maximum impact',
            params={'target': target, 'auto_detect': True}
        ))
        
        return steps
    
    def _map_family_to_class(self, family: str) -> Optional[str]:
        """Map vulnerability family to class"""
        family_lower = family.lower()
        
        if 'sql' in family_lower or 'injection' in family_lower:
            return 'sqli'
        elif 'xss' in family_lower or 'script' in family_lower:
            return 'xss'
        elif 'rce' in family_lower or 'command' in family_lower:
            return 'rce'
        elif 'idor' in family_lower or 'authorization' in family_lower:
            return 'idor'
        elif 'ssrf' in family_lower:
            return 'ssrf'
        elif 'ssti' in family_lower or 'template' in family_lower:
            return 'ssti'
        elif 'auth' in family_lower or 'jwt' in family_lower:
            return 'auth'
        
        return None


class BreadthFirstPlanner(BasePlannerStrategy):
    """Breadth-first exploitation strategy"""
    name = "breadth_first"
    
    def plan(self, target: str, recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None, llm: Any = None, kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None, llm_step_budget: int = 2) -> List[PlanStep]:
        
        steps: List[PlanStep] = []
        
        # Phase 1: Broad reconnaissance
        steps.extend([
            PlanStep('HttpFingerprintPlugin', 'Quick fingerprinting scan', {'target': target}),
            PlanStep('FormDiscoveryPlugin', 'Quick form discovery', {'target': target}),
            PlanStep('APIDiscoveryPlugin', 'API endpoint discovery', {'target': target})
        ])
        
        # Phase 2: Broad vulnerability testing
        test_plugins = [
            ('SQLiTestPlugin', 'Quick SQL injection test'),
            ('XSSTestPlugin', 'Quick XSS test'),
            ('IDORTestPlugin', 'Quick IDOR test'),
            ('SSRFTestPlugin', 'Quick SSRF test'),
            ('SSTITestPlugin', 'Quick SSTI test'),
            ('AuthBypassTestPlugin', 'Quick auth bypass test'),
            ('RCETestPlugin', 'Quick RCE test'),
            ('CSRFTestPlugin', 'Quick CSRF test')
        ]
        
        for plugin, rationale in test_plugins:
            steps.append(PlanStep(plugin, rationale, {'target': target, 'quick_scan': True}))
        
        # Phase 3: Mapper hint
        if mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)
            
            if m.top_families:
                fam, score = m.top_families[0]
                steps.append(PlanStep(
                    'HeuristicAnalyzerPlugin',
                    f'Quick test for {fam} (score: {score:.2f})',
                    {'target': target, 'hint': fam, 'quick': True}
                ))
        
        # Phase 4: Limited LLM suggestions
        if llm and llm_step_budget > 0:
            try:
                suggestions = llm.suggest_steps(target=target, recon=recon or {})
                if suggestions:
                    s = suggestions[0]
                    steps.append(PlanStep(
                        s.get('plugin', 'HeuristicAnalyzerPlugin'),
                        s.get('why', 'LLM breadth test'),
                        {'target': target, **s.get('params', {})}
                    ))
            except:
                pass
        
        return steps


class AggressivePlanner(BasePlannerStrategy):
    """Aggressive exploitation strategy"""
    name = "aggressive"
    
    def plan(self, target: str, recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None, llm: Any = None, kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None, llm_step_budget: int = 5) -> List[PlanStep]:
        
        steps: List[PlanStep] = []
        
        # Skip recon, go straight to exploitation
        
        # Phase 1: High-impact vulnerability exploitation
        critical_exploits = [
            ('RCEExploitPlugin', 'Immediate RCE exploitation attempt',
             {'establish_shell': True, 'vectors': ['command_injection', 'deserialization']}),
            ('SQLiExploitPlugin', 'Immediate SQLi data extraction',
             {'technique': 'union_based', 'extract_data': True, 'enumerate_db': True}),
            ('AuthBypassExploitPlugin', 'Immediate authentication bypass',
             {'escalate_privileges': True, 'methods': ['jwt_none', 'session_fixation']}),
            ('SSRFExploitPlugin', 'Immediate SSRF to cloud metadata',
             {'access_metadata': True, 'scan_internal': True}),
            ('SSTIExploitPlugin', 'Immediate template injection RCE',
             {'execute_commands': True, 'identify_engine': True})
        ]
        
        for plugin, rationale, params in critical_exploits:
            steps.append(PlanStep(plugin, rationale, {'target': target, **params}))
        
        # Phase 2: Business logic exploitation
        steps.extend([
            PlanStep('BusinessLogicPlugin',
                    'Race condition exploitation for financial impact',
                    {'target': target, 'test_race_conditions': True, 'iterations': 100}),
            PlanStep('IDORExploitPlugin',
                    'Mass IDOR data extraction',
                    {'target': target, 'extract_sensitive': True, 'enumerate_objects': True})
        ])
        
        # Phase 3: Vulnerability chaining
        steps.extend([
            PlanStep('ExploitationChainPlugin',
                    'Chain SQLi to RCE immediately',
                    {'target': target, 'chain_type': 'sqli_to_rce', 'aggressive': True}),
            PlanStep('ExploitationChainPlugin',
                    'Chain XSS to account takeover',
                    {'target': target, 'chain_type': 'xss_to_takeover', 'target_admin': True})
        ])
        
        # Phase 4: Mapper-guided aggressive exploitation
        if mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)
            
            for fam, score in m.top_families:
                if score > 0.5:
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        steps.append(PlanStep(
                            f'{vuln_class.upper()}ExploitPlugin',
                            f'Aggressive {fam} exploitation (confidence: {score:.2f})',
                            {'target': target, 'aggressive': True, 'extract_all': True}
                        ))
        
        return steps
    
    def _map_family_to_class(self, family: str) -> Optional[str]:
        """Map vulnerability family to class"""
        family_lower = family.lower()
        
        mapping = {
            'sqli': 'SQLi',
            'xss': 'XSS',
            'rce': 'RCE',
            'idor': 'IDOR',
            'ssrf': 'SSRF',
            'ssti': 'SSTI',
            'auth': 'AuthBypass'
        }
        
        for key, value in mapping.items():
            if key in family_lower:
                return value
        
        return None


class AdaptivePlanner(BasePlannerStrategy):
    """Adaptive planning strategy"""
    name = "adaptive"
    
    def plan(self, target: str, recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None, llm: Any = None, kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None, llm_step_budget: int = 4) -> List[PlanStep]:
        
        steps: List[PlanStep] = []
        
        # Analyze confidence level
        confidence_level = 0.0
        
        if mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)
            if m.top_families:
                confidence_level = m.top_families[0][1] if m.top_families else 0.0
        
        # Adapt strategy based on confidence
        if confidence_level < 0.3:
            # Low confidence - start with recon
            steps.extend([
                PlanStep('HttpFingerprintPlugin', 'Baseline fingerprint', {'target': target}),
                PlanStep('FormDiscoveryPlugin', 'Discover forms', {'target': target}),
                PlanStep('TechnologyStackPlugin', 'Identify technology stack', {'target': target})
            ])
        
        # Adaptive testing based on mapper confidence
        if mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)
            
            for fam, score in m.top_families[:5]:
                if score > 0.7:
                    # High confidence - go straight to exploitation
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        steps.append(PlanStep(
                            f'{vuln_class}ExploitPlugin',
                            f'High-confidence {fam} exploitation (score: {score:.2f})',
                            {'target': target, 'confidence': score}
                        ))
                elif score > 0.4:
                    # Medium confidence - test first
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        steps.append(PlanStep(
                            f'{vuln_class}TestPlugin',
                            f'Test for {fam} (score: {score:.2f})',
                            {'target': target, 'confidence': score}
                        ))
                else:
                    # Low confidence - just analyze
                    steps.append(PlanStep(
                        'HeuristicAnalyzerPlugin',
                        f'Analyze {fam} signals (score: {score:.2f})',
                        {'target': target, 'hint': fam}
                    ))
        
        # Add chaining if confidence is high
        if confidence_level > 0.6:
            steps.append(PlanStep(
                'ExploitationChainPlugin',
                'Attempt vulnerability chaining (high confidence)',
                {'target': target, 'auto_detect': True}
            ))
        
        return steps
    
    def _map_family_to_class(self, family: str) -> Optional[str]:
        """Map vulnerability family to class"""
        family_lower = family.lower()
        
        for vuln in ['sqli', 'xss', 'rce', 'idor', 'ssrf', 'ssti', 'auth', 'jwt', 'xxe']:
            if vuln in family_lower:
                return vuln.upper() if len(vuln) <= 4 else vuln.capitalize()
        
        return None


# ============================================================================
# OUTCOME-DIRECTED SEARCH (from ods.py)
# ============================================================================

@dataclass
class ODSConfig:
    """Configuration for Outcome-Directed Search"""
    window: int = 5
    patience_steps: int = 3
    stagnation_rounds: int = 2
    min_improvement: float = 0.05
    stop_threshold: float = 0.85
    max_iterations: int = 20
    
    # Phase thresholds
    testing_threshold: float = 0.3
    exploit_threshold: float = 0.5
    escalation_threshold: float = 0.7
    chaining_threshold: float = 0.8
    
    # Adaptive parameters
    exploration_rate: float = 0.2
    exploitation_rate: float = 0.8
    adapt_thresholds: bool = True


class EvidenceAggregator:
    """Aggregates and analyzes evidence scores"""
    
    def __init__(self, window_size: int = 5):
        self.window_size = window_size
        self.scores: List[float] = []
    
    def add(self, score: float):
        """Add evidence score"""
        self.scores.append(score)
    
    def get_ema(self) -> float:
        """Get exponential moving average"""
        if not self.scores:
            return 0.0
        
        alpha = 2 / (self.window_size + 1)
        ema = self.scores[0]
        for score in self.scores[1:]:
            ema = alpha * score + (1 - alpha) * ema
        return ema
    
    def get_sma(self) -> float:
        """Get simple moving average"""
        if not self.scores:
            return 0.0
        
        window = self.scores[-self.window_size:]
        return sum(window) / len(window)
    
    def get_max(self) -> float:
        """Get maximum score"""
        return max(self.scores) if self.scores else 0.0
    
    def get_trend(self) -> str:
        """Get trend direction"""
        if len(self.scores) < 2:
            return 'flat'
        
        recent = self.scores[-3:]
        if len(recent) < 3:
            return 'flat'
        
        if recent[-1] > recent[-2] > recent[-3]:
            return 'rising'
        elif recent[-1] < recent[-2] < recent[-3]:
            return 'declining'
        else:
            return 'flat'


class ExploitationState:
    """Tracks the current state of exploitation"""
    
    def __init__(self):
        self.phase = ExploitationPhase.DISCOVERY
        self.discovered_vulns: List[Dict[str, Any]] = []
        self.confirmed_vulns: List[Dict[str, Any]] = []
        self.exploited_vulns: List[Dict[str, Any]] = []
        self.chained_exploits: List[Dict[str, Any]] = []
        self.iteration = 0
        self.stagnation_count = 0
        self.last_improvement_iteration = 0
        self.strategy_performance: Dict[str, float] = {}
    
    def add_vulnerability(self, vuln_type: str, confidence: float, details: Dict):
        """Add a discovered vulnerability"""
        vuln = {
            'type': vuln_type,
            'confidence': confidence,
            'details': details,
            'iteration': self.iteration
        }
        
        if confidence > 0.7:
            self.confirmed_vulns.append(vuln)
        else:
            self.discovered_vulns.append(vuln)
    
    def mark_exploited(self, vuln_type: str, impact: float):
        """Mark vulnerability as exploited"""
        self.exploited_vulns.append({
            'type': vuln_type,
            'impact': impact,
            'iteration': self.iteration
        })
        
        self.stagnation_count = 0
        self.last_improvement_iteration = self.iteration
    
    def update_phase(self, new_phase: ExploitationPhase):
        """Update exploitation phase"""
        self.phase = new_phase
    
    def get_unexploited_vulns(self) -> List[Dict[str, Any]]:
        """Get confirmed but unexploited vulnerabilities"""
        exploited_types = {v['type'] for v in self.exploited_vulns}
        return [v for v in self.confirmed_vulns if v['type'] not in exploited_types]


class OutcomeDirectedSearch:
    """Manages adaptive exploitation through outcome-directed search"""
    
    def __init__(self, config: Optional[ODSConfig] = None):
        self.cfg = config or ODSConfig()
        self.state = ExploitationState()
        self.evidence_agg = EvidenceAggregator(window_size=self.cfg.window)
        self.strategy_weights = {
            'aggressive': 0.3,
            'targeted': 0.4,
            'chaining': 0.2,
            'exfiltration': 0.1
        }
    
    def should_pivot(self) -> bool:
        """Determine if strategy should pivot"""
        if self.state.stagnation_count >= self.cfg.patience_steps:
            return True
        
        if self.evidence_agg.get_trend() == 'declining':
            return True
        
        phase_duration = self.state.iteration - self.state.last_improvement_iteration
        if phase_duration > self.cfg.patience_steps * 2:
            return True
        
        return False
    
    def select_next_strategy(self) -> str:
        """Select next exploitation strategy"""
        current_evidence = self.evidence_agg.get_ema()
        
        if self.state.phase == ExploitationPhase.DISCOVERY:
            if current_evidence < self.cfg.testing_threshold:
                return 'broad_discovery'
            else:
                self.state.update_phase(ExploitationPhase.TESTING)
                return 'targeted_testing'
        
        elif self.state.phase == ExploitationPhase.TESTING:
            if current_evidence < self.cfg.exploit_threshold:
                return 'deep_testing'
            else:
                self.state.update_phase(ExploitationPhase.EXPLOITATION)
                return 'aggressive_exploitation'
        
        elif self.state.phase == ExploitationPhase.EXPLOITATION:
            if current_evidence < self.cfg.escalation_threshold:
                return 'exploit_confirmed'
            else:
                self.state.update_phase(ExploitationPhase.ESCALATION)
                return 'privilege_escalation'
        
        elif self.state.phase == ExploitationPhase.ESCALATION:
            if current_evidence < self.cfg.chaining_threshold:
                return 'lateral_movement'
            else:
                self.state.update_phase(ExploitationPhase.CHAINING)
                return 'chain_vulnerabilities'
        
        elif self.state.phase == ExploitationPhase.CHAINING:
            self.state.update_phase(ExploitationPhase.EXFILTRATION)
            return 'data_exfiltration'
        
        else:
            return 'persistence_and_cleanup'
    
    def generate_pivot_plan(self, target: str, current_evidence: float) -> List[PlanStep]:
        """Generate pivot plan when strategy is not working"""
        steps = []
        strategy = self.select_next_strategy()
        
        if strategy == 'broad_discovery':
            steps.extend([
                PlanStep("SQLiTestPlugin", "Broad SQL injection scan", {"target": target}),
                PlanStep("XSSTestPlugin", "Broad XSS scan", {"target": target}),
                PlanStep("IDORTestPlugin", "Broad IDOR scan", {"target": target}),
                PlanStep("SSRFTestPlugin", "Broad SSRF scan", {"target": target})
            ])
        
        elif strategy == 'targeted_testing':
            for vuln in self.state.discovered_vulns[:3]:
                steps.append(
                    PlanStep(f"{vuln['type']}ExploitPlugin",
                           f"Target {vuln['type']} exploitation",
                           {"target": target, "confidence": vuln['confidence']})
                )
        
        elif strategy == 'aggressive_exploitation':
            for vuln in self.state.confirmed_vulns:
                steps.append(
                    PlanStep(f"{vuln['type']}ExploitPlugin",
                           f"Aggressively exploit {vuln['type']}",
                           {"target": target, "aggressive": True, "extract_data": True})
                )
        
        elif strategy == 'privilege_escalation':
            steps.extend([
                PlanStep("AuthBypassExploitPlugin",
                       "Escalate to admin privileges",
                       {"target": target, "escalate_privileges": True}),
                PlanStep("IDORToPrivEscPlugin",
                       "IDOR-based privilege escalation",
                       {"target": target})
            ])
        
        elif strategy == 'chain_vulnerabilities':
            if len(self.state.exploited_vulns) >= 2:
                steps.extend([
                    PlanStep("SQLiToRCEChainPlugin",
                           "Chain SQLi to RCE",
                           {"target": target}),
                    PlanStep("XSSToAccountTakeoverPlugin",
                           "Chain XSS to account takeover",
                           {"target": target})
                ])
        
        elif strategy == 'data_exfiltration':
            steps.append(
                PlanStep("DataExfiltrationPlugin",
                       "Exfiltrate sensitive data for PoC",
                       {"target": target, "limit": 100})
            )
        
        elif strategy == 'persistence_and_cleanup':
            steps.append(
                PlanStep("ReportGenerationPlugin",
                       "Generate comprehensive exploit report",
                       {"target": target, "include_all": True})
            )
        
        return steps
    
    def should_attempt_chaining(self) -> bool:
        """Determine if vulnerability chaining should be attempted"""
        if len(self.state.exploited_vulns) < 2:
            return False
        
        if self.evidence_agg.get_ema() < self.cfg.chaining_threshold:
            return False
        
        vuln_types = {v['type'] for v in self.state.exploited_vulns}
        
        chainable_pairs = [
            {'sqli', 'rce'},
            {'xss', 'csrf'},
            {'idor', 'auth'},
            {'ssrf', 'rce'},
            {'xxe', 'ssrf'}
        ]
        
        return any(pair.issubset(vuln_types) for pair in chainable_pairs)
    
    def observe(self, evidence: float, results: List[Any]) -> Optional[PlanStep]:
        """Observe evidence and determine next action"""
        self.state.iteration += 1
        self.evidence_agg.add(evidence)
        
        if evidence > self.evidence_agg.get_sma():
            self.state.stagnation_count = 0
            self.state.last_improvement_iteration = self.state.iteration
        else:
            self.state.stagnation_count += 1
        
        if self.evidence_agg.get_max() >= self.cfg.stop_threshold:
            return None
        
        if self.should_pivot():
            pivot_plan = self.generate_pivot_plan("", evidence)
            if pivot_plan:
                return pivot_plan[0]
        
        return None


# ============================================================================
# AUTONOMOUS ORCHESTRATION (from autonomous_orchestration_engine.py)
# ============================================================================

@dataclass
class AutonomousGoal:
    """Represents an autonomous exploitation goal"""
    id: str
    description: str
    priority: DecisionPriority
    success_criteria: Dict[str, Any]
    constraints: Dict[str, Any]
    deadline: Optional[datetime]
    dependencies: List[str]
    reward: float


@dataclass
class DecisionNode:
    """Node in decision tree"""
    id: str
    state: ExploitationPhase
    action: str
    expected_reward: float
    cost: float
    probability_success: float
    children: List['DecisionNode'] = field(default_factory=list)
    parent: Optional['DecisionNode'] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class GoalManager:
    """Manages autonomous exploitation goals"""
    
    def create_goals_from_objectives(self, objectives: List[str],
                                    target: str, constraints: Dict) -> List[AutonomousGoal]:
        """Create goals from high-level objectives"""
        goals = []
        
        for i, objective in enumerate(objectives):
            if 'flag' in objective.lower() or 'ctf' in objective.lower():
                goal = AutonomousGoal(
                    id=f"goal_{i}_ctf",
                    description=f"Capture flag from {target}",
                    priority=DecisionPriority.CRITICAL,
                    success_criteria={'flag_captured': True},
                    constraints=constraints,
                    deadline=datetime.now() + timedelta(hours=2),
                    dependencies=[],
                    reward=1000
                )
            elif 'root' in objective.lower() or 'admin' in objective.lower():
                goal = AutonomousGoal(
                    id=f"goal_{i}_privesc",
                    description=f"Achieve root/admin access on {target}",
                    priority=DecisionPriority.HIGH,
                    success_criteria={'access_level': 'root'},
                    constraints=constraints,
                    deadline=None,
                    dependencies=[],
                    reward=800
                )
            elif 'data' in objective.lower() or 'exfil' in objective.lower():
                goal = AutonomousGoal(
                    id=f"goal_{i}_exfil",
                    description=f"Exfiltrate sensitive data from {target}",
                    priority=DecisionPriority.MEDIUM,
                    success_criteria={'data_exfiltrated': True},
                    constraints=constraints,
                    deadline=None,
                    dependencies=[f"goal_{i}_privesc"],
                    reward=600
                )
            else:
                goal = AutonomousGoal(
                    id=f"goal_{i}_generic",
                    description=objective,
                    priority=DecisionPriority.MEDIUM,
                    success_criteria={},
                    constraints=constraints,
                    deadline=None,
                    dependencies=[],
                    reward=500
                )
            
            goals.append(goal)
        
        return goals
    
    def all_goals_met(self, goals: List[AutonomousGoal], results: List[Dict]) -> bool:
        """Check if all goals are met"""
        return all(self.is_goal_met(goal, results) for goal in goals)
    
    def is_goal_met(self, goal: AutonomousGoal, results: List[Dict]) -> bool:
        """Check if specific goal is met"""
        for criteria_key, criteria_value in goal.success_criteria.items():
            met = False
            for result in results:
                if result.get('data', {}).get(criteria_key) == criteria_value:
                    met = True
                    break
            if not met:
                return False
        return True
    
    def evaluate_progress(self, goal: AutonomousGoal, history: deque) -> float:
        """Evaluate progress towards goal (0-1)"""
        if not goal.success_criteria:
            return 0.0
        
        criteria_met = 0
        total_criteria = len(goal.success_criteria)
        
        for criteria_key, criteria_value in goal.success_criteria.items():
            for entry in history:
                if entry.get('result', {}).get('data', {}).get(criteria_key) == criteria_value:
                    criteria_met += 1
                    break
        
        return criteria_met / total_criteria


class ExploitationStateMachine:
    """Manages exploitation state transitions"""
    
    def __init__(self):
        self.current_state = ExploitationPhase.RECONNAISSANCE
        self.state_history = []
        self.transition_rules = self._define_transitions()
    
    def _define_transitions(self) -> Dict:
        """Define valid state transitions"""
        return {
            ExploitationPhase.RECONNAISSANCE: [ExploitationPhase.VULNERABILITY_DISCOVERY],
            ExploitationPhase.VULNERABILITY_DISCOVERY: [ExploitationPhase.EXPLOITATION, ExploitationPhase.RECONNAISSANCE],
            ExploitationPhase.EXPLOITATION: [ExploitationPhase.POST_EXPLOITATION, ExploitationPhase.VULNERABILITY_DISCOVERY],
            ExploitationPhase.POST_EXPLOITATION: [ExploitationPhase.PERSISTENCE, ExploitationPhase.PIVOTING, ExploitationPhase.EXFILTRATION],
            ExploitationPhase.PIVOTING: [ExploitationPhase.RECONNAISSANCE, ExploitationPhase.EXPLOITATION],
            ExploitationPhase.PERSISTENCE: [ExploitationPhase.EXFILTRATION, ExploitationPhase.CLEANUP],
            ExploitationPhase.EXFILTRATION: [ExploitationPhase.CLEANUP],
            ExploitationPhase.CLEANUP: []
        }
    
    def initialize(self, target: str):
        """Initialize state machine for target"""
        self.current_state = ExploitationPhase.RECONNAISSANCE
        self.state_history = [{
            'state': self.current_state,
            'timestamp': datetime.now(),
            'target': target
        }]
    
    def transition(self, result: Dict):
        """Transition to new state based on result"""
        new_state = result.get('state_after')
        
        if new_state and self.is_valid_transition(self.current_state, new_state):
            self.current_state = new_state
            self.state_history.append({
                'state': new_state,
                'timestamp': datetime.now(),
                'trigger': result.get('action')
            })
    
    def is_valid_transition(self, from_state: ExploitationPhase, to_state: ExploitationPhase) -> bool:
        """Check if transition is valid"""
        return to_state in self.transition_rules.get(from_state, [])


class ResourceManager:
    """Manages resource allocation and monitoring"""
    
    def __init__(self):
        self.resource_usage = {
            'cpu': [],
            'memory': [],
            'network': []
        }
        self.limits = {}
    
    def check_resources_available(self) -> bool:
        """Check if resources are available"""
        # Simplified check - would use actual system monitoring
        return True
    
    def update_usage(self, action: str, duration: float):
        """Update resource usage statistics"""
        cpu_usage = np.random.uniform(10, 50)
        memory_usage = np.random.uniform(100, 500)
        network_requests = np.random.randint(10, 100)
        
        self.resource_usage['cpu'].append(cpu_usage)
        self.resource_usage['memory'].append(memory_usage)
        self.resource_usage['network'].append(network_requests)
    
    def get_usage_report(self) -> Dict:
        """Get resource usage report"""
        return {
            'average_cpu': np.mean(self.resource_usage['cpu']) if self.resource_usage['cpu'] else 0,
            'peak_memory': max(self.resource_usage['memory']) if self.resource_usage['memory'] else 0,
            'total_network_requests': sum(self.resource_usage['network'])
        }


class ReinforcementLearner:
    """Reinforcement learning for improving autonomous decisions"""
    
    def __init__(self, learning_rate: float = 0.01):
        self.learning_rate = learning_rate
        self.q_table = {}
        self.experience_replay = deque(maxlen=1000)
    
    def update(self, decision: Dict, result: Dict):
        """Update Q-values based on result"""
        state_action = f"{decision.get('state', 'unknown')}_{decision['action']}"
        
        reward = self._calculate_reward(result)
        
        if state_action not in self.q_table:
            self.q_table[state_action] = 0
        
        old_value = self.q_table[state_action]
        self.q_table[state_action] = old_value + self.learning_rate * (reward - old_value)
        
        self.experience_replay.append({
            'decision': decision,
            'result': result,
            'reward': reward
        })
    
    def _calculate_reward(self, result: Dict) -> float:
        """Calculate reward for action result"""
        reward = 0
        
        if result.get('success'):
            reward += 100
        else:
            reward -= 10
        
        if result.get('state_after') != result.get('state_before'):
            reward += 50
        
        execution_time = result.get('execution_time', 0)
        if execution_time > 30:
            reward -= 20
        
        return reward
    
    def get_insights(self) -> Dict:
        """Get learning insights"""
        if not self.q_table:
            return {'message': 'No learning data yet'}
        
        best_actions = sorted(self.q_table.items(), key=lambda x: x[1], reverse=True)[:5]
        worst_actions = sorted(self.q_table.items(), key=lambda x: x[1])[:5]
        
        return {
            'total_experiences': len(self.experience_replay),
            'best_state_actions': best_actions,
            'worst_state_actions': worst_actions,
            'average_q_value': np.mean(list(self.q_table.values()))
        }


class AutonomousDecisionMaker:
    """Makes autonomous decisions based on context"""
    
    def __init__(self):
        self.decision_history = []
        self.decision_cache = {}
    
    async def get_next_decision(self, current_state: ExploitationPhase,
                               goals: List[AutonomousGoal],
                               decision_tree: 'DecisionNode',
                               history: deque) -> Optional[Dict]:
        """Get next autonomous decision"""
        priority_goal = self._get_priority_goal(goals, history)
        
        if not priority_goal:
            return None
        
        best_path = self._find_best_path(decision_tree, current_state, priority_goal)
        
        if not best_path:
            return None
        
        next_action = best_path[0] if best_path else None
        
        if not next_action:
            return None
        
        return {
            'action': next_action.action,
            'priority': priority_goal.priority,
            'expected_reward': next_action.expected_reward,
            'probability_success': next_action.probability_success,
            'goal': priority_goal.id
        }
    
    def _get_priority_goal(self, goals: List[AutonomousGoal], history: deque) -> Optional[AutonomousGoal]:
        """Get highest priority unmet goal"""
        for goal in sorted(goals, key=lambda g: g.priority.value):
            if not self._is_goal_met(goal, history):
                return goal
        return None
    
    def _is_goal_met(self, goal: AutonomousGoal, history: deque) -> bool:
        """Check if goal is met"""
        for entry in history:
            if entry.get('result', {}).get('goal_id') == goal.id:
                return True
        return False
    
    def _find_best_path(self, tree: DecisionNode,
                       current_state: ExploitationPhase,
                       goal: AutonomousGoal) -> List[DecisionNode]:
        """Find best path to achieve goal using A* search"""
        start_node = self._find_state_node(tree, current_state)
        if not start_node:
            return []
        
        pq = [(0, [start_node])]
        visited = set()
        
        while pq:
            cost, path = heapq.heappop(pq)
            current = path[-1]
            
            if current.id in visited:
                continue
            visited.add(current.id)
            
            if self._achieves_goal(current, goal):
                return path[1:]
            
            for child in current.children:
                if child.id not in visited:
                    new_cost = cost + child.cost
                    new_path = path + [child]
                    priority = new_cost - child.expected_reward * child.probability_success
                    heapq.heappush(pq, (priority, new_path))
        
        return []
    
    def _find_state_node(self, node: DecisionNode, state: ExploitationPhase) -> Optional[DecisionNode]:
        """Find node with given state"""
        if node.state == state:
            return node
        
        for child in node.children:
            result = self._find_state_node(child, state)
            if result:
                return result
        return None
    
    def _achieves_goal(self, node: DecisionNode, goal: AutonomousGoal) -> bool:
        """Check if node achieves goal"""
        return node.expected_reward >= goal.reward * 0.8


class AutonomousOrchestrationEngine:
    """Implements true autonomous decision-making for exploitation"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        
        # Core components
        self.decision_maker = AutonomousDecisionMaker()
        self.goal_manager = GoalManager()
        self.state_machine = ExploitationStateMachine()
        self.resource_manager = ResourceManager()
        self.learning_engine = ReinforcementLearner()
        
        # Execution tracking
        self.current_goals: List[AutonomousGoal] = []
        self.execution_history: deque = deque(maxlen=1000)
        self.decision_tree: Optional[DecisionNode] = None
        
        # Autonomous operation flags
        self.autonomous_mode = True
        self.pause_requested = False
        self.max_autonomous_actions = 1000
        self.actions_taken = 0
    
    def _default_config(self) -> Dict:
        """Default configuration for autonomous operation"""
        return {
            'max_parallel_exploits': 5,
            'decision_timeout': 30,
            'learning_rate': 0.01,
            'exploration_rate': 0.2,
            'goal_reassessment_interval': 60,
            'resource_limits': {
                'cpu_percent': 80,
                'memory_mb': 4096,
                'network_requests_per_second': 100
            },
            'safety_checks': True,
            'require_confirmation_for_critical': False
        }
    
    async def run_autonomous_exploitation(self, target: str,
                                         objectives: List[str],
                                         constraints: Optional[Dict] = None) -> Dict:
        """Run fully autonomous exploitation"""
        print(f"[AUTONOMOUS] Starting autonomous exploitation of {target}")
        print(f"[AUTONOMOUS] Objectives: {objectives}")
        
        # Initialize goals
        self.current_goals = self.goal_manager.create_goals_from_objectives(
            objectives, target, constraints or {}
        )
        
        # Initialize state machine
        self.state_machine.initialize(target)
        
        # Build decision tree
        self.decision_tree = await self._build_decision_tree(target)
        
        # Main autonomous loop
        results = await self._autonomous_execution_loop()
        
        # Generate report
        report = self._generate_autonomy_report(results)
        
        return report
    
    async def _build_decision_tree(self, target: str) -> DecisionNode:
        """Build decision tree for exploitation planning"""
        root = DecisionNode(
            id="root",
            state=ExploitationPhase.RECONNAISSANCE,
            action="initial_scan",
            expected_reward=0,
            cost=0,
            probability_success=1.0
        )
        
        queue = [root]
        visited = set()
        
        while queue:
            node = queue.pop(0)
            
            if node.id in visited:
                continue
            visited.add(node.id)
            
            possible_actions = await self._generate_possible_actions(node.state, target)
            
            for action in possible_actions:
                child = DecisionNode(
                    id=f"{node.id}_{action['name']}",
                    state=action['next_state'],
                    action=action['name'],
                    expected_reward=action['reward'],
                    cost=action['cost'],
                    probability_success=action['probability'],
                    parent=node
                )
                
                node.children.append(child)
                
                if not self._is_terminal_state(child.state):
                    queue.append(child)
        
        return root
    
    async def _generate_possible_actions(self, state: ExploitationPhase, target: str) -> List[Dict]:
        """Generate possible actions from current state"""
        actions = []
        
        if state == ExploitationPhase.RECONNAISSANCE:
            actions = [
                {'name': 'port_scan', 'next_state': ExploitationPhase.VULNERABILITY_DISCOVERY,
                 'reward': 10, 'cost': 1, 'probability': 0.95},
                {'name': 'service_enumeration', 'next_state': ExploitationPhase.VULNERABILITY_DISCOVERY,
                 'reward': 15, 'cost': 2, 'probability': 0.90}
            ]
        elif state == ExploitationPhase.VULNERABILITY_DISCOVERY:
            actions = [
                {'name': 'vulnerability_scan', 'next_state': ExploitationPhase.EXPLOITATION,
                 'reward': 25, 'cost': 5, 'probability': 0.80},
                {'name': 'manual_testing', 'next_state': ExploitationPhase.EXPLOITATION,
                 'reward': 30, 'cost': 10, 'probability': 0.70}
            ]
        elif state == ExploitationPhase.EXPLOITATION:
            actions = [
                {'name': 'exploit_vulnerability', 'next_state': ExploitationPhase.POST_EXPLOITATION,
                 'reward': 100, 'cost': 20, 'probability': 0.60},
                {'name': 'chain_exploits', 'next_state': ExploitationPhase.POST_EXPLOITATION,
                 'reward': 150, 'cost': 30, 'probability': 0.40}
            ]
        
        return actions
    
    def _is_terminal_state(self, state: ExploitationPhase) -> bool:
        """Check if state is terminal"""
        return state in [ExploitationPhase.CLEANUP, ExploitationPhase.EXFILTRATION]
    
    async def _autonomous_execution_loop(self) -> List[Dict]:
        """Main autonomous execution loop"""
        results = []
        last_goal_reassessment = time.time()
        
        while (self.autonomous_mode and 
               not self.pause_requested and 
               self.actions_taken < self.max_autonomous_actions):
            
            if not self.resource_manager.check_resources_available():
                await asyncio.sleep(5)
                continue
            
            if time.time() - last_goal_reassessment > self.config['goal_reassessment_interval']:
                await self._reassess_goals()
                last_goal_reassessment = time.time()
            
            decision = await self.decision_maker.get_next_decision(
                current_state=self.state_machine.current_state,
                goals=self.current_goals,
                decision_tree=self.decision_tree,
                history=self.execution_history
            )
            
            if not decision:
                print("[AUTONOMOUS] No viable decisions available")
                break
            
            result = await self._execute_decision(decision)
            results.append(result)
            
            self.state_machine.transition(result)
            self.learning_engine.update(decision, result)
            
            if self.goal_manager.all_goals_met(self.current_goals, results):
                print("[AUTONOMOUS] All goals achieved!")
                break
            
            self.actions_taken += 1
            await asyncio.sleep(0.1)
        
        return results
    
    async def _execute_decision(self, decision: Dict) -> Dict:
        """Execute autonomous decision"""
        start_time = time.time()
        
        print(f"[AUTONOMOUS] Executing: {decision['action']} (Priority: {decision['priority']})")
        
        try:
            # Simulate execution based on action type
            await asyncio.sleep(np.random.uniform(1, 5))
            
            success = np.random.random() > 0.3
            
            result = {
                'success': success,
                'action': decision['action'],
                'state_before': self.state_machine.current_state,
                'state_after': self.state_machine.current_state,
                'data': {'simulated': True},
                'execution_time': time.time() - start_time
            }
            
            self.execution_history.append({
                'timestamp': datetime.now(),
                'decision': decision,
                'result': result,
                'execution_time': result['execution_time']
            })
            
            self.resource_manager.update_usage(decision['action'], result['execution_time'])
            
            return result
            
        except Exception as e:
            print(f"[AUTONOMOUS] Error executing {decision['action']}: {e}")
            return {
                'success': False,
                'action': decision['action'],
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    async def _reassess_goals(self):
        """Reassess and reprioritize goals"""
        print("[AUTONOMOUS] Reassessing goals...")
        
        for goal in self.current_goals:
            progress = self.goal_manager.evaluate_progress(goal, self.execution_history)
            
            if progress < 0.2 and goal.deadline:
                time_remaining = (goal.deadline - datetime.now()).total_seconds()
                if time_remaining < 3600:
                    goal.priority = DecisionPriority.CRITICAL
        
        self.current_goals.sort(key=lambda g: g.priority.value)
    
    def _generate_autonomy_report(self, results: List[Dict]) -> Dict:
        """Generate comprehensive autonomy report"""
        successful_actions = [r for r in results if r.get('success')]
        
        return {
            'summary': {
                'total_actions': len(results),
                'successful_actions': len(successful_actions),
                'success_rate': len(successful_actions) / len(results) if results else 0,
                'autonomous_duration': sum(r.get('execution_time', 0) for r in results)
            },
            'execution_path': [
                {'action': r['action'], 'success': r.get('success')}
                for r in results
            ],
            'resource_usage': self.resource_manager.get_usage_report(),
            'learning_insights': self.learning_engine.get_insights()
        }


# ============================================================================
# UNIFIED PLANNING SYSTEM
# ============================================================================

class UnifiedPlanningSystem:
    """Unified planning system combining all planning approaches"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Initialize all planning components
        self.simple_planner = SimplePlanner()
        self.strategies = {
            'depth_first': DepthFirstPlanner(),
            'breadth_first': BreadthFirstPlanner(),
            'aggressive': AggressivePlanner(),
            'adaptive': AdaptivePlanner()
        }
        self.ods = OutcomeDirectedSearch()
        self.autonomous_engine = AutonomousOrchestrationEngine(config)
        
        # Current active strategy
        self.active_strategy = 'adaptive'
    
    def create_plan(self, target: str, recon: Optional[Dict] = None,
                   mode: str = 'simple', signals_text: Optional[str] = None,
                   objectives: Optional[List[str]] = None) -> List[PlanStep]:
        """
        Create exploitation plan using specified mode
        
        Modes:
        - 'simple': Use simple planner
        - 'strategic': Use selected strategy
        - 'ods': Use outcome-directed search
        - 'autonomous': Use autonomous engine
        - 'hybrid': Combine multiple approaches
        """
        
        if mode == 'simple':
            return self.simple_planner.make_plan(target, recon or {}, signals_text)
        
        elif mode == 'strategic':
            strategy = self.strategies.get(self.active_strategy)
            if strategy:
                return strategy.plan(
                    target=target,
                    recon=recon,
                    mapper=self.simple_planner.mapper,
                    llm=self.simple_planner.llm,
                    kb=self.simple_planner.kb,
                    signals_text=signals_text
                )
        
        elif mode == 'ods':
            # Use outcome-directed search
            evidence = recon.get('evidence_score', 0.5) if recon else 0.5
            return self.ods.generate_pivot_plan(target, evidence)
        
        elif mode == 'autonomous':
            # Convert to async execution
            import asyncio
            
            async def run():
                result = await self.autonomous_engine.run_autonomous_exploitation(
                    target=target,
                    objectives=objectives or ['Find and exploit vulnerabilities'],
                    constraints={}
                )
                # Convert autonomous results to PlanSteps
                steps = []
                for action in result.get('execution_path', []):
                    steps.append(PlanStep(
                        plugin=action.get('action', 'UnknownPlugin'),
                        rationale='Autonomous decision',
                        params={'target': target}
                    ))
                return steps
            
            return asyncio.run(run())
        
        elif mode == 'hybrid':
            # Combine multiple approaches
            steps = []
            
            # Start with simple plan
            steps.extend(self.simple_planner.make_plan(target, recon or {}, signals_text))
            
            # Add strategic steps
            strategy = self.strategies.get('adaptive')
            if strategy:
                strategic_steps = strategy.plan(
                    target=target,
                    recon=recon,
                    signals_text=signals_text,
                    llm_step_budget=2
                )
                steps.extend(strategic_steps[:5])
            
            # Add ODS recommendations if evidence is available
            if recon and 'evidence_score' in recon:
                ods_steps = self.ods.get_recommended_next_steps(target)
                steps.extend(ods_steps[:3])
            
            return steps
        
        else:
            # Default to simple planner
            return self.simple_planner.make_plan(target, recon or {}, signals_text)
    
    def adapt_strategy(self, evidence: float, results: List[Dict]):
        """Adapt planning strategy based on evidence and results"""
        # Let ODS observe and potentially pivot
        pivot_step = self.ods.observe(evidence, results)
        
        if pivot_step:
            # Switch to more aggressive strategy if pivoting
            if evidence < 0.3:
                self.active_strategy = 'breadth_first'
            elif evidence < 0.6:
                self.active_strategy = 'depth_first'
            else:
                self.active_strategy = 'aggressive'
        
        # Update ODS state from results
        for result in results:
            self.ods.update_from_result(result)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current planning system status"""
        return {
            'active_strategy': self.active_strategy,
            'ods_summary': self.ods.get_exploitation_summary(),
            'autonomous_mode': self.autonomous_engine.autonomous_mode,
            'actions_taken': self.autonomous_engine.actions_taken,
            'current_phase': self.ods.state.phase.value,
            'evidence_trend': self.ods.evidence_agg.get_trend()
        }
    
    def set_strategy(self, strategy_name: str):
        """Set active planning strategy"""
        if strategy_name in self.strategies:
            self.active_strategy = strategy_name
    
    def should_chain_vulnerabilities(self) -> bool:
        """Check if vulnerability chaining should be attempted"""
        return self.ods.should_attempt_chaining()


# Strategy registry
STRATEGY_REGISTRY: Dict[str, BasePlannerStrategy] = {}

def register_strategy(strategy: BasePlannerStrategy):
    """Register a planning strategy"""
    STRATEGY_REGISTRY[strategy.name] = strategy
    return strategy

def get_planner(name: str) -> BasePlannerStrategy:
    """Get planner strategy by name"""
    return STRATEGY_REGISTRY.get(name, STRATEGY_REGISTRY.get("adaptive"))

# Register default strategies
for strategy in [DepthFirstPlanner(), BreadthFirstPlanner(), 
                 AggressivePlanner(), AdaptivePlanner()]:
    register_strategy(strategy)


# For backward compatibility
Planner = SimplePlanner  # Alias for legacy code

__all__ = [
    'UnifiedPlanningSystem',
    'PlanStep',
    'SimplePlanner',
    'Planner',  # Backward compatibility
    'BasePlannerStrategy',
    'DepthFirstPlanner',
    'BreadthFirstPlanner',
    'AggressivePlanner',
    'AdaptivePlanner',
    'OutcomeDirectedSearch',
    'AutonomousOrchestrationEngine',
    'ExploitationPhase',
    'DecisionPriority',
    'register_strategy',
    'get_planner'
]
