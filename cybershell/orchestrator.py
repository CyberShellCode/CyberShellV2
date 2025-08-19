from dataclasses import dataclass, field
from typing import Dict, Any, List, Type, Optional, Tuple
import time
import json
from pathlib import Path
from datetime import datetime
from .config import SafetyConfig
from .plugins import PluginBase, PluginResult
from .plugin_loader import load_user_plugins
from .strategies import get_planner
from .scoring import get_scorer
from .ods import OutcomeDirectedSearch, ODSConfig, EvidenceAggregator
from .miner import DocumentMiner
from .mapper import AdaptiveLearningMapper
from .llm import LLMConnector
from .reporting import ReportBuilder
from .agent import AutonomousBountyHunter, BountyConfig

# New enhanced modules
from .continuous_learning_pipeline import ContinuousLearningPipeline, ExploitAttempt
from .business_impact_reporter import BusinessImpactReporter, VulnerabilityFinding
from .benchmarking_framework import BenchmarkingFramework, BenchmarkTarget, BenchmarkResult
from .advanced_ai_orchestrator import AdvancedAIOrchestrator, ModelCapability
from .autonomous_orchestration_engine import (
    AutonomousOrchestrationEngine, 
    AutonomousGoal, 
    ExploitationState,
    DecisionPriority
)
from .validation_framework import (
    RealWorldValidationFramework,
    ValidationResult,
    ValidationEvidence,
    EvidenceType,
    ValidationStrength
)

# Core exploitation plugins (lab-safe stubs, real implementation in plugins_user/)
DEFAULT_REGISTRY = {
    # Recon plugins
    'HttpFingerprintPlugin': 'cybershell.plugins.HttpFingerprintPlugin',
    'FormDiscoveryPlugin': 'cybershell.plugins.FormDiscoveryPlugin',
    'HeuristicAnalyzerPlugin': 'cybershell.plugins.HeuristicAnalyzerPlugin',

    # Exploitation plugins - CORRECTED PATHS
    'SQLiTestPlugin': 'plugins_user.exploitation_plugins.SQLiTestPlugin',
    'SQLiExploitPlugin': 'plugins_user.exploitation_plugins.SQLiExploitPlugin',
    'XSSTestPlugin': 'plugins_user.exploitation_plugins.XSSTestPlugin',
    'XSSExploitPlugin': 'plugins_user.exploitation_plugins.XSSExploitPlugin',
    'RCETestPlugin': 'plugins_user.exploitation_plugins.RCETestPlugin',
    'RCEExploitPlugin': 'plugins_user.exploitation_plugins.RCEExploitPlugin',
    'IDORTestPlugin': 'plugins_user.exploitation_plugins.IDORTestPlugin',
    'IDORExploitPlugin': 'plugins_user.exploitation_plugins.IDORExploitPlugin',
    'SSRFTestPlugin': 'plugins_user.exploitation_plugins.SSRFTestPlugin',
    'SSRFExploitPlugin': 'plugins_user.exploitation_plugins.SSRFExploitPlugin',
    'AuthBypassTestPlugin': 'plugins_user.exploitation_plugins.AuthBypassTestPlugin',
    'AuthBypassExploitPlugin': 'plugins_user.exploitation_plugins.AuthBypassExploitPlugin',

    # Support plugins - CORRECTED PATHS
    'StateManagerPlugin': 'plugins_user.state_manager_plugin.StateManagerPlugin',
    'AntiAutomationPlugin': 'plugins_user.anti_automation_plugin.AntiAutomationPlugin',
    'ArtifactHandlingPlugin': 'plugins_user.artifact_handling_plugin.ArtifactHandlingPlugin',
    'SelfHealingPlugin': 'plugins_user.self_healing_plugin.SelfHealingPlugin',
    'BusinessLogicPlugin': 'plugins_user.business_logic_plugin.BusinessLogicPlugin',
}

@dataclass
class ExploitationMetrics:
    """Track exploitation success metrics"""
    total_attempts: int = 0
    successful_exploits: int = 0
    failed_exploits: int = 0
    false_positives: int = 0
    true_positives: int = 0
    average_confidence: float = 0.0
    total_evidence_score: float = 0.0
    exploit_chains: int = 0
    
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.successful_exploits / self.total_attempts
    
    def precision(self) -> float:
        total_positives = self.true_positives + self.false_positives
        if total_positives == 0:
            return 0.0
        return self.true_positives / total_positives

@dataclass
class CyberShell:
    """
    Core orchestrator for bug bounty hunting operations
    Manages agents, plugins, and exploitation workflows
    """
    
    config: SafetyConfig
    doc_root: str = 'docs'
    planner_name: str = 'depth_first'
    scorer_name: str = 'weighted_signal'
    user_plugins_dir: str = 'plugins_user'
    llm: Optional[LLMConnector] = None
    ods_cfg: Optional[ODSConfig] = None
    
    def __post_init__(self):
        # Core components
        self.mapper = AdaptiveLearningMapper(alpha=0.5)
        self.miner = DocumentMiner(self.doc_root)
        self.reporter = ReportBuilder()
        self.metrics = ExploitationMetrics()
        
        # Plugin registry
        self._registry = self._load_plugin_registry()
        
        # Scoring and planning
        self.scorer = get_scorer(self.scorer_name)
        self.planner = get_planner(self.planner_name)
        
        # ODS with evidence aggregation
        if not self.ods_cfg:
            self.ods_cfg = ODSConfig(
                window=5,
                patience_steps=3,
                stop_threshold=0.85,
                min_improvement=0.05,
                max_iterations=20
            )
        
        self.ods = OutcomeDirectedSearch(self.ods_cfg)
        self.evidence_agg = EvidenceAggregator()
        
        # Session state for multi-step exploits
        self.session_state = {}
        
        # Autonomous agent (initialized on demand)
        self._agent = None
    
    def _load_plugin_registry(self) -> Dict[str, Type[PluginBase]]:
        """Load all plugins from registry and user directory"""
        registry = {}
        
        # Load default plugins
        for name, path in DEFAULT_REGISTRY.items():
            try:
                parts = path.split('.')
                module_path = '.'.join(parts[:-1])
                class_name = parts[-1]
                
                module = __import__(module_path, fromlist=[class_name])
                plugin_class = getattr(module, class_name)
                registry[name] = plugin_class
            except Exception as e:
                print(f"[!] Failed to load {name}: {e}")
        
        # Load user plugins
        user_plugins = load_user_plugins(self.user_plugins_dir)
        registry.update(user_plugins)
        
        return registry
    
    def execute_plugin(self, plugin_name: str, params: Dict[str, Any]) -> PluginResult:
        """Execute a single plugin with parameters"""
        plugin_class = self._registry.get(plugin_name)
        if not plugin_class:
            return PluginResult(plugin_name, False, {'error': 'Plugin not found'})
        
        try:
            # Handle authentication state
            if plugin_name == 'StateManagerPlugin':
                # Store session state for other plugins
                plugin = plugin_class(self.config)
                result = plugin.run(**params)
                if result.success:
                    self.session_state.update(result.details.get('session', {}))
                return result
            
            # Pass session state to plugins that need it
            if self.session_state and plugin_name in ['SQLiExploitPlugin', 'XSSExploitPlugin', 
                                                       'RCEExploitPlugin', 'IDORExploitPlugin']:
                params['session'] = self.session_state
            
            plugin = plugin_class(self.config)
            result = plugin.run(**params)
            
            # Update metrics
            self._update_metrics(result)
            
            return result
            
        except Exception as e:
            return PluginResult(plugin_name, False, {'error': str(e)})
    
    def execute(self, target: str, planner_name: Optional[str] = None, 
                scorer_name: Optional[str] = None, llm_step_budget: int = 3,
                doc_root: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute bug bounty workflow with ODS and evidence tracking
        """
        start_time = time.time()
        
        # Use provided or default components
        planner = get_planner(planner_name or self.planner_name)
        scorer = get_scorer(scorer_name or self.scorer_name)
        
        # Phase 1: Initial reconnaissance
        recon = self._execute_recon(target)
        
        # Phase 2: Plan generation (with LLM assistance)
        initial_plan = planner.plan(
            target=target,
            recon=recon,
            mapper=self.mapper,
            llm=self.llm,
            kb=self._get_kb_context(target, recon),
            signals_text=None,
            llm_step_budget=llm_step_budget
        )
        
        # Phase 3: Execute initial plan with evidence collection
        results = []
        evidence_scores = []
        
        for step in initial_plan:
            result = self.execute_plugin(step.plugin, step.params)
            results.append(result)
            
            # Calculate evidence score
            score = scorer.score(result)
            evidence_scores.append(score)
            self.evidence_agg.add(score)
        
        # Phase 4: ODS-driven adaptive exploitation
        ods_results = self._execute_ods_loop(target, recon, results, scorer, planner)
        results.extend(ods_results['results'])
        evidence_scores.extend(ods_results['scores'])
        
        # Phase 5: Vulnerability chaining (if evidence is strong)
        if self.evidence_agg.get_ema() > 0.7:
            chain_results = self._attempt_exploit_chains(results)
            results.extend(chain_results)
        
        # Phase 6: Generate report with evidence
        report = self._generate_exploitation_report(
            target=target,
            recon=recon,
            results=results,
            evidence_scores=evidence_scores,
            duration=time.time() - start_time
        )
        
        return {
            'target': target,
            'recon': recon,
            'plan': [s.__dict__ for s in initial_plan],
            'results': [r.__dict__ for r in results],
            'evidence_summary': {
                'scores': evidence_scores,
                'ema': self.evidence_agg.get_ema(),
                'max': self.evidence_agg.get_max(),
                'trend': self.evidence_agg.get_trend()
            },
            'metrics': self.metrics.__dict__,
            'report': report
        }
    
    def hunt_autonomous(self, target: str, bounty_config: Optional[BountyConfig] = None) -> Dict[str, Any]:
        """
        Launch fully autonomous bug bounty hunting
        """
        if not bounty_config:
            bounty_config = BountyConfig(
                target_domain=target,
                scope=[target],
                aggressive_mode=True,
                chain_vulnerabilities=True,
                extract_data_samples=True,
                auto_generate_reports=True
            )
        
        # Initialize autonomous agent
        self._agent = AutonomousBountyHunter(bounty_config, self)
        
        # Start hunting
        return self._agent.hunt(target)
    
    def _execute_recon(self, target: str) -> Dict[str, Any]:
        """Execute reconnaissance phase"""
        recon = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'technologies': [],
            'endpoints': [],
            'parameters': set(),
            'forms': [],
            'apis': []
        }
        
        # Run reconnaissance plugins
        recon_plugins = [
            'HttpFingerprintPlugin',
            'TechnologyStackPlugin',
            'FormDiscoveryPlugin',
            'APIDiscoveryPlugin'
        ]
        
        for plugin_name in recon_plugins:
            if plugin_name in self._registry:
                result = self.execute_plugin(plugin_name, {'target': target})
                if result.success:
                    self._merge_recon_data(recon, result.details)
        
        return recon
    
    def _execute_ods_loop(self, target: str, recon: Dict, initial_results: List,
                         scorer, planner) -> Dict[str, Any]:
        """Execute Outcome-Directed Search loop for adaptive exploitation"""
        ods_results = []
        ods_scores = []
        
        iteration = 0
        stagnation = 0
        last_ema = self.evidence_agg.get_ema()
        
        while iteration < self.ods_cfg.max_iterations:
            # Check for early stop
            if self.evidence_agg.get_max() >= self.ods_cfg.stop_threshold:
                print(f"[ODS] Early stop: evidence threshold reached ({self.evidence_agg.get_max():.2f})")
                break
            
            # Synthesize signals from recent results
            signals = self._synthesize_signals(initial_results[-5:] + ods_results[-5:])
            
            # Get mapper suggestions
            mapped = self.mapper.map(type('Evt', (), {'as_text': lambda: signals})())
            top_families = [f for f, _ in mapped.top_families[:3]]
            
            # Generate adaptive plan based on evidence
            adaptive_plan = planner.plan(
                target=target,
                recon=recon,
                mapper=self.mapper,
                llm=self.llm,
                kb=self._get_kb_context(target, recon),
                signals_text=signals,
                llm_step_budget=2
            )
            
            # Execute adaptive steps
            for step in adaptive_plan[:3]:  # Limit steps per iteration
                result = self.execute_plugin(step.plugin, step.params)
                ods_results.append(result)
                
                score = scorer.score(result)
                ods_scores.append(score)
                self.evidence_agg.add(score)
            
            # Check for stagnation
            current_ema = self.evidence_agg.get_ema()
            if current_ema - last_ema < self.ods_cfg.min_improvement:
                stagnation += 1
                if stagnation >= self.ods_cfg.patience_steps:
                    print(f"[ODS] Stopping: evidence stagnated at {current_ema:.2f}")
                    break
            else:
                stagnation = 0
            
            last_ema = current_ema
            iteration += 1
        
        return {
            'results': ods_results,
            'scores': ods_scores,
            'iterations': iteration
        }
    
    def _attempt_exploit_chains(self, results: List[PluginResult]) -> List[PluginResult]:
        """Attempt to chain vulnerabilities for greater impact"""
        chain_results = []
        
        # Identify chainable vulnerabilities
        sqli_results = [r for r in results if 'sqli' in r.name.lower() and r.success]
        xss_results = [r for r in results if 'xss' in r.name.lower() and r.success]
        idor_results = [r for r in results if 'idor' in r.name.lower() and r.success]
        
        # SQLi -> RCE chain
        if sqli_results:
            chain_result = self.execute_plugin('SQLiToRCEChainPlugin', {
                'sqli_evidence': sqli_results[0].details,
                'target': sqli_results[0].details.get('target')
            })
            if chain_result.success:
                chain_results.append(chain_result)
                self.metrics.exploit_chains += 1
        
        # XSS -> Account Takeover chain
        if xss_results:
            chain_result = self.execute_plugin('XSSToAccountTakeoverPlugin', {
                'xss_evidence': xss_results[0].details,
                'target': xss_results[0].details.get('target')
            })
            if chain_result.success:
                chain_results.append(chain_result)
                self.metrics.exploit_chains += 1
        
        # IDOR -> Privilege Escalation chain
        if idor_results:
            chain_result = self.execute_plugin('IDORToPrivEscPlugin', {
                'idor_evidence': idor_results[0].details,
                'target': idor_results[0].details.get('target')
            })
            if chain_result.success:
                chain_results.append(chain_result)
                self.metrics.exploit_chains += 1
        
        return chain_results
    
    def _generate_exploitation_report(self, target: str, recon: Dict, results: List,
                                     evidence_scores: List, duration: float) -> str:
        """Generate comprehensive bug bounty report"""
        successful_exploits = [r for r in results if r.success and r.details.get('evidence_score', 0) > 0.7]
        
        report = f"""
# Bug Bounty Exploitation Report
## Target: {target}
## Date: {datetime.now().isoformat()}
## Duration: {duration:.2f} seconds

## Executive Summary
- Total Plugins Executed: {len(results)}
- Successful Exploits: {len(successful_exploits)}
- Average Evidence Score: {sum(evidence_scores)/len(evidence_scores) if evidence_scores else 0:.2f}
- Maximum Evidence Score: {max(evidence_scores) if evidence_scores else 0:.2f}
- Exploit Chains: {self.metrics.exploit_chains}

## Metrics
- Success Rate: {self.metrics.success_rate():.2%}
- Precision: {self.metrics.precision():.2%}
- True Positives: {self.metrics.true_positives}
- False Positives: {self.metrics.false_positives}

## Reconnaissance
Technologies: {', '.join(recon.get('technologies', []))}
Endpoints: {len(recon.get('endpoints', []))}
Forms: {len(recon.get('forms', []))}
APIs: {len(recon.get('apis', []))}

## Vulnerabilities Discovered
"""
        
        # Add detailed findings
        for i, result in enumerate(successful_exploits, 1):
            details = result.details
            report += f"""
### Finding #{i}: {result.name}
**Evidence Score:** {details.get('evidence_score', 0):.2f}
**Endpoint:** {details.get('target', 'N/A')}

#### Evidence:
```json
{json.dumps(details.get('evidence', {}), indent=2)}
```

#### Impact:
{details.get('impact_proof', 'See evidence above')}

---
"""
        
        # Add recommendations
        report += """
## Recommendations
"""
        
        vuln_types = set(r.name.replace('Plugin', '').replace('Exploit', '') for r in successful_exploits)
        for vuln_type in vuln_types:
            if 'SQLi' in vuln_type:
                report += "- Implement parameterized queries and input validation\n"
            elif 'XSS' in vuln_type:
                report += "- Implement proper output encoding and CSP headers\n"
            elif 'RCE' in vuln_type:
                report += "- Sanitize user input and avoid system command execution\n"
            elif 'IDOR' in vuln_type:
                report += "- Implement proper authorization checks\n"
        
        return report
    
    def _synthesize_signals(self, results: List[PluginResult]) -> str:
        """Synthesize signals from results for mapper"""
        signals = []
        
        for result in results:
            if not result.success:
                continue
            
            details = result.details
            
            # Extract various signals
            if 'error_tokens' in details:
                signals.extend(details['error_tokens'])
            
            if 'reflections' in details:
                signals.extend(details['reflections'])
            
            if 'headers' in details:
                signals.extend(f"{k}:{v}" for k, v in details['headers'].items())
            
            if 'evidence_score' in details:
                signals.append(f"evidence:{details['evidence_score']}")
            
            if 'vulnerable' in details:
                signals.append(f"vulnerable:{details['vulnerable']}")
        
        return ' '.join(signals)
    
    def _get_kb_context(self, target: str, recon: Dict) -> Dict[str, Any]:
        """Get knowledge base context for planning"""
        # Mine local documents for relevant information
        query = f"target:{target} "
        query += ' '.join(recon.get('technologies', []))
        
        hits = self.miner.mine(query, top_k=5)
        
        return {
            'titles': [h.title for h in hits],
            'summaries': [h.summary for h in hits]
        }
    
    def _merge_recon_data(self, recon: Dict, details: Dict):
        """Merge reconnaissance data from plugin results"""
        if 'technologies' in details:
            recon['technologies'].extend(details['technologies'])
        
        if 'endpoints' in details:
            recon['endpoints'].extend(details['endpoints'])
        
        if 'parameters' in details:
            recon['parameters'].update(details['parameters'])
        
        if 'forms' in details:
            recon['forms'].extend(details['forms'])
        
        if 'apis' in details:
            recon['apis'].extend(details['apis'])
    
    def _update_metrics(self, result: PluginResult):
        """Update exploitation metrics based on result"""
        self.metrics.total_attempts += 1
        
        if result.success:
            self.metrics.successful_exploits += 1
            
            # Check for true/false positives
            if result.details.get('verified'):
                self.metrics.true_positives += 1
            elif result.details.get('false_positive'):
                self.metrics.false_positives += 1
        else:
            self.metrics.failed_exploits += 1
        
        # Update evidence scores
        if 'evidence_score' in result.details:
            score = result.details['evidence_score']
            n = self.metrics.total_attempts
            self.metrics.average_confidence = (
                (self.metrics.average_confidence * (n - 1) + score) / n
            )
            self.metrics.total_evidence_score += score
    
    def attach_trained_mapper(self, trained_ml):
        """Attach a pre-trained mapper model"""
        self.mapper.ml = trained_ml
    
    def set_llm(self, llm: LLMConnector):
        """Set the LLM connector"""
        self.llm = llm
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current exploitation metrics"""
        return {
            'total_attempts': self.metrics.total_attempts,
            'successful_exploits': self.metrics.successful_exploits,
            'success_rate': self.metrics.success_rate(),
            'precision': self.metrics.precision(),
            'average_confidence': self.metrics.average_confidence,
            'exploit_chains': self.metrics.exploit_chains
        }
