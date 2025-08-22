from dataclasses import dataclass, field
from typing import Dict, Any, List, Type, Optional, Tuple
import time
import json
from pathlib import Path
from datetime import datetime

# Import unified configuration
from .unified_config import UnifiedConfig, get_config, initialize_config

# Existing imports
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
from cybershell.vulnerability_kb import VulnerabilityKBPlugin
from cybershell.bypass_techniques import BypassPlugin
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

@dataclass
class ExploitationMetrics:
    """Metrics for exploitation tracking"""
    total_attempts: int = 0
    successful_exploits: int = 0
    failed_exploits: int = 0
    total_time: float = 0
    vulnerabilities_found: List[str] = field(default_factory=list)

class CyberShell:
    """
    Main orchestrator for CyberShell framework
    Now with unified configuration and enhanced modules
    """
    
    def __init__(self, config: Optional[Dict] = None, args=None):
        """Initialize CyberShell with unified configuration"""
        
        # Initialize unified configuration
        if args:
            self.config = initialize_config(args=args)
        elif config:
            self.config = initialize_config(config_dict=config)
        else:
            self.config = initialize_config()
        
        # Validate configuration
        issues = self.config.validate()
        if issues:
            print(f"[WARNING] Configuration issues: {issues}")
        
        # Core configuration shortcuts
        self.safety_config = self.config.safety
        self.bounty_config = self.config.bounty
        self.exploitation_config = self.config.exploitation
        self.llm_config = self.config.llm
        
        # Initialize core components
        self.plugins = self._load_plugins()
        self.planner = get_planner(self.config.exploitation.max_parallel_exploits)
        self.scorer = get_scorer('default')
        self.metrics = ExploitationMetrics()
        
        # Initialize enhanced modules
        self._initialize_enhanced_modules()
        
        # Initialize ODS if configured
        if self.config.autonomy.enable_autonomy:
            self.ods = OutcomeDirectedSearch(ODSConfig())
            self.evidence_aggregator = EvidenceAggregator()
        
        # Initialize LLM if configured
        if self.config.llm.provider != 'none':
            self.llm_connector = LLMConnector(
                provider=self.config.llm.provider,
                model=self.config.llm.model,
                base_url=self.config.llm.base_url,
                api_key=self.config.llm.api_key
            )
        else:
            self.llm_connector = None
        
        # Initialize reporting
        self.report_builder = ReportBuilder(self.config.reporting)
        
        # Initialize agent if in autonomous mode
        if self.config.autonomy.enable_autonomy:
            self.agent = AutonomousBountyHunter(
                self.config.bounty,
                self.safety_config
            )
        
    def _initialize_enhanced_modules(self):
        """Initialize all enhanced modules with unified config"""
        
        # Machine Learning Pipeline
        self.learning_pipeline = ContinuousLearningPipeline(
            model_dir=self.config.learning.model_dir
        )
        
        # Business Impact Reporter
        self.impact_reporter = BusinessImpactReporter(
            company_profile=self.config.reporting.company_profile
        )
        
        # Benchmarking Framework
        if self.config.benchmarking.enable_benchmarking:
            self.benchmark_framework = BenchmarkingFramework(
                config_file=self.config.config_file
            )
        else:
            self.benchmark_framework = None
        
        # Advanced AI Orchestrator
        self.ai_orchestrator = AdvancedAIOrchestrator(
            config={
                'max_parallel_models': self.config.exploitation.max_parallel_exploits,
                'exploration_rate': self.config.learning.exploration_rate
            }
        )
        
        # Autonomous Orchestration Engine
        self.autonomous_engine = AutonomousOrchestrationEngine(
            config={
                'max_autonomous_actions': self.config.autonomy.max_autonomous_actions,
                'decision_timeout': self.config.autonomy.decision_timeout,
                'learning_rate': self.config.learning.learning_rate
            }
        )
        
        # Set scope for autonomous engine
        self.autonomous_engine.set_scope(
            allowed=self.config.safety.scope_hosts,
            excluded=self.config.safety.out_of_scope_patterns
        )
        
        # Validation Framework
        self.validation_framework = RealWorldValidationFramework(
            config={
                'min_confidence_threshold': self.config.validation.min_confidence_threshold,
                'require_multiple_evidence': self.config.validation.require_multiple_evidence,
                'max_validation_attempts': self.config.validation.max_validation_attempts
            }
        )
        
        # Wire up scope checking
        self.validation_framework.scope_checker = self.safety_config.is_in_scope
    
    def _load_plugins(self) -> Dict[str, PluginBase]:
        """Load plugins from user directory"""
        if self.config.plugin.enable_user_plugins:
            plugins = load_user_plugins(self.config.plugin.plugins_dir)
            
            # Apply whitelist/blacklist
            if self.config.plugin.plugin_whitelist:
                plugins = {k: v for k, v in plugins.items() 
                          if k in self.config.plugin.plugin_whitelist}
            
            if self.config.plugin.plugin_blacklist:
                plugins = {k: v for k, v in plugins.items() 
                          if k not in self.config.plugin.plugin_blacklist}
            
            return plugins
        return {}
    
    def check_scope(self, target: str) -> bool:
        """Check if target is in scope using unified config"""
        return self.safety_config.is_in_scope(target)
    
    async def run_exploitation(self, target: str) -> Dict:
        """Run exploitation with all enhanced features"""
        
        # Check scope
        if not self.check_scope(target):
            print(f"[SCOPE] Target {target} is out of scope!")
            return {'error': 'out_of_scope'}
        
        print(f"[*] Starting exploitation of {target}")
        start_time = time.time()
        
        # Use AI orchestrator for intelligent exploitation
        if self.config.llm.provider != 'none':
            ai_result = await self.ai_orchestrator.orchestrate_exploitation(
                target=target,
                vulnerability_type='AUTO',
                context={'config': self.config.to_dict()}
            )
            
            # Validate results
            validation = await self.validation_framework.validate_exploitation(
                target=target,
                vulnerability_type=ai_result.get('vulnerability_type', 'UNKNOWN'),
                exploitation_result=ai_result
            )
            
            # Record for learning
            if self.config.learning.enable_continuous_learning:
                attempt = ExploitAttempt(
                    timestamp=datetime.now(),
                    target=target,
                    vulnerability_type=ai_result.get('vulnerability_type', 'UNKNOWN'),
                    plugin_used='AI_Orchestrator',
                    success=validation.validated,
                    confidence_score=validation.confidence_score,
                    evidence_score=validation.confidence_score,
                    execution_time=time.time() - start_time,
                    error_details=None,
                    environmental_factors={},
                    payload_characteristics={}
                )
                self.learning_pipeline.record_exploitation_attempt(attempt)
        
        # Run autonomous exploitation if enabled
        if self.config.autonomy.enable_autonomy:
            autonomous_result = await self.autonomous_engine.run_autonomous_exploitation(
                target=target,
                objectives=['Find all vulnerabilities', 'Demonstrate impact'],
                constraints={'max_time': self.config.exploitation.exploitation_timeout}
            )
            
            # Generate business impact report
            if autonomous_result.get('findings'):
                report = self.impact_reporter.generate_executive_report(
                    findings=autonomous_result['findings'],
                    scan_metadata={
                        'target': target,
                        'duration': time.time() - start_time
                    }
                )
                
                # Save report
                report_path = Path(self.config.reporting.output_dir) / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                
                print(f"[+] Report saved to {report_path}")
        
        # Update metrics
        self.metrics.total_attempts += 1
        self.metrics.total_time += time.time() - start_time
        
        return {
            'target': target,
            'duration': time.time() - start_time,
            'metrics': self.metrics,
            'config_used': self.config.version
        }
    
    def get_status(self) -> Dict:
        """Get current status with all module information"""
        return {
            'config_version': self.config.version,
            'target': self.config.bounty.target_domain,
            'scope': self.config.safety.scope_hosts,
            'metrics': self.metrics,
            'learning_insights': self.learning_pipeline.get_learning_insights(),
            'modules_loaded': {
                'learning': True,
                'impact_reporting': True,
                'benchmarking': self.benchmark_framework is not None,
                'ai_orchestration': True,
                'autonomous': self.config.autonomy.enable_autonomy,
                'validation': True
            }
        }
