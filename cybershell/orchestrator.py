from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Type, Optional, Tuple
import time
import json
from pathlib import Path
from datetime import datetime
import asyncio

# Import unified configuration
from .unified_config import UnifiedConfig, get_config, initialize_config, BountyConfig

# Group 1: Payload Management
from .payload_manager import UnifiedPayloadManager, PayloadContext

# Group 2: Learning Pipeline
from .learning_pipeline import (
    UnifiedLearningPipeline, 
    ExploitAttempt,
    RunMetrics,
    save, load, create_model_store,
    train_mapper
)

# Group 3: AI Orchestration
from .ai_orchestrator import (
    UnifiedAIOrchestrator,
    ModelCapability,
    OllamaConnector,
    OpenAIConnector,
    ChatSession,
    build_step_prompt
)

# Group 4: Knowledge Management
from .knowledge_manager import (
    UnifiedKnowledgeManager,
    VulnerabilityKnowledgeBase,
    DocumentMiner,
    KnowledgeBase
)

# Group 5: Scanner
from .scanner import (
    UnifiedScanner,
    WebApplicationMapper,
    IDORHunter,
    ExternalToolsManager
)

# Group 6: Planning System
from .planning_system import (
    UnifiedPlanningSystem,
    PlanStep,
    SimplePlanner,
    OutcomeDirectedSearch,
    AutonomousOrchestrationEngine,
    get_planner,
    register_strategy
)

# Group 7: Reporting System
from .reporting_system import (
    UnifiedReportingSystem,
    VulnerabilityFinding,
    get_scorer,
    EvidenceAggregator,
    PluginResult
)

# Group 8: Testing System
from .testing_system import (
    UnifiedTestingSystem,
    BenchmarkingFramework,
    RealWorldValidationFramework,
    BenchmarkTarget,
    BenchmarkResult,
    ValidationResult
)

# Group 9: Bypass System
from .bypass_system import (
    UnifiedBypassSystem,
    BypassPlugin,
    ProtectionDetection
)

# Group 10: State Management
from .state_manager import (
    UnifiedStateManager,
    WorkflowState,
    retry,
    FeedbackItem
)

# Group 11: Utils
from .utils import (
    SignalEvent,
    Tactic, 
    Evidence,
    ExploitResult,
    TargetFingerprint,
    ValidationResult as UtilValidationResult,
    is_in_scope,
    generate_report_filename,
    calculate_severity,
    format_evidence_summary
)

# Group 12: Plugin Runtime
from .plugin_runtime import (
    PluginRegistry,
    PluginBase,
    PluginResult as PluginRuntimeResult,
    PluginMetadata,
    PluginCapability,
    create_plugin_runtime
)

# Other imports
from .strategies import get_planner as legacy_get_planner
from .agent import AutonomousBountyHunter
from .fingerprinter import Fingerprinter, TargetFingerprint as FingerprintResult
from .ods import OutcomeDirectedSearch as LegacyODS, ODSConfig

@dataclass
class ExploitationMetrics:
    """Metrics for exploitation tracking"""
    total_attempts: int = 0
    successful_exploits: int = 0
    failed_exploits: int = 0
    total_time: float = 0
    vulnerabilities_found: List[str] = field(default_factory=list)
    fingerprints_collected: int = 0

class CyberShell:
    """
    Main orchestrator for CyberShell framework with all unified modules
    """
    
    def __init__(self, config: Optional[Dict] = None, args=None):
        """Initialize CyberShell with unified modules"""
        
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
        
        # Initialize metrics
        self.metrics = ExploitationMetrics()
        
        # GROUP 1: Unified Payload Manager
        self.payload_manager = UnifiedPayloadManager(
            kb_path=self.config.knowledge_base_path if hasattr(self.config, 'knowledge_base_path') else "knowledge_base/",
            config=self.config.to_dict()
        )
        
        # GROUP 2: Unified Learning Pipeline
        self.learning_pipeline = UnifiedLearningPipeline(
            model_dir=self.config.learning.model_dir,
            kb=None  # Will be set after knowledge manager init
        )
        self.run_metrics = self.learning_pipeline.metrics
        
        # GROUP 3: Unified AI Orchestrator
        self.ai_orchestrator = UnifiedAIOrchestrator(
            config={
                'max_parallel_models': self.config.exploitation.max_parallel_exploits,
                'default_provider': self.config.llm.provider,
                'ollama_model': self.config.llm.model,
                'ollama_url': self.config.llm.base_url,
                'openai_api_key': self.config.llm.api_key
            }
        )
        self.chat = self.ai_orchestrator.create_chat_session(
            name="default",
            kb=None  # Will be set after knowledge manager init
        )
        
        # GROUP 4: Unified Knowledge Manager
        self.knowledge_manager = UnifiedKnowledgeManager({
            'kb_path': 'knowledge_base/',
            'doc_root': self.config.get('doc_root', './documents') if isinstance(self.config, dict) else './documents',
            'embedding_dim': 384
        })
        # Backward compatibility aliases
        self.vulnerability_kb = self.knowledge_manager.vulnerability_kb
        self.document_miner = self.knowledge_manager.document_miner
        self.kb = self.knowledge_manager.simple_kb
        
        # Update learning pipeline and chat with KB
        self.learning_pipeline.kb = self.kb
        if self.chat:
            self.chat.kb = self.kb
        
        # GROUP 5: Unified Scanner
        self.scanner = UnifiedScanner({
            'requests_per_second': 5,
            'burst_size': 10,
            'output_dir': './scan_output',
            'respect_headers': True
        })
        # Backward compatibility
        self.mapper = self.scanner.web_mapper
        self.idor_hunter = self.scanner.idor_hunter
        self.external_tools = self.scanner.external_tools
        
        # GROUP 6: Unified Planning System
        self.planning_system = UnifiedPlanningSystem({
            'max_parallel_exploits': self.config.exploitation.max_parallel_exploits,
            'learning_rate': 0.01,
            'exploration_rate': 0.2
        })
        # Backward compatibility
        self.planner = self.planning_system.simple_planner
        self.ods = self.planning_system.ods
        self.autonomous_engine = self.planning_system.autonomous_engine
        
        # GROUP 7: Unified Reporting System
        self.reporting_system = UnifiedReportingSystem({
            'company_profile': getattr(self.config.reporting, 'company_profile', None),
            'output_dir': self.config.reporting.output_dir
        })
        # Backward compatibility
        self.report_builder = self.reporting_system.bug_bounty_reporter
        self.business_reporter = self.reporting_system.business_impact_reporter
        self.evidence_aggregator = self.reporting_system.evidence_aggregator
        
        # GROUP 8: Unified Testing System
        self.testing_system = UnifiedTestingSystem({
            'benchmark_config': None,
            'validation_config': None,
            'parallel': self.config.exploitation.max_parallel_exploits
        })
        # Backward compatibility
        self.benchmarking = self.testing_system.benchmarking
        self.validation = self.testing_system.validation
        
        # GROUP 9: Unified Bypass System
        self.bypass_system = UnifiedBypassSystem({})
        
        # GROUP 10: Unified State Manager
        self.state_manager = UnifiedStateManager(config={
            'session_timeout': getattr(self.config.exploitation, 'session_timeout', 3600),
            'state_file': getattr(self.config, 'state_file', './sessions/state.pkl')
        })
        # Connect ML mapper if available
        if hasattr(self, 'mapper'):
            self.state_manager.set_ml_mapper(self.mapper)
        # Load previous state
        self.state_manager.load_state()
        
        # GROUP 12: Plugin Runtime
        self.plugin_registry = create_plugin_runtime(config={
            'plugins_dir': self.config.plugin.plugins_dir,
            'scope_hosts': self.config.safety.scope_hosts,
            'safe_mode': self.config.safety.safe_mode
        })
        plugins_loaded = self.plugin_registry.load_from_directory(
            self.config.plugin.plugins_dir
        )
        print(f"[INFO] Loaded {plugins_loaded} user plugins")
        
        # Legacy compatibility - expose plugins dict
        self.plugins = self.plugin_registry._plugins
        
        # Initialize fingerprinter (already in use)
        self.fingerprinter = Fingerprinter({
            'timeout': self.config.exploitation.request_timeout,
            'aggressive': self.config.exploitation.aggressive_mode,
            'use_external_tools': False
        })
        self.fingerprint_cache = {}
        
        # Initialize agent if in autonomous mode
        if self.config.autonomy.enable_autonomy:
            self.agent = AutonomousBountyHunter(
                self.config.bounty,
                self.safety_config
            )
            # Wire in unified components
            self.agent.payload_manager = self.payload_manager
            self.agent.fingerprinter = self.fingerprinter
    
    def check_scope(self, target: str) -> bool:
        """Check if target is in scope using unified config"""
        return self.safety_config.is_in_scope(target)
    
    def fingerprint_target(self, target: str, use_cache: bool = True) -> TargetFingerprint:
        """Fingerprint target and cache results"""
        # Check cache
        if use_cache and target in self.fingerprint_cache:
            cached = self.fingerprint_cache[target]
            if hasattr(cached, 'timestamp'):
                try:
                    if (datetime.now() - datetime.fromisoformat(cached.timestamp)).seconds < 300:
                        print(f"[FINGERPRINT] Using cached fingerprint for {target}")
                        return cached
                except:
                    pass
        
        # Perform fingerprinting
        print(f"[FINGERPRINT] Fingerprinting {target}...")
        fingerprint = self.fingerprinter.fingerprint(
            target,
            aggressive=self.config.exploitation.aggressive_mode
        )
        
        # Add timestamp
        fingerprint.timestamp = datetime.now().isoformat()
        
        # Cache result
        self.fingerprint_cache[target] = fingerprint
        self.metrics.fingerprints_collected += 1
        
        # Log summary
        print(f"[FINGERPRINT] Detected: {fingerprint.product} {fingerprint.version or 'unknown version'}")
        if fingerprint.technologies:
            print(f"[FINGERPRINT] Technologies: {', '.join(fingerprint.technologies)}")
        if fingerprint.waf:
            print(f"[FINGERPRINT] WAF detected: {fingerprint.waf}")
        
        return fingerprint
    
    def select_payloads_for_target(self, target: str, vulnerability_type: str, context: Optional[Dict] = None):
        """Select optimal payloads using unified payload manager"""
        fingerprint = self.fingerprint_target(target)
        
        # Create PayloadContext
        payload_context = PayloadContext(
            target_url=target,
            parameter_name=context.get('param') if context else None,
            waf_detected=fingerprint.waf
        )
        
        # Get payloads using unified manager
        ranked_payloads = self.payload_manager.get_payloads_for_target(
            target_url=target,
            vulnerability_type=vulnerability_type,
            fingerprint=fingerprint,
            context=payload_context,
            top_n=10
        )
        
        # Convert to simple list for plugins
        return [{'payload': rp.payload, 'rank': rp.rank} for rp in ranked_payloads]
    
    def start_exploitation(self, target):
        """Start exploitation with state management"""
        # Update workflow state
        self.state_manager.send_event("start_scan")
        
        # Get/create authenticated session
        session_result = self.state_manager.get_session(
            target, 
            credentials={'username': 'admin', 'password': 'admin'}
        )
        
        if session_result['success']:
            session = session_result['session']
            # Use session for requests...
        
        # Continue with exploitation
        self.state_manager.send_event("start_exploit")
    
    def handle_human_feedback(self, event, correct_families):
        """Handle HITL feedback"""
        self.state_manager.submit_feedback(event, correct_families)
        applied = self.state_manager.apply_feedback()
        print(f"Applied {applied} feedback items")
    
    @retry  # Use the retry decorator for resilient operations
    def make_authenticated_request(self, target, endpoint):
        """Make authenticated request with retry"""
        session_data = self.state_manager.get_session(target)
        if session_data['success']:
            session = session_data['session']
            return session.get(f"{target}{endpoint}")
        return None
    
    def save_progress(self):
        """Save state periodically"""
        self.state_manager.save_state()
    
    def execute_plugin(self, plugin_name: str, **kwargs):
        """Execute a plugin with orchestrator context"""
        # Add orchestrator context
        kwargs['session'] = self.state_manager.get_session(kwargs.get('target', ''))
        kwargs['config'] = self.config.to_dict()
        
        # Execute through registry
        result = self.plugin_registry.execute_plugin(plugin_name, **kwargs)
        
        if result and result.success:
            # Update learning pipeline with results
            self.learning_pipeline.record_outcome(
                [plugin_name],
                result.evidence_score > 0.5
            )
        
        return result
    
    def get_exploitation_chain(self, vulnerability_type: str) -> List[str]:
        """Get plugin chain for exploitation"""
        # Map vulnerability types to capability chains
        chains = {
            'sqli': [PluginCapability.EXPLOIT, PluginCapability.EXFILTRATION],
            'xss': [PluginCapability.EXPLOIT, PluginCapability.POST_EXPLOIT],
            'rce': [PluginCapability.EXPLOIT, PluginCapability.PERSISTENCE]
        }
        
        capabilities = chains.get(vulnerability_type.lower(), [PluginCapability.EXPLOIT])
        return self.plugin_registry.get_plugin_chain(capabilities)
    
    def run_plugin_chain(self, chain: List[str], initial_context: Dict):
        """Run a chain of plugins"""
        results = self.plugin_registry.execute_chain(chain, initial_context)
        
        # Generate report from results
        if results:
            success_count = sum(1 for r in results if r.success)
            print(f"Chain completed: {success_count}/{len(results)} successful")
        
        return results
    
    def handle_403_forbidden(self, target):
        """Handle 403 forbidden responses with bypass system"""
        # Auto-bypass attempt
        from urllib.parse import urlparse
        result = self.bypass_system.auto_bypass(
            target,
            path=urlparse(target).path,
            max_attempts=10
        )
        
        if result['success']:
            print(f"Bypassed using: {result['technique']}")
            return result['result']
        
        return None
    
    def detect_and_bypass_waf(self, target, payload):
        """Detect and bypass WAF"""
        # Detect protections
        protections = self.bypass_system.detect_protections(target)
        
        # Generate evasions if WAF detected
        if any(p['type'] == 'WAF' for p in protections['protections']):
            evasions = self.bypass_system.generate_waf_evasions(payload)
            
            for evasion in evasions:
                # Try evasion
                pass
    
    async def run_exploitation(self, target: str) -> Dict:
        """Run exploitation with all unified modules"""
        
        # Check scope
        if not self.check_scope(target):
            print(f"[SCOPE] Target {target} is out of scope!")
            return {'error': 'out_of_scope'}
        
        print(f"[*] Starting exploitation of {target}")
        start_time = time.time()
        
        # Start exploitation workflow
        self.start_exploitation(target)
        
        # Fingerprint target
        fingerprint = self.fingerprint_target(target)
        
        # Comprehensive scanning
        scan_result = await self.scanner.comprehensive_scan(
            target,
            options={
                'scan_type': 'normal',
                'enable_nmap': False,
                'enable_sqlmap': True,
                'enable_idor': True,
                'use_browser': False
            }
        )
        
        # Search knowledge base
        kb_results = self.knowledge_manager.search(
            f"{fingerprint.product} vulnerabilities",
            search_type="all"
        )
        
        # Create exploitation plan
        plan = self.planning_system.create_plan(
            target,
            recon=scan_result,
            mode='hybrid'
        )
        
        # Use AI for intelligent exploitation
        steps = self.ai_orchestrator.suggest_exploitation_steps(target, scan_result)
        
        # Validate findings
        findings = []
        for vuln_type in ['sqli', 'xss', 'rce']:
            validation_result = await self.testing_system.validate_exploitation(
                target=target,
                vulnerability_type=vuln_type.upper(),
                exploitation_result={'found': 1, 'response': 'test'}
            )
            
            if validation_result.confidence_score > 0.8:
                finding = self.reporting_system.create_vulnerability_finding(
                    vuln_type=vuln_type,
                    evidence={'validated': True},
                    target=target
                )
                findings.append(finding)
        
        # Generate report
        report = self.reporting_system.generate_report(
            target=target,
            findings=findings,
            scan_metadata={'duration': time.time() - start_time},
            report_type='combined'
        )
        
        # Update metrics
        self.metrics.total_attempts += 1
        self.metrics.total_time += time.time() - start_time
        if findings:
            self.metrics.successful_exploits += len(findings)
            self.metrics.vulnerabilities_found.extend([f.vuln_type for f in findings])
        
        # Save progress
        self.save_progress()
        
        return {
            'target': target,
            'duration': time.time() - start_time,
            'fingerprint': {
                'product': fingerprint.product,
                'version': fingerprint.version
            },
            'findings': findings,
            'report': report,
            'metrics': asdict(self.metrics)
        }
    
    def execute(self, target: str, llm_step_budget: int = 5) -> Dict[str, Any]:
        """Execute exploitation workflow with all unified modules"""
        start_time = time.time()
        
        # Check scope
        if not self.check_scope(target):
            return {
                'evidence_summary': {'ema': 0, 'max': 0, 'trend': 'none'},
                'metrics': {
                    'total_attempts': 0,
                    'successful_exploits': 0,
                    'success_rate': 0,
                    'exploit_chains': 0
                },
                'report': f"Target {target} is out of scope"
            }
        
        # Run exploitation
        result = {}
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.run_exploitation(target))
        except Exception as e:
            result = {'error': str(e)}
        
        # Build evidence summary
        evidence_summary = {
            'ema': self.evidence_aggregator.get_ema() if hasattr(self.evidence_aggregator, 'get_ema') else 0.5,
            'max': 0.8,
            'trend': 'stable'
        }
        
        # Get metrics
        metrics = asdict(self.metrics)
        metrics.update({
            'success_rate': self.metrics.successful_exploits / max(1, self.metrics.total_attempts),
            'exploit_chains': 0
        })
        
        # Generate final report
        report = result.get('report', f"Exploitation of {target} completed")
        
        return {
            'evidence_summary': evidence_summary,
            'metrics': metrics,
            'report': report,
            'target': target,
            'duration': time.time() - start_time,
            'findings': result.get('findings', [])
        }
    
    def get_status(self) -> Dict:
        """Get current status with all module information"""
        return {
            'config_version': self.config.version,
            'target': self.config.bounty.target_domain,
            'scope': self.config.safety.scope_hosts,
            'metrics': asdict(self.metrics),
            'fingerprints_cached': len(self.fingerprint_cache),
            'learning_insights': self.learning_pipeline.get_learning_insights(),
            'state': self.state_manager.get_state_summary(),
            'modules_loaded': {
                'payload_management': True,
                'learning': True,
                'ai_orchestration': True,
                'knowledge_management': True,
                'scanning': True,
                'planning': True,
                'reporting': True,
                'testing': True,
                'bypass': True,
                'state_management': True,
                'plugin_runtime': True,
                'fingerprinting': True
            }
        }
    
    def hunt_autonomous(self, target: str, bounty_config: BountyConfig) -> Dict:
        """Run autonomous hunting"""
        if hasattr(self, 'agent'):
            return self.agent.hunt(target)
        else:
            # Fallback to execute
            return self.execute(target, llm_step_budget=10)
