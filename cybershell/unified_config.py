import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# BASE CONFIGURATION CLASSES
# ============================================================================

@dataclass
class SafetyConfig:
    """Safety and scope configuration"""
    allow_localhost: bool = False
    allow_private_ranges: bool = False
    allow_production: bool = False
    scope_hosts: List[str] = field(default_factory=list)
    out_of_scope_patterns: List[str] = field(default_factory=list)
    additional_scope_hosts: List[str] = field(default_factory=list)
    require_explicit_authorization: bool = True
    safe_mode: bool = False
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        from urllib.parse import urlparse
        
        parsed = urlparse(target if '://' in target else f'http://{target}')
        domain = parsed.netloc or parsed.path
        
        # Check localhost
        if not self.allow_localhost and domain in ['localhost', '127.0.0.1', '::1']:
            return False
        
        # Check private ranges
        if not self.allow_private_ranges:
            import ipaddress
            try:
                ip = ipaddress.ip_address(domain.split(':')[0])
                if ip.is_private:
                    return False
            except ValueError:
                pass
        
        # Check out-of-scope patterns
        for pattern in self.out_of_scope_patterns:
            if pattern in domain:
                return False
        
        # Check explicit scope
        all_scope = self.scope_hosts + self.additional_scope_hosts
        if not all_scope:
            return False  # No scope = no testing (fail-safe)
        
        for allowed in all_scope:
            if allowed.startswith('*.'):
                if domain.endswith(allowed[2:]) or domain == allowed[2:]:
                    return True
            elif domain == allowed:
                return True
        
        return False

@dataclass
class BountyConfig:
    """Bug bounty specific configuration"""
    target_domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    aggressive_mode: bool = False
    chain_vulnerabilities: bool = False
    extract_data_samples: bool = False
    auto_generate_reports: bool = True
    max_parallel_exploits: int = 5
    min_cvss_for_exploit: float = 4.0
    confidence_threshold: float = 0.75
    bounty_values: Dict[str, float] = field(default_factory=lambda: {
        'Critical': 10000,
        'High': 5000,
        'Medium': 1000,
        'Low': 100
    })

@dataclass
class ExploitationConfig:
    """Exploitation behavior configuration"""
    max_parallel_exploits: int = 10
    min_cvss_for_exploit: float = 7.0
    confidence_threshold: float = 0.8
    chain_vulnerabilities: bool = True
    extract_data_samples: bool = True
    exploitation_timeout: int = 300  # seconds
    max_exploitation_attempts: int = 3
    delay_between_attempts: float = 1.0
    prioritize_critical: bool = True
    skip_low_severity: bool = False

@dataclass
class LLMConfig:
    """LLM integration configuration"""
    provider: str = "ollama"  # ollama, openai, anthropic, none
    model: str = "dolphin-mixtral:8x7b"
    base_url: str = "http://localhost:11434"
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2000
    timeout: int = 30
    max_retries: int = 3
    context_window: int = 32768
    enable_caching: bool = True
    cache_ttl: int = 3600

@dataclass
class LearningConfig:
    """Machine learning and adaptive learning configuration"""
    enable_continuous_learning: bool = True
    model_update_threshold: int = 100
    experience_buffer_size: int = 10000
    learning_rate: float = 0.01
    exploration_rate: float = 0.2
    model_save_interval: int = 1000
    model_dir: str = "models/adaptive"
    enable_online_learning: bool = True
    batch_size: int = 32
    validation_split: float = 0.2

@dataclass
class ReportingConfig:
    """Reporting and output configuration"""
    output_format: str = "json"  # json, markdown, html, pdf
    output_dir: str = "reports"
    include_screenshots: bool = True
    include_poc_code: bool = True
    include_remediation: bool = True
    include_business_impact: bool = True
    include_compliance_mapping: bool = True
    executive_summary: bool = True
    technical_details: bool = True
    generate_charts: bool = True
    company_profile: Dict[str, Any] = field(default_factory=lambda: {
        'name': 'Target Organization',
        'industry': 'Technology',
        'compliance_requirements': ['GDPR', 'SOC2', 'PCI-DSS']
    })

@dataclass
class BenchmarkingConfig:
    """Benchmarking and performance testing configuration"""
    enable_benchmarking: bool = False
    benchmark_suite: str = "basic"  # basic, advanced, comprehensive
    max_parallel_benchmarks: int = 10
    benchmark_timeout: int = 300
    collect_metrics_interval: float = 1.0
    performance_thresholds: Dict[str, float] = field(default_factory=lambda: {
        'max_cpu': 80.0,
        'max_memory': 4096.0,
        'min_success_rate': 0.7,
        'max_false_positive_rate': 0.2
    })
    compare_tools: List[str] = field(default_factory=lambda: [
        'Burp Suite', 'OWASP ZAP', 'Nuclei'
    ])

@dataclass
class ValidationConfig:
    """Validation and verification configuration"""
    min_confidence_threshold: float = 0.7
    require_multiple_evidence: bool = True
    max_validation_attempts: int = 5
    validation_timeout: int = 30
    differential_threshold: float = 0.3
    timing_deviation_threshold: float = 2.0
    check_false_positives: bool = True
    verify_remediation: bool = False
    evidence_correlation: bool = True

@dataclass
class AutonomyConfig:
    """Autonomous operation configuration"""
    enable_autonomy: bool = True
    max_autonomous_actions: int = 1000
    decision_timeout: int = 30
    goal_reassessment_interval: int = 60
    learning_enabled: bool = True
    exploration_vs_exploitation: float = 0.2
    allow_destructive_actions: bool = False
    require_human_confirmation: bool = False
    pause_on_critical_finding: bool = True

@dataclass
class PluginConfig:
    """Plugin system configuration"""
    plugins_dir: str = "plugins_user"
    enable_user_plugins: bool = True
    plugin_timeout: int = 60
    max_plugin_retries: int = 3
    plugin_whitelist: List[str] = field(default_factory=list)
    plugin_blacklist: List[str] = field(default_factory=list)
    auto_reload_plugins: bool = False

@dataclass
class NetworkConfig:
    """Network and proxy configuration"""
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    no_proxy: List[str] = field(default_factory=lambda: ['localhost', '127.0.0.1'])
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    user_agent: str = "CyberShell/2.0"
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = True

@dataclass
class DebugConfig:
    """Debug and logging configuration"""
    debug: bool = False
    verbose: bool = False
    log_level: str = "INFO"
    log_file: Optional[str] = "cybershell.log"
    log_to_console: bool = True
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    save_responses: bool = False
    save_payloads: bool = False
    trace_execution: bool = False

# ============================================================================
# MAIN UNIFIED CONFIGURATION
# ============================================================================

@dataclass
class UnifiedConfig:
    """
    Unified configuration for all CyberShell components
    Single source of truth for all settings
    """
    
    # Core configurations
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    bounty: BountyConfig = field(default_factory=lambda: BountyConfig(target_domain=""))
    exploitation: ExploitationConfig = field(default_factory=ExploitationConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    learning: LearningConfig = field(default_factory=LearningConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    benchmarking: BenchmarkingConfig = field(default_factory=BenchmarkingConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    autonomy: AutonomyConfig = field(default_factory=AutonomyConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    debug: DebugConfig = field(default_factory=DebugConfig)
    
    # Metadata
    version: str = "2.0.0"
    config_file: Optional[str] = None
    
    @classmethod
    def from_file(cls, config_file: str = "config.yaml") -> 'UnifiedConfig':
        """Load configuration from YAML file"""
        config_path = Path(config_file)
        
        if not config_path.exists():
            logger.warning(f"Config file {config_file} not found, using defaults")
            return cls()
        
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        return cls.from_dict(data, config_file=config_file)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], config_file: Optional[str] = None) -> 'UnifiedConfig':
        """Create configuration from dictionary"""
        config = cls()
        config.config_file = config_file
        
        # Update each sub-configuration
        if 'safety' in data:
            config.safety = SafetyConfig(**data['safety'])
        if 'bounty' in data:
            config.bounty = BountyConfig(**data['bounty'])
        if 'exploitation' in data:
            config.exploitation = ExploitationConfig(**data['exploitation'])
        if 'llm' in data:
            config.llm = LLMConfig(**data['llm'])
        if 'learning' in data:
            config.learning = LearningConfig(**data['learning'])
        if 'reporting' in data:
            config.reporting = ReportingConfig(**data['reporting'])
        if 'benchmarking' in data:
            config.benchmarking = BenchmarkingConfig(**data['benchmarking'])
        if 'validation' in data:
            config.validation = ValidationConfig(**data['validation'])
        if 'autonomy' in data:
            config.autonomy = AutonomyConfig(**data['autonomy'])
        if 'plugin' in data:
            config.plugin = PluginConfig(**data['plugin'])
        if 'network' in data:
            config.network = NetworkConfig(**data['network'])
        if 'debug' in data:
            config.debug = DebugConfig(**data['debug'])
        
        return config
    
    @classmethod
    def from_args(cls, args) -> 'UnifiedConfig':
        """Create configuration from command-line arguments"""
        config = cls()
        
        # Map command-line arguments to configuration
        if hasattr(args, 'target'):
            config.bounty.target_domain = args.target
        
        if hasattr(args, 'scope') and args.scope:
            config.safety.scope_hosts = args.scope.split(',')
            config.bounty.scope = args.scope.split(',')
        
        if hasattr(args, 'out_of_scope') and args.out_of_scope:
            config.safety.out_of_scope_patterns = args.out_of_scope.split(',')
            config.bounty.out_of_scope = args.out_of_scope.split(',')
        
        if hasattr(args, 'safe_mode'):
            config.safety.safe_mode = args.safe_mode
            config.bounty.aggressive_mode = not args.safe_mode
        
        if hasattr(args, 'production'):
            config.safety.allow_production = args.production
            config.safety.allow_localhost = not args.production
            config.safety.allow_private_ranges = not args.production
        
        if hasattr(args, 'chain_exploits'):
            config.exploitation.chain_vulnerabilities = args.chain_exploits
            config.bounty.chain_vulnerabilities = args.chain_exploits
        
        if hasattr(args, 'extract_data'):
            config.exploitation.extract_data_samples = args.extract_data
            config.bounty.extract_data_samples = args.extract_data
        
        if hasattr(args, 'parallel'):
            config.exploitation.max_parallel_exploits = args.parallel
            config.bounty.max_parallel_exploits = args.parallel
        
        if hasattr(args, 'min_cvss'):
            config.exploitation.min_cvss_for_exploit = args.min_cvss
            config.bounty.min_cvss_for_exploit = args.min_cvss
        
        if hasattr(args, 'confidence'):
            config.exploitation.confidence_threshold = args.confidence
            config.bounty.confidence_threshold = args.confidence
        
        if hasattr(args, 'llm'):
            config.llm.provider = args.llm
        
        if hasattr(args, 'verbose'):
            config.debug.verbose = args.verbose
            config.debug.debug = args.verbose
        
        if hasattr(args, 'output'):
            config.reporting.output_dir = os.path.dirname(args.output) or 'reports'
        
        if hasattr(args, 'format'):
            config.reporting.output_format = args.format
        
        return config
    
    def merge_with_env(self) -> 'UnifiedConfig':
        """Merge configuration with environment variables"""
        
        # LLM settings from environment
        if os.getenv('OLLAMA_MODEL'):
            self.llm.model = os.getenv('OLLAMA_MODEL')
        if os.getenv('OLLAMA_BASE_URL'):
            self.llm.base_url = os.getenv('OLLAMA_BASE_URL')
        if os.getenv('OPENAI_API_KEY'):
            self.llm.api_key = os.getenv('OPENAI_API_KEY')
            if not self.llm.provider:
                self.llm.provider = 'openai'
        if os.getenv('ANTHROPIC_API_KEY'):
            self.llm.api_key = os.getenv('ANTHROPIC_API_KEY')
            if not self.llm.provider:
                self.llm.provider = 'anthropic'
        
        # Network settings
        if os.getenv('HTTP_PROXY'):
            self.network.http_proxy = os.getenv('HTTP_PROXY')
        if os.getenv('HTTPS_PROXY'):
            self.network.https_proxy = os.getenv('HTTPS_PROXY')
        
        # Debug settings
        if os.getenv('DEBUG'):
            self.debug.debug = os.getenv('DEBUG').lower() in ('true', '1', 'yes')
        if os.getenv('VERBOSE'):
            self.debug.verbose = os.getenv('VERBOSE').lower() in ('true', '1', 'yes')
        
        return self
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)
    
    def save(self, config_file: Optional[str] = None):
        """Save configuration to YAML file"""
        config_file = config_file or self.config_file or "config.yaml"
        
        with open(config_file, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"Configuration saved to {config_file}")
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Check required fields
        if not self.bounty.target_domain and not self.safety.scope_hosts:
            issues.append("No target or scope defined")
        
        # Check conflicting settings
        if self.safety.safe_mode and self.bounty.aggressive_mode:
            issues.append("Both safe_mode and aggressive_mode are enabled")
        
        if self.safety.allow_production and not self.safety.scope_hosts:
            issues.append("Production mode enabled without explicit scope")
        
        # Check thresholds
        if self.exploitation.confidence_threshold > 1.0 or self.exploitation.confidence_threshold < 0:
            issues.append("Confidence threshold must be between 0 and 1")
        
        if self.exploitation.min_cvss_for_exploit > 10.0 or self.exploitation.min_cvss_for_exploit < 0:
            issues.append("CVSS threshold must be between 0 and 10")
        
        # Check paths
        if not Path(self.plugin.plugins_dir).exists():
            issues.append(f"Plugin directory {self.plugin.plugins_dir} does not exist")
        
        return issues
    
    def get_module_config(self, module_name: str) -> Any:
        """Get configuration for specific module"""
        return getattr(self, module_name, None)
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return f"UnifiedConfig(version={self.version}, target={self.bounty.target_domain})"

# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigurationManager:
    """
    Singleton configuration manager for CyberShell
    Ensures single source of truth for all configuration
    """
    
    _instance = None
    _config: Optional[UnifiedConfig] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def initialize(self, 
                  config_file: Optional[str] = None,
                  args: Optional[Any] = None,
                  config_dict: Optional[Dict] = None) -> UnifiedConfig:
        """Initialize configuration from various sources"""
        
        # Priority: args > config_dict > config_file > defaults
        if args:
            self._config = UnifiedConfig.from_args(args)
        elif config_dict:
            self._config = UnifiedConfig.from_dict(config_dict)
        elif config_file:
            self._config = UnifiedConfig.from_file(config_file)
        else:
            self._config = UnifiedConfig()
        
        # Merge with environment variables
        self._config.merge_with_env()
        
        # Validate configuration
        issues = self._config.validate()
        if issues:
            logger.warning(f"Configuration issues: {issues}")
        
        return self._config
    
    @property
    def config(self) -> UnifiedConfig:
        """Get current configuration"""
        if self._config is None:
            self._config = UnifiedConfig()
        return self._config
    
    def reload(self):
        """Reload configuration from file"""
        if self._config and self._config.config_file:
            self._config = UnifiedConfig.from_file(self._config.config_file)
            self._config.merge_with_env()
    
    def update(self, **kwargs):
        """Update specific configuration values"""
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)

# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def get_config() -> UnifiedConfig:
    """Get current configuration instance"""
    return ConfigurationManager().config

def initialize_config(config_file: Optional[str] = None,
                     args: Optional[Any] = None,
                     config_dict: Optional[Dict] = None) -> UnifiedConfig:
    """Initialize and return configuration"""
    return ConfigurationManager().initialize(config_file, args, config_dict)

def update_config(**kwargs):
    """Update configuration values"""
    ConfigurationManager().update(**kwargs)

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example: Create configuration from command-line arguments
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--scope', help='Scope')
    parser.add_argument('--safe-mode', action='store_true')
    parser.add_argument('--production', action='store_true')
    
    args = parser.parse_args(['http://example.com', '--scope', '*.example.com'])
    
    # Initialize configuration
    config = initialize_config(args=args)
    
    # Access configuration
    print(f"Target: {config.bounty.target_domain}")
    print(f"Scope: {config.safety.scope_hosts}")
    print(f"Safe mode: {config.safety.safe_mode}")
    
    # Check if target is in scope
    print(f"In scope: {config.safety.is_in_scope('http://example.com')}")
    
    # Save configuration
    config.save("my_config.yaml")
