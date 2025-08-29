"""
CyberShellV2 - Advanced Autonomous Exploitation Framework
=========================================================
A comprehensive security testing framework for authorized bug bounty hunting 
and CTF competitions with ML-powered continuous learning capabilities.

Author: CyberShellCode
License: MIT (for authorized security testing only)
"""

__version__ = "2.0.0"
__author__ = "CyberShellCode"
__license__ = "MIT"

# Core modules
from . import orchestrator
from . import agent
from . import unified_config
from . import rate_limiter
from . import fingerprinter  # Keep - actively used

# Unified modules (merged from multiple files)
from . import payload_manager
from . import learning_pipeline
from . import ai_orchestrator
from . import knowledge_manager
from . import scanner
from . import planning_system
from . import reporting_system
from . import testing_system
from . import bypass_system
from . import state_manager
from . import utils
from . import plugin_runtime

# Legacy config redirect
try:
    from . import config
except ImportError:
    pass  # Legacy config might not exist

# Main orchestrator class for convenience
from .orchestrator import CyberShell

# Plugin base classes - now from plugin_runtime
from .plugin_runtime import (
    PluginBase,
    PluginResult,
    PluginMetadata,
    PluginCapability,
    PluginRegistry
)

# Configuration classes
from .unified_config import (
    UnifiedConfig,
    SafetyConfig,
    BountyConfig,
    ExploitationConfig,
    LLMConfig,
    LearningConfig,
    ReportingConfig,
    BenchmarkingConfig,
    ValidationConfig,
    AutonomyConfig,
    PluginConfig,
    NetworkConfig,
    DebugConfig,
    RateLimitConfig,
    VulnerabilityKBConfig,
    BypassConfig,
    IntegrationConfig
)

# Utility classes
from .utils import (
    SignalEvent,
    Tactic,
    Evidence,
    ExploitResult,
    TargetFingerprint,
    ValidationResult
)

# State management
from .state_manager import (
    UnifiedStateManager,
    WorkflowState,
    FeedbackItem
)

__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__license__',
    
    # Core modules
    'orchestrator',
    'agent',
    'unified_config',
    'config',  # Legacy, redirects to unified_config
    'rate_limiter',
    'fingerprinter',
    
    # Unified modules
    'payload_manager',
    'learning_pipeline',
    'ai_orchestrator',
    'knowledge_manager',
    'scanner',
    'planning_system',
    'reporting_system',
    'testing_system',
    'bypass_system',
    'state_manager',
    'utils',
    'plugin_runtime',
    
    # Main classes exported for convenience
    'CyberShell',
    'PluginBase',
    'PluginResult',
    'PluginMetadata',
    'PluginCapability',
    'PluginRegistry',
    
    # Configuration classes
    'UnifiedConfig',
    'SafetyConfig',
    'BountyConfig',
    'ExploitationConfig',
    'LLMConfig',
    'LearningConfig',
    'ReportingConfig',
    'BenchmarkingConfig',
    'ValidationConfig',
    'AutonomyConfig',
    'PluginConfig',
    'NetworkConfig',
    'DebugConfig',
    'RateLimitConfig',
    'VulnerabilityKBConfig',
    'BypassConfig',
    'IntegrationConfig',
    
    # Utility classes
    'SignalEvent',
    'Tactic',
    'Evidence',
    'ExploitResult',
    'TargetFingerprint',
    'ValidationResult',
    
    # State management
    'UnifiedStateManager',
    'WorkflowState',
    'FeedbackItem'
]

def get_version():
    """Return the current version of CyberShellV2."""
    return __version__

def check_dependencies():
    """Check if all required dependencies are installed."""
    required = [
        'scikit-learn',
        'pandas',
        'numpy',
        'pyyaml',
        'joblib',
        'scipy',
        'streamlit',
        'plotly',
        'requests',
        'beautifulsoup4',
        'aiohttp',  # For async operations
        'cryptography',  # For JWT handling
        'python-dotenv'  # For environment variables
    ]
    
    missing = []
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"⚠️  Missing dependencies: {', '.join(missing)}")
        print(f"   Install with: pip install {' '.join(missing)}")
        return False
    return True

# Initialize logging for the package
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler if none exists
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)

logger.info(f"CyberShellV2 v{__version__} initialized")

# Check dependencies on import
if not check_dependencies():
    logger.warning("Some dependencies are missing. Framework may not function properly.")
