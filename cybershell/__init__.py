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
from . import plugins
from . import scoring
from . import strategies
from . import unified_config
from . import llm_connectors
from . import reporting
from . import plugin_loader

# Security and bypass modules
from . import vulnerability_kb
from . import bypass_techniques
from . import rate_limiter

# Enhancement modules (AI/ML)
from . import continuous_learning_pipeline
from . import business_impact_reporter
from . import benchmarking_framework
from . import advanced_ai_orchestrator
from . import autonomous_orchestration_engine
from . import validation_framework

# Adaptive learning submodule
from . import adaptive

# Legacy config redirect (if still needed)
try:
    from . import config
except ImportError:
    pass  # Legacy config might not exist

# Main orchestrator class for convenience
from .orchestrator import CyberShell

# Plugin base classes
from .plugins import PluginBase, PluginResult

# Configuration classes
from .unified_config import (
    UnifiedConfig,
    SafetyConfig,
    BountyConfig,
    ExploitationConfig,
    LLMConfig,
    LearningConfig
)

__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__license__',
    
    # Core modules
    'orchestrator',
    'agent',
    'plugins',
    'scoring',
    'strategies',
    'unified_config',
    'config',  # Legacy, redirects to unified_config
    'llm_connectors',
    'reporting',
    'plugin_loader',
    
    # Security and bypass modules
    'vulnerability_kb',
    'bypass_techniques',
    'rate_limiter',
    
    # Enhancement modules (AI/ML)
    'continuous_learning_pipeline',
    'business_impact_reporter',
    'benchmarking_framework',
    'advanced_ai_orchestrator',
    'autonomous_orchestration_engine',
    'validation_framework',
    
    # Adaptive learning submodule
    'adaptive',
    
    # Main classes exported for convenience
    'CyberShell',
    'PluginBase',
    'PluginResult',
    'UnifiedConfig',
    'SafetyConfig',
    'BountyConfig',
    'ExploitationConfig',
    'LLMConfig',
    'LearningConfig'
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
        'beautifulsoup4'
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
