"""
Unified Plugin Runtime for CyberShell
Handles plugin discovery, loading, registration, and execution
"""

import importlib.util
import sys
import inspect
import traceback
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, Type, List, Optional, Callable, Union
from enum import Enum
import logging
import hashlib
import json
from datetime import datetime


# ========== Plugin Result & Metadata ==========

@dataclass
class PluginResult:
    """Standard result format for all plugins"""
    name: str
    success: bool
    details: Dict[str, Any]
    evidence_score: float = 0.0  # 0.0 to 1.0 confidence
    severity: Optional[str] = None  # Critical, High, Medium, Low, Info
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None
    execution_time: float = 0.0  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'success': self.success,
            'details': self.details,
            'evidence_score': self.evidence_score,
            'severity': self.severity,
            'timestamp': self.timestamp,
            'error': self.error,
            'execution_time': self.execution_time
        }


class PluginCapability(Enum):
    """Plugin capability categories"""
    RECON = "recon"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"
    REPORTING = "reporting"
    VALIDATION = "validation"
    BYPASS = "bypass"


@dataclass
class PluginMetadata:
    """Metadata about a plugin"""
    name: str
    version: str = "1.0.0"
    author: str = "anonymous"
    description: str = ""
    capabilities: List[PluginCapability] = field(default_factory=list)
    safe_mode_compatible: bool = True
    requires_auth: bool = False
    requires_session: bool = False
    risk_level: str = "low"  # low, medium, high, critical
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'capabilities': [c.value for c in self.capabilities],
            'safe_mode_compatible': self.safe_mode_compatible,
            'requires_auth': self.requires_auth,
            'requires_session': self.requires_session,
            'risk_level': self.risk_level,
            'tags': self.tags
        }


# ========== Base Plugin Classes ==========

class PluginBase:
    """Base class for all plugins"""
    
    # Class-level metadata
    metadata = PluginMetadata(name="PluginBase")
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize plugin with configuration"""
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self._execution_history = []
        self._last_result = None
        
    def in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        scope_hosts = self.config.get('scope_hosts', [])
        if not scope_hosts:
            return True  # No scope defined, allow all
            
        from urllib.parse import urlparse
        parsed = urlparse(target if '://' in target else f'http://{target}')
        hostname = parsed.hostname or parsed.path
        
        for scope_host in scope_hosts:
            if scope_host.startswith('*.'):
                # Wildcard domain
                if hostname.endswith(scope_host[2:]):
                    return True
            elif hostname == scope_host or target.startswith(scope_host):
                return True
                
        return False
    
    def validate_input(self, **kwargs) -> bool:
        """Validate plugin input parameters"""
        required = self.get_required_params()
        for param in required:
            if param not in kwargs:
                self.logger.error(f"Missing required parameter: {param}")
                return False
        return True
    
    def get_required_params(self) -> List[str]:
        """Get list of required parameters"""
        return []
    
    def pre_run(self, **kwargs) -> bool:
        """Pre-execution hook"""
        if not self.validate_input(**kwargs):
            return False
        
        target = kwargs.get('target', '')
        if target and not self.in_scope(target):
            self.logger.warning(f"Target {target} is out of scope")
            return False
            
        return True
    
    def run(self, **kwargs) -> PluginResult:
        """Main plugin execution - must be overridden"""
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")
    
    def post_run(self, result: PluginResult) -> PluginResult:
        """Post-execution hook"""
        self._last_result = result
        self._execution_history.append({
            'timestamp': result.timestamp,
            'success': result.success,
            'evidence_score': result.evidence_score
        })
        return result
    
    def execute(self, **kwargs) -> PluginResult:
        """Execute plugin with full lifecycle"""
        import time
        start_time = time.time()
        
        try:
            # Pre-run checks
            if not self.pre_run(**kwargs):
                return PluginResult(
                    name=self.__class__.__name__,
                    success=False,
                    details={'error': 'Pre-run validation failed'},
                    error='Validation failed'
                )
            
            # Execute main logic
            result = self.run(**kwargs)
            
            # Post-run processing
            result = self.post_run(result)
            
        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}")
            result = PluginResult(
                name=self.__class__.__name__,
                success=False,
                details={'exception': str(e)},
                error=traceback.format_exc()
            )
        
        result.execution_time = time.time() - start_time
        return result
    
    def get_capabilities(self) -> List[PluginCapability]:
        """Get plugin capabilities"""
        return self.metadata.capabilities
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata"""
        return self.metadata
    
    def get_history(self) -> List[Dict]:
        """Get execution history"""
        return self._execution_history
    
    def get_last_result(self) -> Optional[PluginResult]:
        """Get last execution result"""
        return self._last_result


# ========== Built-in Safe Plugins ==========

class HttpFingerprintPlugin(PluginBase):
    """Safe HTTP fingerprinting plugin"""
    
    metadata = PluginMetadata(
        name="HttpFingerprintPlugin",
        description="Fingerprint HTTP services safely",
        capabilities=[PluginCapability.RECON],
        safe_mode_compatible=True,
        risk_level="low"
    )
    
    def get_required_params(self) -> List[str]:
        return ['target']
    
    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get('target', '')
        
        # Simulated safe fingerprinting (no actual network calls in safe mode)
        if self.config.get('safe_mode', True):
            return PluginResult(
                name=self.metadata.name,
                success=True,
                details={
                    'target': target,
                    'headers': {'server': 'nginx/1.18.0'},
                    'technologies': ['PHP', 'MySQL', 'jQuery'],
                    'fingerprint': 'SAFE_MODE_SIMULATION'
                },
                evidence_score=0.0
            )
        
        # Real fingerprinting would go here
        return PluginResult(
            name=self.metadata.name,
            success=False,
            details={'error': 'Real fingerprinting not implemented'}
        )


class FormDiscoveryPlugin(PluginBase):
    """Discover HTML forms"""
    
    metadata = PluginMetadata(
        name="FormDiscoveryPlugin",
        description="Discover and analyze HTML forms",
        capabilities=[PluginCapability.RECON],
        safe_mode_compatible=True,
        risk_level="low"
    )
    
    def get_required_params(self) -> List[str]:
        return ['target']
    
    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get('target', '')
        
        # Simulated form discovery
        forms = [
            {
                'action': '/login',
                'method': 'POST',
                'inputs': ['username', 'password', 'csrf_token']
            },
            {
                'action': '/search',
                'method': 'GET',
                'inputs': ['query', 'category']
            }
        ]
        
        return PluginResult(
            name=self.metadata.name,
            success=True,
            details={
                'target': target,
                'forms_found': len(forms),
                'forms': forms
            },
            evidence_score=0.3
        )


class HeuristicAnalyzerPlugin(PluginBase):
    """Heuristic vulnerability analysis"""
    
    metadata = PluginMetadata(
        name="HeuristicAnalyzerPlugin",
        description="Perform heuristic vulnerability analysis",
        capabilities=[PluginCapability.RECON, PluginCapability.VALIDATION],
        safe_mode_compatible=True,
        risk_level="low"
    )
    
    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get('target', '')
        hints = kwargs.get('hints', [])
        
        # Simulated heuristic analysis
        vulnerabilities = []
        
        if 'id=' in target or 'user=' in target:
            vulnerabilities.append({
                'type': 'potential_sqli',
                'confidence': 0.4,
                'location': 'query_parameter'
            })
        
        if '<script>' in str(hints):
            vulnerabilities.append({
                'type': 'potential_xss',
                'confidence': 0.5,
                'location': 'user_input'
            })
        
        return PluginResult(
            name=self.metadata.name,
            success=len(vulnerabilities) > 0,
            details={
                'target': target,
                'vulnerabilities': vulnerabilities,
                'heuristics_applied': ['parameter_analysis', 'pattern_matching']
            },
            evidence_score=0.3 if vulnerabilities else 0.0
        )


# ========== Plugin Registry & Loader ==========

class PluginRegistry:
    """Central registry for all plugins"""
    
    def __init__(self):
        self._plugins: Dict[str, Type[PluginBase]] = {}
        self._instances: Dict[str, PluginBase] = {}
        self._metadata: Dict[str, PluginMetadata] = {}
        self._capabilities_map: Dict[PluginCapability, List[str]] = {
            cap: [] for cap in PluginCapability
        }
        self.logger = logging.getLogger('PluginRegistry')
        
        # Register built-in plugins
        self._register_builtins()
    
    def _register_builtins(self):
        """Register built-in safe plugins"""
        builtins = [
            HttpFingerprintPlugin,
            FormDiscoveryPlugin,
            HeuristicAnalyzerPlugin
        ]
        
        for plugin_class in builtins:
            self.register(plugin_class)
    
    def register(self, plugin_class: Type[PluginBase]) -> bool:
        """Register a plugin class"""
        try:
            if not issubclass(plugin_class, PluginBase):
                self.logger.error(f"{plugin_class} is not a PluginBase subclass")
                return False
            
            name = plugin_class.__name__
            
            # Store class and metadata
            self._plugins[name] = plugin_class
            
            # Extract metadata
            if hasattr(plugin_class, 'metadata'):
                metadata = plugin_class.metadata
            else:
                metadata = PluginMetadata(name=name)
            
            self._metadata[name] = metadata
            
            # Update capabilities map
            for cap in metadata.capabilities:
                self._capabilities_map[cap].append(name)
            
            self.logger.info(f"Registered plugin: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register plugin: {e}")
            return False
    
    def load_from_file(self, file_path: Path) -> int:
        """Load plugins from a Python file"""
        count = 0
        
        try:
            # Create module spec from file
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if not spec or not spec.loader:
                self.logger.error(f"Failed to create spec for {file_path}")
                return 0
            
            # Load module
            module = importlib.util.module_from_spec(spec)
            sys.modules[file_path.stem] = module
            spec.loader.exec_module(module)
            
            # Find and register plugin classes
            for name in dir(module):
                obj = getattr(module, name)
                
                if (inspect.isclass(obj) and 
                    issubclass(obj, PluginBase) and 
                    obj is not PluginBase):
                    
                    if self.register(obj):
                        count += 1
            
            self.logger.info(f"Loaded {count} plugins from {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load plugins from {file_path}: {e}")
        
        return count
    
    def load_from_directory(self, dir_path: str) -> int:
        """Load all plugins from a directory"""
        total = 0
        base = Path(dir_path)
        
        if not base.exists():
            self.logger.warning(f"Plugin directory does not exist: {dir_path}")
            return 0
        
        # Find all Python files
        for py_file in base.rglob('*.py'):
            if py_file.name.startswith('_'):
                continue  # Skip private modules
            
            count = self.load_from_file(py_file)
            total += count
        
        self.logger.info(f"Loaded {total} plugins from {dir_path}")
        return total
    
    def create_instance(self, plugin_name: str, config: Optional[Dict] = None) -> Optional[PluginBase]:
        """Create an instance of a plugin"""
        if plugin_name not in self._plugins:
            self.logger.error(f"Plugin not found: {plugin_name}")
            return None
        
        try:
            plugin_class = self._plugins[plugin_name]
            instance = plugin_class(config=config)
            self._instances[plugin_name] = instance
            return instance
            
        except Exception as e:
            self.logger.error(f"Failed to create instance of {plugin_name}: {e}")
            return None
    
    def get_instance(self, plugin_name: str) -> Optional[PluginBase]:
        """Get existing instance or create new one"""
        if plugin_name in self._instances:
            return self._instances[plugin_name]
        return self.create_instance(plugin_name)
    
    def execute_plugin(self, plugin_name: str, **kwargs) -> Optional[PluginResult]:
        """Execute a plugin by name"""
        instance = self.get_instance(plugin_name)
        if not instance:
            return None
        
        return instance.execute(**kwargs)
    
    def get_plugins_by_capability(self, capability: PluginCapability) -> List[str]:
        """Get plugins with a specific capability"""
        return self._capabilities_map.get(capability, [])
    
    def get_safe_plugins(self) -> List[str]:
        """Get all safe-mode compatible plugins"""
        safe = []
        for name, metadata in self._metadata.items():
            if metadata.safe_mode_compatible:
                safe.append(name)
        return safe
    
    def get_plugin_metadata(self, plugin_name: str) -> Optional[PluginMetadata]:
        """Get metadata for a plugin"""
        return self._metadata.get(plugin_name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all registered plugins with metadata"""
        plugins = []
        for name in self._plugins:
            metadata = self._metadata.get(name)
            plugins.append({
                'name': name,
                'metadata': metadata.to_dict() if metadata else None,
                'loaded': name in self._instances
            })
        return plugins
    
    def get_plugin_chain(self, capabilities: List[PluginCapability]) -> List[str]:
        """Get a chain of plugins for a sequence of capabilities"""
        chain = []
        for cap in capabilities:
            plugins = self.get_plugins_by_capability(cap)
            if plugins:
                # Select best plugin for capability (could be enhanced with scoring)
                chain.append(plugins[0])
        return chain
    
    def execute_chain(self, chain: List[str], initial_context: Dict[str, Any]) -> List[PluginResult]:
        """Execute a chain of plugins"""
        results = []
        context = initial_context.copy()
        
        for plugin_name in chain:
            result = self.execute_plugin(plugin_name, **context)
            if result:
                results.append(result)
                
                # Update context with results for next plugin
                if result.success and result.details:
                    context.update(result.details)
                else:
                    # Chain broken
                    break
        
        return results
    
    def validate_plugin_file(self, file_path: Path) -> Dict[str, Any]:
        """Validate a plugin file without loading it"""
        validation = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'plugin_count': 0
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Basic validation
            if 'PluginBase' not in content:
                validation['warnings'].append('No PluginBase import detected')
            
            if 'def run(' not in content:
                validation['warnings'].append('No run() method detected')
            
            # Check for dangerous operations
            dangerous = ['eval(', 'exec(', '__import__', 'compile(']
            for danger in dangerous:
                if danger in content:
                    validation['warnings'].append(f'Potentially dangerous operation: {danger}')
            
            # Count potential plugin classes
            import re
            class_pattern = r'class\s+(\w+)\s*\([^)]*PluginBase[^)]*\)'
            matches = re.findall(class_pattern, content)
            validation['plugin_count'] = len(matches)
            
            validation['valid'] = validation['plugin_count'] > 0
            
        except Exception as e:
            validation['errors'].append(str(e))
        
        return validation


# ========== Convenience Functions ==========

def create_plugin_runtime(config: Optional[Dict] = None) -> PluginRegistry:
    """Create and configure plugin runtime"""
    runtime = PluginRegistry()
    
    # Load user plugins if directory specified
    if config and 'plugins_dir' in config:
        runtime.load_from_directory(config['plugins_dir'])
    
    return runtime


def load_user_plugins(dir_path: str, config: Optional[Dict] = None) -> Dict[str, Type[PluginBase]]:
    """Legacy function - load plugins from directory"""
    registry = PluginRegistry()
    registry.load_from_directory(dir_path)
    
    # Return dictionary of plugin classes for compatibility
    return registry._plugins.copy()


# Plugin development helpers
def create_plugin_template(name: str, capabilities: List[str]) -> str:
    """Generate a plugin template"""
    cap_enums = [f"PluginCapability.{c.upper()}" for c in capabilities]
    
    template = f'''"""
{name} Plugin
Generated plugin template
"""

from typing import Dict, Any, List
from cybershell.plugin_runtime import PluginBase, PluginResult, PluginMetadata, PluginCapability


class {name}(PluginBase):
    """
    TODO: Add description
    """
    
    metadata = PluginMetadata(
        name="{name}",
        description="TODO: Add description",
        capabilities=[{', '.join(cap_enums)}],
        safe_mode_compatible=False,
        risk_level="medium",
        tags=[]
    )
    
    def get_required_params(self) -> List[str]:
        """Define required parameters"""
        return ['target']
    
    def run(self, **kwargs) -> PluginResult:
        """Main plugin logic"""
        target = kwargs.get('target', '')
        
        # TODO: Implement plugin logic
        
        return PluginResult(
            name=self.metadata.name,
            success=True,
            details={{
                'target': target,
                # Add your results here
            }},
            evidence_score=0.0,
            severity="Info"
        )
'''
    
    return template
