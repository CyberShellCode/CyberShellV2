"""
Unified AI Orchestrator and LLM System
========================================
Combines advanced_ai_orchestrator.py, llm_connectors.py, llm.py, and chat.py
Provides multi-model orchestration, various LLM connectors, and chat interface
"""

import asyncio
import json
import time
import logging
import os
import re
import requests
import hashlib
import numpy as np
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
from enum import Enum

# Set up module logger
logger = logging.getLogger(__name__)

# ============================================================================
# SYSTEM PROMPTS AND HELPERS (from llm.py)
# ============================================================================

SYSTEM_PROMPT = "You are CyberShell's planning co-pilot. Suggest non-destructive, lab-safe analysis steps."

EXPLOITATION_PROMPT = """You are CyberShell's advanced exploitation engine for bug bounty hunting on authorized targets.
Focus on finding and exploiting high-severity vulnerabilities with real business impact.
Always suggest aggressive exploitation techniques and vulnerability chains."""

def build_step_prompt(target: str, recon: Dict[str, Any], 
                     kb_titles: List[str] = None, 
                     miner_summaries: List[str] = None, 
                     mapper_top: List[str] = None) -> str:
    """Build prompt for step suggestions (from llm.py)"""
    parts = [
        f"Target: {target}",
        f"Recon: {recon}",
        f"Top families (mapper): {', '.join(mapper_top) if mapper_top else 'n/a'}",
        "KB titles: " + (", ".join(kb_titles) if kb_titles else "(none)"),
        "Doc summaries:\n" + ("\n".join(miner_summaries) if miner_summaries else "(none)"),
        "Output JSON list of steps; each with: plugin, why, params (no network/exploit)."
    ]
    return "\n".join(parts)

def safe_parse_steps(text: str) -> List[Dict[str, Any]]:
    """Parse LLM output to extract exploitation steps (from llm_connectors.py)"""
    text = text.strip()
    if text.startswith('[') and text.endswith(']'):
        try:
            arr = json.loads(text)
            return arr if isinstance(arr, list) else []
        except Exception:
            return []
    m = re.search(r'\[[\s\S]*\]', text)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
        return arr if isinstance(arr, list) else []
    except Exception:
        return []

# ============================================================================
# DATA CLASSES
# ============================================================================

class ModelCapability(Enum):
    """Capabilities of different AI models"""
    CODE_GENERATION = "code_generation"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    PAYLOAD_CRAFTING = "payload_crafting"
    PATTERN_RECOGNITION = "pattern_recognition"
    STRATEGIC_PLANNING = "strategic_planning"
    REPORT_WRITING = "report_writing"
    REVERSE_ENGINEERING = "reverse_engineering"

@dataclass
class AIModel:
    """Represents an AI model with its capabilities"""
    name: str
    provider: str  # ollama, openai, anthropic, local
    capabilities: List[ModelCapability]
    context_window: int
    cost_per_token: float
    latency_ms: float
    accuracy_score: float
    specializations: List[str]
    connection_params: Dict[str, Any]

@dataclass
class ChatMessage:
    """Chat message (from chat.py)"""
    role: str
    content: str

@dataclass
class ChatSession:
    """Chat session with history (enhanced from chat.py)"""
    history: List[ChatMessage] = field(default_factory=list)
    kb: Optional[Any] = None  # Knowledge base reference
    llm: Optional[Any] = None  # LLM connector
    max_history: int = 100
    
    def ask(self, text: str) -> Dict[str, Any]:
        """Ask a question and get response"""
        self.history.append(ChatMessage('user', text))
        
        # Get KB context if available
        hits = []
        kb_titles = []
        if self.kb and hasattr(self.kb, 'retrieve'):
            hits = self.kb.retrieve(text, k=5)
            kb_titles = [h['item'].title for h in hits]
        
        # Get LLM response
        if self.llm:
            if hasattr(self.llm, 'answer'):
                answer = self.llm.answer(text=text, kb_titles=kb_titles)
            else:
                answer = f"LLM response to: {text}"
        else:
            kb_summary = "Top related: " + ", ".join(kb_titles) if hits else "No related entries."
            answer = kb_summary
        
        self.history.append(ChatMessage('assistant', answer))
        
        # Trim history if too long
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
        
        return {
            'answer': answer,
            'hits': [{'title': t, 'score': h['score']} for t, h in zip(kb_titles, hits)]
        }

# ============================================================================
# BASE LLM CONNECTOR (from llm.py enhanced)
# ============================================================================

class BaseLLMConnector:
    """Base class for all LLM connectors"""
    
    def __init__(self, system_prompt: Optional[str] = None):
        self.system_prompt = system_prompt or SYSTEM_PROMPT
    
    def answer(self, text: str, kb_titles: List[str] = None) -> str:
        """Answer a question"""
        return "LLM disabled. KB: " + (", ".join(kb_titles) if kb_titles else "(none)")
    
    def suggest_steps(self, target: str, recon: Dict[str, Any], 
                     kb_titles: List[str] = None, 
                     miner_summaries: List[str] = None, 
                     mapper_top: List[str] = None) -> List[Dict[str, Any]]:
        """Suggest exploitation steps"""
        return []
    
    def generate_payload(self, vulnerability: str, context: Dict = None) -> str:
        """Generate exploitation payload"""
        return f"PAYLOAD[{vulnerability}]"

# ============================================================================
# OLLAMA CONNECTOR (from llm_connectors.py)
# ============================================================================

class OllamaConnector(BaseLLMConnector):
    """Ollama connector for uncensored exploitation assistance"""
    
    def __init__(self, model: str = "dolphin-mixtral:8x7b", 
                 base_url: str = "http://localhost:11434",
                 temperature: float = 0.7,
                 system_prompt: Optional[str] = None):
        super().__init__(system_prompt or EXPLOITATION_PROMPT)
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
    
    def _query_ollama(self, messages: List[Dict[str, str]]) -> str:
        """Query Ollama API"""
        url = f"{self.base_url}/api/chat"
        
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "top_p": 0.9,
                "top_k": 40,
                "num_predict": 1000
            }
        }
        
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "")
        except Exception as e:
            logger.error(f"Ollama query failed: {e}")
            return ""
    
    def suggest_steps(self, target: str, recon: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        """Generate aggressive exploitation steps"""
        prompt = f"""Target: {target}
Recon: {json.dumps(recon, indent=2)}

Generate 10 exploitation steps for bug bounty hunting.
Focus on critical vulnerabilities (RCE, SQLi, Auth Bypass).
Return ONLY a JSON array of steps."""

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        return safe_parse_steps(response)
    
    def answer(self, text: str, kb_titles: List[str] = None) -> str:
        """Answer exploitation questions"""
        prompt = f"Question: {text}\nKB: {', '.join(kb_titles or [])}"
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt}
        ]
        return self._query_ollama(messages).strip()
    
    def generate_bypass_payload(self, blocked_payload: str, context: str) -> str:
        """Generate WAF bypass payloads"""
        prompt = f"""Blocked payload: {blocked_payload}
Context: {context}

Generate 5 bypass variations using encoding, case variation, etc.
Return only payloads, one per line."""

        messages = [
            {"role": "system", "content": "You are a WAF bypass specialist."},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        payloads = response.strip().split('\n')
        return payloads[0] if payloads else blocked_payload

# ============================================================================
# OPENAI CONNECTOR (from llm_connectors.py)
# ============================================================================

class OpenAIConnector(BaseLLMConnector):
    """OpenAI connector with exploitation focus"""
    
    def __init__(self, model: str = None, temperature: float = 0.7,
                 max_tokens: int = 1000, base_url: str = None,
                 api_key: str = None, system_prompt: str = None):
        super().__init__(system_prompt or EXPLOITATION_PROMPT)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    
    def _chat(self, messages: List[Dict[str, str]]) -> str:
        """Call OpenAI API"""
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "messages": messages
        }
        
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=60)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return ""
    
    def suggest_steps(self, target: str, recon: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        """Generate exploitation steps"""
        prompt = build_step_prompt(target, recon, 
                                 kwargs.get('kb_titles', []),
                                 kwargs.get('miner_summaries', []),
                                 kwargs.get('mapper_top', []))
        
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        response = self._chat(messages)
        return safe_parse_steps(response)
    
    def answer(self, text: str, kb_titles: List[str] = None) -> str:
        """Answer questions"""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Q: {text}\nKB: {', '.join(kb_titles or [])}"}
        ]
        return self._chat(messages).strip()

# ============================================================================
# UNIFIED AI ORCHESTRATOR (from advanced_ai_orchestrator.py)
# ============================================================================

class UnifiedAIOrchestrator:
    """
    Orchestrates multiple AI models for optimal exploitation strategies
    Main interface for all AI/LLM operations
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.models = self._initialize_models()
        self.connectors = self._initialize_connectors()
        self.chat_sessions = {}  # Named chat sessions
        self.response_cache = {}
        self.performance_tracker = PerformanceTracker()
        
        # Get KB and payload manager if available
        self.kb = None
        self.payload_manager = None
        
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            'max_parallel_models': 3,
            'context_compression_ratio': 0.7,
            'cache_ttl_seconds': 3600,
            'ensemble_voting': True,
            'temperature_range': (0.1, 0.9),
            'default_provider': 'ollama',
            'ollama_model': 'dolphin-mixtral:8x7b',
            'ollama_url': 'http://localhost:11434',
            'openai_model': 'gpt-4',
            'openai_api_key': os.getenv('OPENAI_API_KEY'),
        }
    
    def _initialize_models(self) -> Dict[str, AIModel]:
        """Initialize available AI models"""
        return {
            'dolphin-mixtral': AIModel(
                name='dolphin-mixtral:8x7b',
                provider='ollama',
                capabilities=[
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.VULNERABILITY_ANALYSIS,
                    ModelCapability.PAYLOAD_CRAFTING
                ],
                context_window=32768,
                cost_per_token=0.0,
                latency_ms=500,
                accuracy_score=0.85,
                specializations=['web_exploitation', 'code_analysis'],
                connection_params={'base_url': self.config['ollama_url']}
            ),
            'gpt-4': AIModel(
                name='gpt-4',
                provider='openai',
                capabilities=[
                    ModelCapability.STRATEGIC_PLANNING,
                    ModelCapability.PATTERN_RECOGNITION,
                    ModelCapability.REPORT_WRITING
                ],
                context_window=8192,
                cost_per_token=0.03,
                latency_ms=2000,
                accuracy_score=0.92,
                specializations=['reasoning', 'analysis'],
                connection_params={'api_key': self.config.get('openai_api_key')}
            )
        }
    
    def _initialize_connectors(self) -> Dict[str, BaseLLMConnector]:
        """Initialize LLM connectors"""
        connectors = {}
        
        # Ollama connector
        connectors['ollama'] = OllamaConnector(
            model=self.config['ollama_model'],
            base_url=self.config['ollama_url']
        )
        
        # OpenAI connector if API key available
        if self.config.get('openai_api_key'):
            connectors['openai'] = OpenAIConnector(
                model=self.config['openai_model'],
                api_key=self.config['openai_api_key']
        )
        
        return connectors
    
    def get_connector(self, provider: str = None) -> BaseLLMConnector:
        """Get LLM connector by provider"""
        provider = provider or self.config['default_provider']
        return self.connectors.get(provider, BaseLLMConnector())
    
    def create_chat_session(self, name: str = "default", 
                           provider: str = None,
                           kb: Any = None) -> ChatSession:
        """Create or get a named chat session"""
        if name not in self.chat_sessions:
            connector = self.get_connector(provider)
            self.chat_sessions[name] = ChatSession(
                llm=connector,
                kb=kb or self.kb
            )
        return self.chat_sessions[name]
    
    def chat(self, message: str, session_name: str = "default") -> Dict[str, Any]:
        """Simple chat interface"""
        session = self.create_chat_session(session_name)
        return session.ask(message)
    
    async def orchestrate_exploitation(self, target: str,
                                      vulnerability_type: str,
                                      context: Dict) -> Dict:
        """Orchestrate multiple models for exploitation"""
        
        # Select best model for task
        model = self._select_best_model(vulnerability_type)
        connector = self.connectors.get(model.provider)
        
        if not connector:
            return {'success': False, 'error': 'No connector available'}
        
        # Get exploitation steps
        steps = connector.suggest_steps(
            target=target,
            recon=context.get('recon', {}),
            kb_titles=context.get('kb_titles', []),
            mapper_top=context.get('mapper_top', [])
        )
        
        return {
            'success': True,
            'exploitation_steps': steps,
            'model_used': model.name,
            'confidence': 0.85
        }
    
    def _select_best_model(self, task: str) -> AIModel:
        """Select best model for task"""
        # Map task to capability
        capability_map = {
            'XSS': ModelCapability.PAYLOAD_CRAFTING,
            'SQLI': ModelCapability.PAYLOAD_CRAFTING,
            'RCE': ModelCapability.CODE_GENERATION,
            'ANALYSIS': ModelCapability.VULNERABILITY_ANALYSIS
        }
        
        needed_capability = capability_map.get(task.upper(), ModelCapability.VULNERABILITY_ANALYSIS)
        
        # Find models with capability
        suitable_models = [
            model for model in self.models.values()
            if needed_capability in model.capabilities
        ]
        
        # Return best by accuracy
        if suitable_models:
            return max(suitable_models, key=lambda m: m.accuracy_score)
        
        # Fallback to first model
        return list(self.models.values())[0]
    
    async def generate_adaptive_payload(self, vulnerability: str,
                                       target_response: str,
                                       previous_attempts: List[Dict]) -> Dict:
        """Generate adaptive payload based on previous attempts"""
        
        connector = self.get_connector()
        
        # Build context from attempts
        context = f"""Vulnerability: {vulnerability}
Target Response: {target_response[:500]}
Previous Attempts: {len(previous_attempts)}
Failed Patterns: {[a['payload'][:50] for a in previous_attempts if not a.get('success')]}

Generate an adaptive payload that bypasses the observed filters."""
        
        # Get payload suggestion
        if hasattr(connector, 'generate_bypass_payload'):
            last_payload = previous_attempts[-1]['payload'] if previous_attempts else ""
            payload = connector.generate_bypass_payload(last_payload, context)
        else:
            payload = connector.generate_payload(vulnerability, {'context': context})
        
        return {
            'payload': payload,
            'technique': 'adaptive_bypass',
            'confidence': 0.7,
            'model_used': self.config['default_provider']
        }
    
    def suggest_exploitation_steps(self, target: str, recon_data: Dict) -> List[Dict]:
        """Get exploitation steps from default connector"""
        connector = self.get_connector()
        return connector.suggest_steps(target, recon_data)
    
    def analyze_vulnerability(self, vulnerability_data: Dict) -> str:
        """Analyze vulnerability using AI"""
        connector = self.get_connector()
        
        prompt = f"""Analyze this vulnerability:
Type: {vulnerability_data.get('type')}
Endpoint: {vulnerability_data.get('endpoint')}
Evidence: {vulnerability_data.get('evidence')}

Provide:
1. Severity assessment
2. Exploitation approach
3. Business impact
4. Remediation steps"""
        
        return connector.answer(prompt)
    
    def get_performance_report(self) -> Dict:
        """Get AI performance report"""
        return self.performance_tracker.get_report()

# ============================================================================
# PERFORMANCE TRACKER
# ============================================================================

class PerformanceTracker:
    """Tracks AI/LLM performance"""
    
    def __init__(self):
        self.executions = []
        self.model_stats = {}
    
    def record_execution(self, model: str, task: str, 
                        success: bool, latency: float):
        """Record execution metrics"""
        self.executions.append({
            'timestamp': datetime.now(),
            'model': model,
            'task': task,
            'success': success,
            'latency': latency
        })
        
        if model not in self.model_stats:
            self.model_stats[model] = {
                'executions': 0,
                'successes': 0,
                'total_latency': 0
            }
        
        stats = self.model_stats[model]
        stats['executions'] += 1
        if success:
            stats['successes'] += 1
        stats['total_latency'] += latency
    
    def get_report(self) -> Dict:
        """Generate performance report"""
        if not self.executions:
            return {'message': 'No executions recorded'}
        
        return {
            'total_executions': len(self.executions),
            'success_rate': sum(1 for e in self.executions if e['success']) / len(self.executions),
            'model_performance': {
                model: {
                    'success_rate': stats['successes'] / stats['executions'] if stats['executions'] > 0 else 0,
                    'avg_latency': stats['total_latency'] / stats['executions'] if stats['executions'] > 0 else 0,
                    'usage_count': stats['executions']
                }
                for model, stats in self.model_stats.items()
            }
        }

# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

# Aliases for backward compatibility
AdvancedAIOrchestrator = UnifiedAIOrchestrator
LLMConnector = BaseLLMConnector
OpenAIChatConnector = OpenAIConnector

# Legacy connector initialization
class OpenAICompatibleHTTPConnector(BaseLLMConnector):
    """Generic OpenAI-compatible API connector (backward compat)"""
    
    def __init__(self, config: Dict = None, **kwargs):
        super().__init__()
        self.connector = OpenAIConnector(**kwargs) if kwargs else OpenAIConnector()
    
    def suggest_steps(self, target: str, recon: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        return self.connector.suggest_steps(target, recon, **kwargs)
    
    def answer(self, text: str, kb_titles: List[str] = None) -> str:
        return self.connector.answer(text, kb_titles)
