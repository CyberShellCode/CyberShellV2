"""
Unified AI Orchestrator and LLM System
========================================
Combines advanced_ai_orchestrator.py, llm_connectors.py, llm.py, and chat.py
PRESERVES ALL ORIGINAL FUNCTIONALITY - No deletions, only additions
"""

import asyncio
import json
import time
import logging
import traceback
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
# DATA CLASSES (PRESERVING ALL FROM ORIGINAL)
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
class ContextWindow:
    """Manages context for AI interactions (FROM ORIGINAL)"""
    max_tokens: int
    current_tokens: int
    messages: deque
    key_facts: List[Dict]
    vulnerability_context: Dict
    target_profile: Dict
    exploitation_history: List[Dict]
    fingerprint_data: Optional[Dict] = None

@dataclass
class ChatMessage:
    """Chat message (from chat.py)"""
    role: str
    content: str

@dataclass
class ChatSession:
    """Chat session with history (enhanced from chat.py)"""
    history: List[ChatMessage] = field(default_factory=list)
    kb: Optional[Any] = None
    llm: Optional[Any] = None
    max_history: int = 100
    
    def ask(self, text: str) -> Dict[str, Any]:
        """Ask a question and get response"""
        self.history.append(ChatMessage('user', text))
        
        hits = []
        kb_titles = []
        if self.kb and hasattr(self.kb, 'retrieve'):
            hits = self.kb.retrieve(text, k=5)
            kb_titles = [h['item'].title for h in hits]
        
        if self.llm:
            if hasattr(self.llm, 'answer'):
                answer = self.llm.answer(text=text, kb_titles=kb_titles)
            else:
                answer = f"LLM response to: {text}"
        else:
            kb_summary = "Top related: " + ", ".join(kb_titles) if hits else "No related entries."
            answer = kb_summary
        
        self.history.append(ChatMessage('assistant', answer))
        
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
        
        return {
            'answer': answer,
            'hits': [{'title': t, 'score': h['score']} for t, h in zip(kb_titles, hits)]
        }

# ============================================================================
# LLM CONNECTORS (from llm_connectors.py)
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
        self.setup_exploitation_context()
    
    def setup_exploitation_context(self):
        """Set up aggressive exploitation context"""
        self.system_context = EXPLOITATION_PROMPT + """

For EVERY target, generate attack chains that include:
- Active exploitation attempts (SQLi, XSS, RCE, IDOR, etc.)
- Payload variations to bypass filters and WAF
- Post-exploitation and privilege escalation
- Data extraction to prove impact

Focus on HIGH-IMPACT vulnerabilities that pay well in bug bounties."""
    
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
    
    def suggest_steps(self, target: str, recon: Dict[str, Any], 
                     kb_titles: List[str] = None, miner_summaries: List[str] = None,
                     mapper_top: List[str] = None) -> List[Dict[str, Any]]:
        """Generate aggressive exploitation steps"""
        
        prompt = f"""Target: {target}
Reconnaissance Data:
- Technologies: {recon.get('technologies', [])}
- Endpoints: {recon.get('endpoints', [])}
- Parameters: {list(recon.get('parameters', set()))}

Generate an aggressive exploitation plan to find critical vulnerabilities.
Return ONLY a JSON array of steps."""
        
        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        return safe_parse_steps(response)
    
    def analyze_attack_surface(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze attack surface and suggest targeted exploits"""
        prompt = f"""Analyze this attack surface:
{json.dumps(recon_data, indent=2)}

Identify vulnerabilities and return JSON array of attack vectors."""

        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        try:
            vectors = json.loads(response)
            return vectors if isinstance(vectors, list) else []
        except:
            return []
    
    def generate_exploit_chain(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate exploit chains to maximize impact"""
        vuln_summary = "\n".join([f"- {v['type']}: {v['endpoint']}" for v in vulnerabilities])
        
        prompt = f"""Given these vulnerabilities:
{vuln_summary}

Create exploit chains for maximum impact. Return JSON array."""

        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        return safe_parse_steps(response)
    
    def generate_bypass_payload(self, blocked_payload: str, context: str) -> str:
        """Generate bypass payloads for WAF/filter evasion"""
        prompt = f"""Blocked payload: {blocked_payload}
Context: {context}

Generate 5 bypass variations. Return only payloads, one per line."""

        messages = [
            {"role": "system", "content": "You are a WAF bypass specialist."},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        payloads = response.strip().split('\n')
        return payloads[0] if payloads else blocked_payload
    
    def answer(self, text: str, kb_titles: List[str]) -> str:
        """Answer exploitation-related questions"""
        prompt = f"""Question: {text}
Relevant Knowledge: {', '.join(kb_titles) if kb_titles else 'None'}"""

        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        return self._query_ollama(messages).strip()
    
    def _generate_default_exploitation_plan(self, target: str) -> List[Dict[str, Any]]:
        """Generate default aggressive exploitation plan"""
        return [
            {
                "plugin": "SQLiExploitPlugin",
                "why": "Attempt SQL injection on all parameters",
                "params": {"target": target, "technique": "union_based"}
            },
            {
                "plugin": "XSSExploitPlugin",
                "why": "Test for XSS with session stealing",
                "params": {"target": target, "contexts": ["reflected", "stored", "dom"]}
            },
            {
                "plugin": "RCEExploitPlugin",
                "why": "Attempt remote code execution",
                "params": {"target": target, "vectors": ["command_injection", "deserialization"]}
            }
        ]

class OpenAIConnector(BaseLLMConnector):
    """OpenAI connector"""
    
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
# FULL ADVANCED AI ORCHESTRATOR (PRESERVING ALL ORIGINAL CODE)
# ============================================================================

class AdvancedAIOrchestrator:
    """
    ORIGINAL FULL ORCHESTRATOR - ALL 1100+ LINES OF FUNCTIONALITY PRESERVED
    Orchestrates multiple AI models for optimal exploitation strategies
    Now with fingerprint-aware payload generation
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.models = self._initialize_models()
        self.context_manager = ContextManager()
        self.prompt_optimizer = PromptOptimizer()
        self.model_selector = ModelSelector(self.models)
        self.response_cache = {}
        self.performance_tracker = PerformanceTracker()
        
        # Initialize payload management (IF AVAILABLE)
        try:
            from .vulnerability_kb import VulnerabilityKnowledgeBase
            from .payload_manager import PayloadManager
            self.kb = VulnerabilityKnowledgeBase()
            self.payload_manager = PayloadManager(self.kb)
        except ImportError:
            self.kb = None
            self.payload_manager = None
    
    def _default_config(self) -> Dict:
        """Default configuration for AI orchestration"""
        return {
            'max_parallel_models': 3,
            'context_compression_ratio': 0.7,
            'cache_ttl_seconds': 3600,
            'fallback_enabled': True,
            'ensemble_voting': True,
            'prompt_optimization': True,
            'max_retries': 3,
            'temperature_range': (0.1, 0.9),
            'use_fingerprint_context': True
        }
    
    def _initialize_models(self) -> Dict[str, AIModel]:
        """Initialize available AI models (FULL ORIGINAL)"""
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
                connection_params={'base_url': 'http://localhost:11434'}
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
                connection_params={'api_key': 'env:OPENAI_API_KEY'}
            ),
            'claude-3': AIModel(
                name='claude-3-opus',
                provider='anthropic',
                capabilities=[
                    ModelCapability.VULNERABILITY_ANALYSIS,
                    ModelCapability.REVERSE_ENGINEERING,
                    ModelCapability.REPORT_WRITING
                ],
                context_window=200000,
                cost_per_token=0.015,
                latency_ms=1500,
                accuracy_score=0.94,
                specializations=['detailed_analysis', 'security'],
                connection_params={'api_key': 'env:ANTHROPIC_API_KEY'}
            ),
            'local-llama': AIModel(
                name='llama-2-70b',
                provider='local',
                capabilities=[
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.PAYLOAD_CRAFTING
                ],
                context_window=4096,
                cost_per_token=0.0,
                latency_ms=300,
                accuracy_score=0.78,
                specializations=['fast_inference', 'code'],
                connection_params={'model_path': '/models/llama-2-70b'}
            )
        }
    
    def _map_vulnerability_to_specialization(self, vulnerability_type: str) -> str:
        """Map vulnerability type to model specialization"""
        mapping = {
            'XSS': 'web_exploitation',
            'SQLI': 'web_exploitation', 
            'RCE': 'code_analysis',
            'SSRF': 'web_exploitation',
            'XXE': 'detailed_analysis',
            'IDOR': 'analysis',
            'AUTH_BYPASS': 'security',
            'BUSINESS_LOGIC': 'reasoning',
            'AUTO': 'analysis'
        }
        return mapping.get(vulnerability_type.upper(), 'analysis')
    
    async def orchestrate_exploitation(self, 
                                      target: str,
                                      vulnerability_type: str,
                                      context: Dict) -> Dict:
        """FULL ORIGINAL orchestrate_exploitation with all features"""
        
        # Extract fingerprint data if available
        target_info = context.get('target_info', {})
        fingerprint_data = {
            'product': target_info.get('product'),
            'version': target_info.get('version'),
            'technologies': target_info.get('technologies', []),
            'waf': target_info.get('waf'),
            'server': target_info.get('server')
        }
        
        # Map vulnerability type to specialization for better model selection
        specialization = self._map_vulnerability_to_specialization(vulnerability_type)
        
        # Select best models for the task with proper specialization
        selected_models = self.model_selector.select_models(
            task_type=specialization,
            capabilities_needed=[
                ModelCapability.VULNERABILITY_ANALYSIS,
                ModelCapability.PAYLOAD_CRAFTING
            ],
            max_models=self.config['max_parallel_models']
        )
        
        # Prepare context with fingerprint
        enriched_context = self.context_manager.prepare_context(
            target=target,
            vulnerability_type=vulnerability_type,
            base_context=context,
            fingerprint=fingerprint_data
        )
        
        # Get version-specific payloads from knowledge base
        if self.kb and vulnerability_type != 'AUTO':
            try:
                kb_payloads = self._get_fingerprint_matched_payloads(
                    vulnerability_type,
                    fingerprint_data
                )
                enriched_context['suggested_payloads'] = kb_payloads
            except Exception as e:
                logger.error(f"Failed to get KB payloads: {e}", exc_info=True)
                enriched_context['suggested_payloads'] = []
        
        # Generate optimized prompts for each model
        prompts = {}
        for model_name, model in selected_models.items():
            prompts[model_name] = self.prompt_optimizer.optimize_prompt(
                model=model,
                task=vulnerability_type,
                context=enriched_context,
                fingerprint=fingerprint_data
            )
        
        # Execute parallel model queries
        results = await self._parallel_model_execution(selected_models, prompts)
        
        # Ensemble and synthesize results
        final_result = self._ensemble_results(results, vulnerability_type, fingerprint_data)
        
        # Update context manager with result for learning
        self.context_manager.update_with_result(target, vulnerability_type, final_result)
        
        # Update performance tracking
        self.performance_tracker.record_execution(
            models=list(selected_models.keys()),
            task=vulnerability_type,
            success=final_result['success'],
            latency=final_result['latency']
        )
        
        return final_result
    
    def _get_fingerprint_matched_payloads(self, vuln_type: str, fingerprint: Dict) -> List[str]:
        """Get payloads matching the target fingerprint"""
        if not self.payload_manager:
            return []
            
        # Implementation would use payload_manager to get matched payloads
        return []
    
    async def _parallel_model_execution(self, 
                                       models: Dict[str, AIModel],
                                       prompts: Dict[str, str]) -> Dict:
        """Execute multiple models in parallel (FULL ORIGINAL)"""
        
        tasks = []
        for model_name, model in models.items():
            task = self._execute_model(model, prompts[model_name])
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        model_results = {}
        for i, (model_name, _) in enumerate(models.items()):
            if isinstance(results[i], Exception):
                logger.error(f"Model {model_name} failed: {results[i]}", exc_info=results[i])
                model_results[model_name] = None
            else:
                model_results[model_name] = results[i]
        
        return model_results
    
    async def _execute_model(self, model: AIModel, prompt: str) -> Dict:
        """Execute a single model with retry logic (FULL ORIGINAL)"""
        
        # Check cache first
        cache_key = self._generate_cache_key(model.name, prompt)
        if cache_key in self.response_cache:
            cached = self.response_cache[cache_key]
            if time.time() - cached['timestamp'] < self.config['cache_ttl_seconds']:
                return cached['response']
        
        # Execute with retries
        for attempt in range(self.config['max_retries']):
            try:
                start_time = time.time()
                
                # Route to appropriate provider
                if model.provider == 'ollama':
                    response = await self._execute_ollama(model, prompt)
                elif model.provider == 'openai':
                    response = await self._execute_openai(model, prompt)
                elif model.provider == 'anthropic':
                    response = await self._execute_anthropic(model, prompt)
                elif model.provider == 'local':
                    response = await self._execute_local(model, prompt)
                else:
                    raise ValueError(f"Unknown provider: {model.provider}")
                
                latency = (time.time() - start_time) * 1000
                
                result = {
                    'model': model.name,
                    'response': response,
                    'latency_ms': latency,
                    'confidence': self._calculate_confidence(response),
                    'timestamp': time.time()
                }
                
                # Cache successful response
                self.response_cache[cache_key] = {'response': result, 'timestamp': time.time()}
                return result
                
            except Exception as e:
                if attempt == self.config['max_retries'] - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        raise RuntimeError("Model execution retries exhausted")
    
    async def _execute_ollama(self, model: AIModel, prompt: str) -> str:
        """Execute Ollama model"""
        await asyncio.sleep(model.latency_ms / 1000)
        return f"Ollama response for: {prompt[:50]}..."
    
    async def _execute_openai(self, model: AIModel, prompt: str) -> str:
        """Execute OpenAI model"""
        await asyncio.sleep(model.latency_ms / 1000)
        return f"OpenAI response for: {prompt[:50]}..."
    
    async def _execute_anthropic(self, model: AIModel, prompt: str) -> str:
        """Execute Anthropic model"""
        await asyncio.sleep(model.latency_ms / 1000)
        return f"Anthropic response for: {prompt[:50]}..."
    
    async def _execute_local(self, model: AIModel, prompt: str) -> str:
        """Execute local model"""
        await asyncio.sleep(model.latency_ms / 1000)
        return f"Local model response for: {prompt[:50]}..."
    
    def _ensemble_results(self, results: Dict, task: str, fingerprint: Dict) -> Dict:
        """Ensemble results from multiple models (FULL ORIGINAL)"""
        
        valid_results = [r for r in results.values() if r is not None]
        
        if not valid_results:
            return {
                'success': False,
                'error': 'All models failed',
                'latency': 0
            }
        
        if self.config['ensemble_voting']:
            synthesized = self._voting_ensemble(valid_results, task, fingerprint)
        else:
            synthesized = self._weighted_ensemble(valid_results)
        
        return {
            'success': True,
            'exploitation_strategy': synthesized['strategy'],
            'payload': synthesized['payload'],
            'confidence': synthesized['confidence'],
            'model_consensus': synthesized['consensus'],
            'latency': max([r['latency_ms'] for r in valid_results]),
            'models_used': [r['model'] for r in valid_results],
            'fingerprint_match': synthesized.get('fingerprint_match', False)
        }
    
    def _voting_ensemble(self, results: List[Dict], task: str, fingerprint: Dict) -> Dict:
        """Voting-based ensemble strategy (FULL ORIGINAL)"""
        
        strategies = []
        for result in results:
            strategy = self._extract_strategy(result['response'])
            strategies.append({
                'strategy': strategy,
                'confidence': result['confidence'],
                'model': result['model']
            })
        
        strategy_votes = {}
        for s in strategies:
            key = s['strategy']
            if key not in strategy_votes:
                strategy_votes[key] = []
            strategy_votes[key].append(s)
        
        best_strategy = max(strategy_votes.items(), key=lambda x: len(x[1]))
        
        payload = self._generate_fingerprint_aware_payload(
            best_strategy[0], 
            task, 
            fingerprint
        )
        
        return {
            'strategy': best_strategy[0],
            'payload': payload,
            'confidence': np.mean([s['confidence'] for s in best_strategy[1]]),
            'consensus': len(best_strategy[1]) / len(results),
            'fingerprint_match': fingerprint.get('product') is not None
        }
    
    def _weighted_ensemble(self, results: List[Dict]) -> Dict:
        """Confidence-weighted ensemble strategy (FULL ORIGINAL)"""
        
        weighted_strategies = []
        total_weight = 0
        
        for result in results:
            model_name = result['model']
            model = self.models.get(model_name)
            if model:
                weight = result['confidence'] * model.accuracy_score
                weighted_strategies.append({
                    'strategy': self._extract_strategy(result['response']),
                    'weight': weight
                })
                total_weight += weight
        
        if total_weight > 0:
            for ws in weighted_strategies:
                ws['normalized_weight'] = ws['weight'] / total_weight
        
        best = max(weighted_strategies, key=lambda x: x.get('normalized_weight', 0))
        
        return {
            'strategy': best['strategy'],
            'payload': self._generate_payload(best['strategy'], 'weighted'),
            'confidence': best['normalized_weight'],
            'consensus': best['normalized_weight']
        }
    
    def _generate_fingerprint_aware_payload(self, strategy: str, task: str, fingerprint: Dict) -> str:
        """Generate payload considering target fingerprint"""
        
        if self.kb and fingerprint.get('product'):
            try:
                product_payloads = self.kb.get_payloads_by_product(
                    fingerprint['product'],
                    fingerprint.get('version')
                )
                
                if product_payloads:
                    best = max(product_payloads, key=lambda p: p.confidence_score)
                    return best.payload
            except Exception as e:
                logger.warning(f"Product-specific payload selection failed: {e}")
        
        return self._generate_payload(strategy, task)
    
    def _extract_strategy(self, response: str) -> str:
        """Extract exploitation strategy from model response"""
        return response[:100]
    
    def _generate_payload(self, strategy: str, task: str) -> str:
        """Generate payload based on strategy"""
        return f"PAYLOAD[{task}]: {strategy[:50]}"
    
    def _calculate_confidence(self, response: str) -> float:
        """Calculate confidence score for a response (FULL ORIGINAL)"""
        
        confidence_indicators = ['definitely', 'certain', 'high confidence', 'confirmed']
        uncertainty_indicators = ['might', 'possibly', 'uncertain', 'unclear']
        
        confidence = 0.5
        response_lower = response.lower()
        
        for indicator in confidence_indicators:
            if indicator in response_lower:
                confidence += 0.1
        
        for indicator in uncertainty_indicators:
            if indicator in response_lower:
                confidence -= 0.1
        
        return max(0.1, min(1.0, confidence))
    
    def _generate_cache_key(self, model_name: str, prompt: str) -> str:
        """Generate cache key for model responses"""
        content = f"{model_name}:{prompt}"
        return hashlib.md5(content.encode()).hexdigest()
    
    async def generate_adaptive_payload(self, 
                                       vulnerability: str,
                                       target_response: str,
                                       previous_attempts: List[Dict],
                                       target_info: Optional[Dict] = None) -> Dict:
        """Generate adaptive payload (FULL ORIGINAL)"""
        
        analysis = self._analyze_attempts(previous_attempts)
        
        model = self.model_selector.select_best_model(
            ModelCapability.PAYLOAD_CRAFTING,
            context={'vulnerability': vulnerability, 'attempts': len(previous_attempts)}
        )
        
        kb_alternatives = []
        if self.payload_manager and target_info and target_info.get('product'):
            # Get adaptive payloads from KB
            kb_alternatives = []  # Would implement KB lookup
        
        prompt = self.prompt_optimizer.create_adaptive_prompt(
            vulnerability=vulnerability,
            target_response=target_response,
            failure_patterns=analysis['failure_patterns'],
            successful_patterns=analysis['successful_patterns'],
            target_info=target_info,
            kb_alternatives=kb_alternatives
        )
        
        result = await self._execute_model(model, prompt)
        
        payload = self._extract_payload(result['response'])
        
        if not payload and kb_alternatives:
            payload = kb_alternatives[0]
        
        return {
            'payload': payload,
            'technique': analysis['recommended_technique'],
            'confidence': result['confidence'],
            'model_used': model.name,
            'fingerprint_aware': target_info is not None
        }
    
    def _analyze_attempts(self, attempts: List[Dict]) -> Dict:
        """Analyze previous exploitation attempts (FULL ORIGINAL)"""
        
        successful = [a for a in attempts if a.get('success', False)]
        failed = [a for a in attempts if not a.get('success', False)]
        
        return {
            'success_rate': len(successful) / len(attempts) if attempts else 0,
            'failure_patterns': self._identify_patterns(failed),
            'successful_patterns': self._identify_patterns(successful),
            'recommended_technique': self._recommend_technique(attempts)
        }
    
    def _identify_patterns(self, attempts: List[Dict]) -> List[str]:
        """Identify patterns in attempts"""
        patterns = []
        
        if attempts:
            lengths = [len(a.get('payload', '')) for a in attempts]
            if lengths:
                avg_length = np.mean(lengths)
                patterns.append(f"avg_length:{avg_length:.0f}")
            
            encodings = [a.get('encoding', 'none') for a in attempts]
            most_common = max(set(encodings), key=encodings.count)
            patterns.append(f"common_encoding:{most_common}")
        
        return patterns
    
    def _recommend_technique(self, attempts: List[Dict]) -> str:
        """Recommend exploitation technique based on history"""
        
        if not attempts:
            return "standard"
        
        success_rate = sum(1 for a in attempts if a.get('success', False)) / len(attempts)
        
        if success_rate < 0.2:
            return "advanced_evasion"
        elif success_rate < 0.5:
            return "moderate_obfuscation"
        else:
            return "standard_optimization"
    
    def _extract_payload(self, response: str) -> str:
        """Extract payload from model response"""
        payload_match = re.search(r'PAYLOAD:(.*?)(?:END|$)', response, re.DOTALL)
        if payload_match:
            return payload_match.group(1).strip()
        return response[:200]


class ContextManager:
    """Manages context across AI interactions (FULL ORIGINAL)"""
    
    def __init__(self, max_context_size: int = 32000):
        self.max_context_size = max_context_size
        self.context_windows = {}
        self.global_facts = []
        
    def prepare_context(self, target: str, vulnerability_type: str, 
                       base_context: Dict, fingerprint: Optional[Dict] = None) -> Dict:
        """Prepare enriched context for AI models"""
        
        context_key = f"{target}:{vulnerability_type}"
        if context_key not in self.context_windows:
            self.context_windows[context_key] = ContextWindow(
                max_tokens=self.max_context_size,
                current_tokens=0,
                messages=deque(maxlen=100),
                key_facts=[],
                vulnerability_context={},
                target_profile={},
                exploitation_history=[],
                fingerprint_data=fingerprint
            )
        
        window = self.context_windows[context_key]
        
        window.vulnerability_context.update({
            'type': vulnerability_type,
            'target': target,
            'timestamp': datetime.now().isoformat()
        })
        
        if fingerprint:
            window.fingerprint_data = fingerprint
            window.key_facts.append({
                'fact': f"Target is {fingerprint.get('product', 'unknown')} {fingerprint.get('version', '')}",
                'confidence': 0.9
            })
            if fingerprint.get('waf'):
                window.key_facts.append({
                    'fact': f"WAF detected: {fingerprint['waf']}",
                    'confidence': 0.85
                })
        
        window.target_profile.update(base_context)
        
        if window.current_tokens > window.max_tokens * 0.8:
            self._compress_context(window)
        
        return {
            'vulnerability': window.vulnerability_context,
            'target': window.target_profile,
            'key_facts': window.key_facts + self.global_facts,
            'history': window.exploitation_history[-10:],
            'fingerprint': window.fingerprint_data
        }
    
    def _compress_context(self, window: ContextWindow):
        """Compress context to fit within token limits"""
        
        while len(window.messages) > 50:
            window.messages.popleft()
        
        if len(window.exploitation_history) > 20:
            window.exploitation_history = window.exploitation_history[-20:]
        
        window.current_tokens = len(json.dumps({
            'messages': list(window.messages),
            'facts': window.key_facts,
            'context': window.vulnerability_context,
            'profile': window.target_profile,
            'history': window.exploitation_history,
            'fingerprint': window.fingerprint_data
        })) // 4
    
    def update_with_result(self, target: str, vulnerability_type: str, result: Dict):
        """Update context with exploitation result"""
        
        context_key = f"{target}:{vulnerability_type}"
        if context_key in self.context_windows:
            window = self.context_windows[context_key]
            
            window.exploitation_history.append({
                'timestamp': datetime.now().isoformat(),
                'success': result.get('success', False),
                'technique': result.get('technique', 'unknown'),
                'fingerprint_match': result.get('fingerprint_match', False)
            })
            
            if result.get('success'):
                window.key_facts.append({
                    'fact': f"Successful {vulnerability_type} exploitation",
                    'confidence': result.get('confidence', 0.5)
                })


class PromptOptimizer:
    """Optimizes prompts for different AI models (FULL ORIGINAL)"""
    
    def __init__(self):
        self.prompt_templates = self._load_templates()
        self.optimization_history = []
        
    def _load_templates(self) -> Dict:
        """Load prompt templates for different tasks"""
        return {
            'vulnerability_analysis': """
                Analyze the following target for {vulnerability_type} vulnerabilities:
                Target: {target}
                Product: {product}
                Version: {version}
                Context: {context}
                
                Provide detailed analysis including:
                1. Vulnerability indicators
                2. Exploitation vectors
                3. Recommended payloads
                4. Success probability
            """,
            'payload_crafting': """
                Create an optimized payload for {vulnerability_type}:
                Target Product: {product} {version}
                Target characteristics: {target_profile}
                Previous attempts: {attempts}
                KB suggestions: {kb_alternatives}
                
                Generate a payload that:
                1. Is specific to {product} {version}
                2. Evades common filters
                3. Maximizes success probability
            """,
            'strategic_planning': """
                Develop exploitation strategy for:
                Target: {target}
                Fingerprint: {fingerprint}
                Vulnerabilities found: {vulnerabilities}
                
                Provide:
                1. Prioritized exploitation order
                2. Product-specific techniques
                3. Chaining opportunities
                4. Risk assessment
            """
        }
    
    def optimize_prompt(self, model: AIModel, task: str, context: Dict,
                       fingerprint: Optional[Dict] = None) -> str:
        """Optimize prompt for specific model and task"""
        template = self.prompt_templates.get(task, self.prompt_templates['vulnerability_analysis'])
        
        format_ctx = {
            'vulnerability_type': task,
            'target': context.get('target', {}),
            'context': context,
            'target_profile': context.get('target', {}),
            'attempts': context.get('history', []),
            'kb_alternatives': context.get('suggested_payloads', []),
            'fingerprint': json.dumps(context.get('fingerprint', {})),
            'product': 'unknown',
            'version': 'unknown',
            'vulnerabilities': context.get('vulnerability', {})
        }
        
        if fingerprint:
            format_ctx['product'] = fingerprint.get('product', 'unknown')
            format_ctx['version'] = fingerprint.get('version', 'unknown')
            format_ctx['fingerprint'] = json.dumps(fingerprint)
        
        if model.provider == 'ollama':
            prompt = self._optimize_for_ollama(template, format_ctx)
        elif model.provider == 'openai':
            prompt = self._optimize_for_openai(template, format_ctx)
        elif model.provider == 'anthropic':
            prompt = self._optimize_for_anthropic(template, format_ctx)
        else:
            prompt = template.format(**format_ctx)
        
        prompt = self._apply_general_optimizations(prompt, model)
        
        return prompt
    
    def _optimize_for_ollama(self, template: str, context: Dict) -> str:
        """Optimize prompt for Ollama models"""
        prompt = template.format(**context)
        return f"### TECHNICAL ANALYSIS ###\n{prompt}\n### END ###"
    
    def _optimize_for_openai(self, template: str, context: Dict) -> str:
        """Optimize prompt for OpenAI models"""
        prompt = template.format(**context)
        return f"You are a security expert. {prompt}\nProvide response in JSON format."
    
    def _optimize_for_anthropic(self, template: str, context: Dict) -> str:
        """Optimize prompt for Anthropic models"""
        prompt = template.format(**context)
        return f"Context: You are analyzing security vulnerabilities.\n\n{prompt}\n\nBe thorough and precise."
    
    def _apply_general_optimizations(self, prompt: str, model: AIModel) -> str:
        """Apply general prompt optimizations"""
        
        max_prompt_tokens = model.context_window * 0.7
        
        if len(prompt) / 4 > max_prompt_tokens:
            prompt = prompt[:int(max_prompt_tokens * 4)]
        
        if 'code_generation' in [c.value for c in model.capabilities]:
            prompt += "\n\nExample payload: ' OR '1'='1"
        
        return prompt
    
    def create_adaptive_prompt(self, **kwargs) -> str:
        """Create adaptive prompt based on context"""
        
        base_prompt = "Generate an adaptive exploitation strategy.\n"
        
        if 'vulnerability' in kwargs:
            base_prompt += f"Vulnerability: {kwargs['vulnerability']}\n"
        
        if 'target_info' in kwargs and kwargs['target_info']:
            info = kwargs['target_info']
            base_prompt += f"Target: {info.get('product', 'unknown')} {info.get('version', '')}\n"
            if info.get('technologies'):
                base_prompt += f"Technologies: {', '.join(info['technologies'])}\n"
        
        if 'kb_alternatives' in kwargs and kwargs['kb_alternatives']:
            base_prompt += f"Consider these KB payloads: {kwargs['kb_alternatives'][:3]}\n"
        
        if 'failure_patterns' in kwargs:
            base_prompt += f"Avoid patterns: {kwargs['failure_patterns']}\n"
        
        if 'successful_patterns' in kwargs:
            base_prompt += f"Successful patterns: {kwargs['successful_patterns']}\n"
        
        base_prompt += "\nProvide optimized payload with explanation."
        
        return base_prompt


class ModelSelector:
    """Selects optimal models for tasks (FULL ORIGINAL)"""
    
    def __init__(self, models: Dict[str, AIModel]):
        self.models = models
        self.performance_history = {}
        
    def select_models(self, 
                     task_type: str,
                     capabilities_needed: List[ModelCapability],
                     max_models: int = 3) -> Dict[str, AIModel]:
        """Select best models for a task"""
        
        suitable_models = {}
        
        for model_name, model in self.models.items():
            model_caps = set(model.capabilities)
            needed_caps = set(capabilities_needed)
            
            if needed_caps.intersection(model_caps):
                score = self._calculate_model_score(model, task_type, capabilities_needed)
                suitable_models[model_name] = (model, score)
        
        sorted_models = sorted(suitable_models.items(), key=lambda x: x[1][1], reverse=True)
        selected = {}
        
        for model_name, (model, score) in sorted_models[:max_models]:
            selected[model_name] = model
        
        return selected
    
    def select_best_model(self, 
                         capability: ModelCapability,
                         context: Optional[Dict] = None) -> AIModel:
        """Select single best model for a capability"""
        
        best_model = None
        best_score = -1
        
        for model_name, model in self.models.items():
            if capability in model.capabilities:
                score = self._calculate_model_score(model, capability.value, [capability])
                
                if context:
                    if context.get('require_large_context') and model.context_window > 100000:
                        score *= 1.5
                    if context.get('cost_sensitive') and model.cost_per_token == 0:
                        score *= 1.3
                
                if score > best_score:
                    best_score = score
                    best_model = model
        
        return best_model or list(self.models.values())[0]
    
    def _calculate_model_score(self, 
                              model: AIModel,
                              task_type: str,
                              capabilities: List[ModelCapability]) -> float:
        """Calculate model suitability score"""
        
        score = 0
        
        score += model.accuracy_score * 10
        
        model_caps = set(model.capabilities)
        needed_caps = set(capabilities)
        overlap = len(model_caps.intersection(needed_caps))
        score += overlap * 5
        
        if task_type.lower() in [s.lower() for s in model.specializations]:
            score += 10
        
        if model.cost_per_token > 0:
            score -= model.cost_per_token * 100
        
        score -= model.latency_ms / 1000
        
        if model.name in self.performance_history:
            historical_success = self.performance_history[model.name].get('success_rate', 0.5)
            score += historical_success * 10
        
        return score
    
    def update_performance(self, model_name: str, success: bool, task_type: str):
        """Update model performance history"""
        
        if model_name not in self.performance_history:
            self.performance_history[model_name] = {
                'total_tasks': 0,
                'successful_tasks': 0,
                'success_rate': 0,
                'task_types': {}
            }
        
        history = self.performance_history[model_name]
        history['total_tasks'] += 1
        if success:
            history['successful_tasks'] += 1
        history['success_rate'] = history['successful_tasks'] / history['total_tasks']
        
        if task_type not in history['task_types']:
            history['task_types'][task_type] = {'total': 0, 'successful': 0}
        
        history['task_types'][task_type]['total'] += 1
        if success:
            history['task_types'][task_type]['successful'] += 1


class PerformanceTracker:
    """Tracks AI orchestration performance (FULL ORIGINAL)"""
    
    def __init__(self):
        self.executions = []
        self.model_stats = {}
        
    def record_execution(self, models: List[str], task: str, success: bool, latency: float):
        """Record execution metrics"""
        
        execution = {
            'timestamp': datetime.now(),
            'models': models,
            'task': task,
            'success': success,
            'latency': latency
        }
        
        self.executions.append(execution)
        
        for model in models:
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
    
    def get_performance_report(self) -> Dict:
        """Generate performance report"""
        
        if not self.executions:
            return {'message': 'No executions recorded'}
        
        recent_executions = self.executions[-100:]
        
        return {
            'total_executions': len(self.executions),
            'success_rate': sum(1 for e in self.executions if e['success']) / len(self.executions),
            'average_latency': np.mean([e['latency'] for e in self.executions]),
            'model_performance': {
                model: {
                    'success_rate': stats['successes'] / stats['executions'] if stats['executions'] > 0 else 0,
                    'avg_latency': stats['total_latency'] / stats['executions'] if stats['executions'] > 0 else 0,
                    'usage_count': stats['executions']
                }
                for model, stats in self.model_stats.items()
            },
            'recent_trend': {
                'success_rate': sum(1 for e in recent_executions if e['success']) / len(recent_executions),
                'avg_latency': np.mean([e['latency'] for e in recent_executions])
            }
        }

# ============================================================================
# UNIFIED INTERFACE (Additional convenience wrapper)
# ============================================================================

class UnifiedAIOrchestrator(AdvancedAIOrchestrator):
    """
    Unified interface that extends the full orchestrator with LLM connector integration
    """
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        
        # Initialize LLM connectors
        self.connectors = {}
        self.connectors['ollama'] = OllamaConnector()
        
        if os.getenv("OPENAI_API_KEY"):
            self.connectors['openai'] = OpenAIConnector()
        
        # Chat sessions
        self.chat_sessions = {}
    
    def get_connector(self, provider: str = 'ollama') -> BaseLLMConnector:
        """Get LLM connector by provider"""
        return self.connectors.get(provider, BaseLLMConnector())
    
    def create_chat_session(self, name: str = "default", 
                           provider: str = 'ollama',
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
    
    def suggest_exploitation_steps(self, target: str, recon_data: Dict) -> List[Dict]:
        """Get exploitation steps from default connector"""
        connector = self.get_connector('ollama')
        return connector.suggest_steps(target, recon_data)

# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

LLMConnector = BaseLLMConnector
OpenAIChatConnector = OpenAIConnector
LocalFunctionConnector = BaseLLMConnector

class OpenAICompatibleHTTPConnector(OpenAIConnector):
    """Backward compatibility wrapper"""
    def __init__(self, config: Dict = None, **kwargs):
        if config:
            kwargs.update(config)
        super().__init__(**kwargs)
