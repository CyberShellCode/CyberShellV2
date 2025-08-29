"""
Unified State Manager for CyberShell
Combines workflow state machines, authentication sessions, and human-in-the-loop feedback
"""

import json
import time
import pickle
import hashlib
import re
import jwt
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable, Union
from datetime import datetime, timedelta
from urllib.parse import urlparse
from enum import Enum

import requests


class WorkflowState(Enum):
    """Workflow states for exploitation"""
    IDLE = "idle"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    VALIDATING = "validating"
    REPORTING = "reporting"
    WAITING_HUMAN = "waiting_human"
    ERROR = "error"


@dataclass
class State:
    """FSM state with optional enter/exit hooks"""
    name: str
    on_enter: Optional[Callable[[], None]] = None
    on_exit: Optional[Callable[[], None]] = None


@dataclass
class FeedbackItem:
    """Human feedback for ML training"""
    event: Any  # SignalEvent type
    correct_families: List[str]
    timestamp: datetime = field(default_factory=datetime.now)
    applied: bool = False


class UnifiedStateManager:
    """
    Unified state management combining:
    - Workflow state machines
    - Authentication/session management  
    - Human-in-the-loop feedback
    """
    
    def __init__(self, config: Optional[Dict] = None):
        # Configuration
        self.config = config or {}
        
        # Workflow state machine
        self.workflow_state = WorkflowState.IDLE
        self.states: Dict[str, State] = {}
        self.transitions: Dict[tuple, str] = {}
        self._init_workflow_states()
        
        # Session management
        self.sessions = {}
        self.credentials_store = {}
        self.tokens = {}
        self.cookies = {}
        self.csrf_tokens = {}
        self.api_keys = {}
        self.token_expiry = {}
        self.session_timeout = self.config.get('session_timeout', 3600)
        self.state_file = self.config.get('state_file', './sessions/state.pkl')
        
        # HITL feedback
        self.feedback_buffer: List[FeedbackItem] = []
        self.mapper = None  # Set by orchestrator if ML feedback is needed
        
        # Workflow history
        self.workflow_history = []
        self.current_target = None
        
    def _init_workflow_states(self):
        """Initialize default workflow states"""
        # Add basic workflow states
        for state in WorkflowState:
            self.add_state(State(
                name=state.value,
                on_enter=lambda s=state: self._log_state_entry(s),
                on_exit=lambda s=state: self._log_state_exit(s)
            ))
            
        # Add transitions
        self.add_transition(WorkflowState.IDLE.value, "start_scan", WorkflowState.SCANNING.value)
        self.add_transition(WorkflowState.SCANNING.value, "start_exploit", WorkflowState.EXPLOITING.value)
        self.add_transition(WorkflowState.EXPLOITING.value, "validate", WorkflowState.VALIDATING.value)
        self.add_transition(WorkflowState.VALIDATING.value, "report", WorkflowState.REPORTING.value)
        self.add_transition(WorkflowState.REPORTING.value, "complete", WorkflowState.IDLE.value)
        
        # Human intervention transitions
        for state in WorkflowState:
            if state != WorkflowState.WAITING_HUMAN:
                self.add_transition(state.value, "request_human", WorkflowState.WAITING_HUMAN.value)
        self.add_transition(WorkflowState.WAITING_HUMAN.value, "resume", WorkflowState.IDLE.value)
        
        # Error transitions
        for state in WorkflowState:
            if state != WorkflowState.ERROR:
                self.add_transition(state.value, "error", WorkflowState.ERROR.value)
        self.add_transition(WorkflowState.ERROR.value, "recover", WorkflowState.IDLE.value)
    
    # ========== Workflow State Machine Methods ==========
    
    def add_state(self, state: State):
        """Add a state to the workflow"""
        self.states[state.name] = state
    
    def add_transition(self, src: str, event: str, dst: str):
        """Add a state transition"""
        self.transitions[(src, event)] = dst
    
    def send_event(self, event: str) -> bool:
        """Send an event to trigger state transition"""
        key = (self.workflow_state.value if isinstance(self.workflow_state, WorkflowState) 
               else self.workflow_state, event)
        
        if key not in self.transitions:
            return False
            
        # Execute exit hook
        if self.workflow_state.value in self.states:
            exit_hook = self.states[self.workflow_state.value].on_exit
            if exit_hook:
                exit_hook()
        
        # Transition
        old_state = self.workflow_state
        new_state_name = self.transitions[key]
        self.workflow_state = WorkflowState(new_state_name) if new_state_name in [s.value for s in WorkflowState] else new_state_name
        
        # Execute enter hook
        if new_state_name in self.states:
            enter_hook = self.states[new_state_name].on_enter
            if enter_hook:
                enter_hook()
        
        # Log transition
        self.workflow_history.append({
            'timestamp': datetime.now(),
            'from': old_state,
            'to': self.workflow_state,
            'event': event,
            'target': self.current_target
        })
        
        return True
    
    def get_workflow_state(self) -> str:
        """Get current workflow state"""
        return self.workflow_state.value if isinstance(self.workflow_state, WorkflowState) else self.workflow_state
    
    def _log_state_entry(self, state: WorkflowState):
        """Log state entry"""
        pass  # Implement logging if needed
    
    def _log_state_exit(self, state: WorkflowState):
        """Log state exit"""
        pass  # Implement logging if needed
    
    # ========== Session/Authentication Methods ==========
    
    def get_session(self, target: str, credentials: Optional[Dict] = None) -> Dict[str, Any]:
        """Get or create an authenticated session for target"""
        # Check for existing valid session
        if target in self.sessions:
            if self.validate_session(target, self.sessions[target]):
                return {
                    'success': True,
                    'session': self.sessions[target],
                    'cookies': self.cookies.get(target),
                    'token': self.tokens.get(target),
                    'csrf_token': self.csrf_tokens.get(target)
                }
            else:
                # Try to refresh
                result = self.refresh_session(target)
                if result['success']:
                    return result
        
        # Need to login
        if credentials or target in self.credentials_store:
            creds = credentials or self.credentials_store.get(target, {})
            return self.handle_login(target, creds)
        
        return {'success': False, 'message': 'No session or credentials available'}
    
    def handle_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """Handle various types of login mechanisms"""
        # Store credentials for future use
        if credentials:
            self.credentials_store[target] = credentials
        
        # Detect and execute login
        login_type = self.detect_login_type(target)
        
        login_methods = {
            'form': self.form_login,
            'json': self.json_login,
            'oauth': self.oauth_login,
            'jwt': self.jwt_login,
            'graphql': self.graphql_login
        }
        
        method = login_methods.get(login_type, self.generic_login)
        result = method(target, credentials)
        
        if result['success']:
            self.current_target = target
            
        return result
    
    def detect_login_type(self, target: str) -> str:
        """Detect the type of authentication mechanism"""
        try:
            response = requests.get(target, timeout=5)
            content = response.text.lower()
            headers = response.headers
            
            if 'graphql' in content or '/graphql' in content:
                return 'graphql'
            elif 'oauth' in content or 'authorize' in content:
                return 'oauth'
            elif 'application/json' in headers.get('Content-Type', ''):
                return 'json'
            elif '<form' in content and 'password' in content:
                return 'form'
            elif 'jwt' in content or 'bearer' in content:
                return 'jwt'
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def form_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """Handle form-based login"""
        session = requests.Session()
        
        # Get login page to extract CSRF token
        login_page = session.get(target)
        csrf_token = self.extract_csrf_token(login_page.text)
        
        if not credentials:
            credentials = self.try_common_credentials()
        
        login_data = {
            'username': credentials.get('username', 'admin'),
            'password': credentials.get('password', 'admin'),
            'csrf_token': csrf_token,
            'submit': 'Login'
        }
        
        # Try different parameter names
        param_variations = [
            {'username': 'user', 'password': 'pass'},
            {'username': 'email', 'password': 'password'},
            {'username': 'login', 'password': 'pwd'},
            {'username': 'uname', 'password': 'passwd'}
        ]
        
        for variation in param_variations:
            test_data = {variation[k]: login_data[k] for k in ['username', 'password']}
            test_data['csrf_token'] = csrf_token
            
            response = session.post(target, data=test_data, allow_redirects=True)
            
            if self.check_login_success(response):
                self.sessions[target] = session
                self.cookies[target] = session.cookies.get_dict()
                if csrf_token:
                    self.csrf_tokens[target] = csrf_token
                return {
                    'success': True,
                    'session': session,
                    'cookies': self.cookies[target],
                    'message': 'Form login successful'
                }
        
        return {'success': False, 'message': 'Form login failed'}
    
    def json_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """Handle JSON-based API login"""
        session = requests.Session()
        
        if not credentials:
            credentials = self.try_common_credentials()
        
        login_data = {
            'username': credentials.get('username', 'admin'),
            'password': credentials.get('password', 'admin')
        }
        
        headers = {'Content-Type': 'application/json'}
        endpoints = ['/login', '/api/login', '/auth/login', '/api/auth/login', '/authenticate']
        
        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        
        for endpoint in endpoints:
            try:
                response = session.post(
                    f"{base_url}{endpoint}",
                    json=login_data,
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    token = data.get('token') or data.get('access_token') or data.get('auth_token')
                    
                    if token:
                        self.tokens[target] = token
                        session.headers['Authorization'] = f'Bearer {token}'
                        
                        # Try to decode JWT for expiry
                        try:
                            decoded = jwt.decode(token, options={"verify_signature": False})
                            exp = decoded.get('exp')
                            if exp:
                                self.token_expiry[target] = datetime.fromtimestamp(exp)
                        except:
                            pass
                    
                    self.sessions[target] = session
                    return {
                        'success': True,
                        'session': session,
                        'token': token,
                        'message': 'JSON login successful'
                    }
            except:
                continue
        
        return {'success': False, 'message': 'JSON login failed'}
    
    def graphql_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """Handle GraphQL-based login"""
        session = requests.Session()
        
        if not credentials:
            credentials = self.try_common_credentials()
        
        login_mutation = """
        mutation Login($username: String!, $password: String!) {
            login(username: $username, password: $password) {
                token
                user { id username role }
            }
        }
        """
        
        variables = {
            'username': credentials.get('username', 'admin'),
            'password': credentials.get('password', 'admin')
        }
        
        endpoints = ['/graphql', '/api/graphql', '/query', '/gql']
        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        
        for endpoint in endpoints:
            try:
                response = session.post(
                    f"{base_url}{endpoint}",
                    json={'query': login_mutation, 'variables': variables},
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and 'login' in data['data']:
                        login_data = data['data']['login']
                        token = login_data.get('token')
                        
                        if token:
                            self.tokens[target] = token
                            session.headers['Authorization'] = f'Bearer {token}'
                        
                        self.sessions[target] = session
                        return {
                            'success': True,
                            'session': session,
                            'token': token,
                            'user_data': login_data.get('user'),
                            'message': 'GraphQL login successful'
                        }
            except:
                continue
        
        return {'success': False, 'message': 'GraphQL login failed'}
    
    def oauth_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """Handle OAuth authentication flow (placeholder)"""
        return {
            'success': False,
            'message': 'OAuth implementation needed',
            'flow_type': 'oauth2'
        }
    
    def jwt_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """Handle JWT-based authentication"""
        # First try standard JSON login to get JWT
        return self.json_login(target, credentials)
    
    def generic_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """Generic login attempt for unknown authentication types"""
        methods = [self.form_login, self.json_login, self.graphql_login, self.jwt_login]
        
        for method in methods:
            result = method(target, credentials)
            if result['success']:
                return result
        
        return {'success': False, 'message': 'All login methods failed'}
    
    def handle_multi_step_auth(self, target: str, step: int, **kwargs) -> Dict[str, Any]:
        """Handle multi-step authentication (MFA, OTP, etc.)"""
        if step == 1:
            return self.handle_login(target, kwargs.get('credentials', {}))
        elif step == 2:
            otp = kwargs.get('otp', '')
            session = self.sessions.get(target)
            
            if session and otp:
                response = session.post(f"{target}/verify-otp", json={'otp': otp})
                if response.status_code == 200:
                    return {
                        'success': True,
                        'session': session,
                        'message': 'Multi-factor authentication successful'
                    }
        
        return {'success': False, 'message': 'Multi-step authentication failed'}
    
    def validate_session(self, target: str, session: requests.Session) -> bool:
        """Validate if a session is still active"""
        try:
            response = session.get(f"{target}/api/user", timeout=5)
            return response.status_code != 401
        except:
            return False
    
    def refresh_session(self, target: str) -> Dict[str, Any]:
        """Refresh an expired session"""
        # Try token refresh
        if target in self.tokens:
            refresh_token = self.tokens.get(f"{target}_refresh")
            if refresh_token:
                result = self.refresh_token(target, refresh_token)
                if result['success']:
                    return result
        
        # Try to re-login with stored credentials
        if target in self.credentials_store:
            return self.handle_login(target, self.credentials_store[target])
        
        return {'success': False, 'message': 'Unable to refresh session'}
    
    def refresh_token(self, target: str, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token using refresh token"""
        try:
            response = requests.post(f"{target}/refresh", json={'refresh_token': refresh_token})
            
            if response.status_code == 200:
                data = response.json()
                new_token = data.get('access_token')
                
                if new_token:
                    self.tokens[target] = new_token
                    if target in self.sessions:
                        self.sessions[target].headers['Authorization'] = f'Bearer {new_token}'
                    
                    return {
                        'success': True,
                        'token': new_token,
                        'message': 'Token refreshed successfully'
                    }
        except:
            pass
        
        return {'success': False, 'message': 'Token refresh failed'}
    
    def extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML"""
        patterns = [
            r'csrf_token["\']?\s*[:=]\s*["\']([^"\']+)',
            r'name=["\']csrf[_-]?token["\'].*?value=["\']([^"\']+)',
            r'<meta name=["\']csrf-token["\'] content=["\']([^"\']+)',
            r'X-CSRF-Token["\']:\s*["\']([^"\']+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def check_login_success(self, response: requests.Response) -> bool:
        """Check if login was successful"""
        if response.status_code in [200, 302]:
            success_indicators = ['dashboard', 'welcome', 'profile', 'logout', 'success', 'authenticated']
            failure_indicators = ['invalid', 'failed', 'error', 'incorrect', 'wrong', 'denied']
            
            text_lower = response.text.lower()
            url_lower = response.url.lower()
            
            for indicator in success_indicators:
                if indicator in url_lower or indicator in text_lower:
                    return True
            
            for indicator in failure_indicators:
                if indicator in text_lower:
                    return False
            
            # If redirected away from login page, probably successful
            if 'login' not in url_lower:
                return True
        
        return False
    
    def try_common_credentials(self) -> Dict[str, str]:
        """Return common default credentials"""
        common_creds = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'user', 'password': 'user'},
            {'username': 'test', 'password': 'test'},
        ]
        return common_creds[0]  # Could iterate through all
    
    # ========== HITL Feedback Methods ==========
    
    def submit_feedback(self, event: Any, correct_families: List[str]):
        """Submit human feedback for ML training"""
        item = FeedbackItem(event=event, correct_families=correct_families)
        self.feedback_buffer.append(item)
        
        # Request human intervention state
        if self.workflow_state != WorkflowState.WAITING_HUMAN:
            self.send_event("request_human")
    
    def apply_feedback(self) -> int:
        """Apply accumulated feedback to ML model"""
        if not self.feedback_buffer or not self.mapper:
            return 0
        
        # Extract texts and labels from feedback
        texts = []
        labels = []
        
        for fb in self.feedback_buffer:
            if hasattr(fb.event, 'as_text'):
                texts.append(fb.event.as_text())
                labels.append(fb.correct_families)
                fb.applied = True
        
        if texts and hasattr(self.mapper, 'ml') and hasattr(self.mapper.ml, 'partial_fit'):
            # Convert to numpy array format expected by ML
            from .adaptive.mapper import FAMILIES
            Y = np.zeros((len(texts), len(FAMILIES)), dtype=int)
            
            for i, families in enumerate(labels):
                for fam in families:
                    if fam in FAMILIES:
                        Y[i, FAMILIES.index(fam)] = 1
            
            self.mapper.ml.partial_fit(texts, Y)
        
        # Clear applied feedback
        applied_count = len([fb for fb in self.feedback_buffer if fb.applied])
        self.feedback_buffer = [fb for fb in self.feedback_buffer if not fb.applied]
        
        # Resume from human intervention
        if self.workflow_state == WorkflowState.WAITING_HUMAN and not self.feedback_buffer:
            self.send_event("resume")
        
        return applied_count
    
    def get_pending_feedback(self) -> List[FeedbackItem]:
        """Get pending feedback items"""
        return [fb for fb in self.feedback_buffer if not fb.applied]
    
    def set_ml_mapper(self, mapper):
        """Set the ML mapper for feedback training"""
        self.mapper = mapper
    
    # ========== State Persistence Methods ==========
    
    def save_state(self) -> Dict[str, Any]:
        """Save current state to disk"""
        state = {
            'workflow_state': self.workflow_state.value if isinstance(self.workflow_state, WorkflowState) else self.workflow_state,
            'sessions': {k: None for k in self.sessions.keys()},  # Don't pickle session objects
            'tokens': self.tokens,
            'cookies': self.cookies,
            'csrf_tokens': self.csrf_tokens,
            'credentials': self.credentials_store,
            'workflow_history': self.workflow_history[-100:],  # Keep last 100 entries
            'current_target': self.current_target
        }
        
        try:
            import os
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            
            with open(self.state_file, 'wb') as f:
                pickle.dump(state, f)
            return {'success': True, 'message': 'State saved'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to save state: {e}'}
    
    def load_state(self) -> Dict[str, Any]:
        """Load state from disk"""
        try:
            with open(self.state_file, 'rb') as f:
                state = pickle.load(f)
            
            # Restore state
            if 'workflow_state' in state:
                ws = state['workflow_state']
                self.workflow_state = WorkflowState(ws) if ws in [s.value for s in WorkflowState] else ws
            
            self.tokens = state.get('tokens', {})
            self.cookies = state.get('cookies', {})
            self.csrf_tokens = state.get('csrf_tokens', {})
            self.credentials_store = state.get('credentials', {})
            self.workflow_history = state.get('workflow_history', [])
            self.current_target = state.get('current_target')
            
            # Note: sessions need to be recreated, not loaded
            
            return {'success': True, 'message': 'State loaded'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to load state: {e}'}
    
    # ========== Utility Methods ==========
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get summary of current state"""
        return {
            'workflow_state': self.get_workflow_state(),
            'active_sessions': list(self.sessions.keys()),
            'stored_credentials': list(self.credentials_store.keys()),
            'active_tokens': list(self.tokens.keys()),
            'pending_feedback': len(self.get_pending_feedback()),
            'current_target': self.current_target,
            'history_length': len(self.workflow_history)
        }
    
    def clear_target_state(self, target: str):
        """Clear all state for a specific target"""
        self.sessions.pop(target, None)
        self.tokens.pop(target, None)
        self.cookies.pop(target, None)
        self.csrf_tokens.pop(target, None)
        self.credentials_store.pop(target, None)
    
    def reset(self):
        """Reset all state"""
        self.workflow_state = WorkflowState.IDLE
        self.sessions.clear()
        self.tokens.clear()
        self.cookies.clear()
        self.csrf_tokens.clear()
        self.credentials_store.clear()
        self.feedback_buffer.clear()
        self.workflow_history.clear()
        self.current_target = None


# Utility decorator from original statemachine.py
def retry(func, attempts=3, base_delay=0.5, factor=2.0):
    """Retry decorator for resilient operations"""
    def wrapper(*args, **kwargs):
        delay = base_delay
        last_exc = None
        for _ in range(attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exc = e
                time.sleep(delay)
                delay *= factor
        raise last_exc
    return wrapper


# Plugin compatibility wrapper
class StateManagerPlugin:
    """Compatibility wrapper for plugin system"""
    
    def __init__(self):
        self.state_manager = UnifiedStateManager()
    
    def run(self, **kwargs) -> Dict[str, Any]:
        """Plugin interface for state management"""
        action = kwargs.get('action', 'get_session')
        target = kwargs.get('target', '')
        
        actions = {
            'login': lambda: self.state_manager.handle_login(target, kwargs.get('credentials', {})),
            'get_session': lambda: self.state_manager.get_session(target),
            'refresh': lambda: self.state_manager.refresh_session(target),
            'save_state': lambda: self.state_manager.save_state(),
            'load_state': lambda: self.state_manager.load_state(),
            'multi_step_auth': lambda: self.state_manager.handle_multi_step_auth(
                target, kwargs.get('step', 1), **kwargs
            ),
            'submit_feedback': lambda: {'success': True, 'count': self.state_manager.submit_feedback(
                kwargs.get('event'), kwargs.get('families', [])
            )},
            'apply_feedback': lambda: {'success': True, 'applied': self.state_manager.apply_feedback()},
            'workflow_event': lambda: {'success': self.state_manager.send_event(kwargs.get('event', ''))},
            'get_state': lambda: self.state_manager.get_state_summary()
        }
        
        handler = actions.get(action, lambda: {'success': False, 'message': f'Unknown action: {action}'})
        return handler()
