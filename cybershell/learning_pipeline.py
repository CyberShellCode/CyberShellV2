"""
Unified Learning Pipeline with Enhanced Integration
==================================================
Enhanced version that integrates with ExploitationResult from enhanced_adaptive_learning.py
and provides comprehensive performance metrics.
"""

import json
import pickle
import numpy as np
import time
import tempfile
import os
import glob
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, TypeVar, Generic, Union
from dataclasses import dataclass, asdict, field
import logging
import threading
import queue
from collections import defaultdict

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_recall_fscore_support, 
    confusion_matrix, 
    classification_report, 
    multilabel_confusion_matrix,
    accuracy_score,
    roc_auc_score,
    roc_curve
)
import joblib

logger = logging.getLogger(__name__)

# Type variable for generic model storage
T = TypeVar('T')

# Try to import enhanced components
try:
    from .enhanced.enhanced_adaptive_learning import ExploitationResult, ExploitationLearner
    ENHANCED_AVAILABLE = True
except ImportError:
    ENHANCED_AVAILABLE = False
    # Define stub if not available
    @dataclass
    class ExploitationResult:
        target: str
        vulnerability_type: str
        payload: str
        response_code: int
        response_time: float
        waf_detected: bool
        waf_type: Optional[str]
        bypass_used: Optional[str]
        success: bool
        indicators: List[str]
        timestamp: datetime = field(default_factory=datetime.now)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ExploitAttempt:
    """Records details of exploitation attempts for learning"""
    timestamp: datetime
    target: str
    vulnerability_type: str
    plugin_used: str
    success: bool
    confidence_score: float
    evidence_score: float
    execution_time: float
    error_details: Optional[str]
    environmental_factors: Dict[str, Any]
    payload_characteristics: Dict[str, Any]
    # Enhanced fields for integration
    waf_encountered: bool = False
    waf_type: Optional[str] = None
    bypass_technique: Optional[str] = None
    response_indicators: List[str] = field(default_factory=list)
    javascript_rendered: bool = False
    api_endpoint: bool = False

@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    confusion_matrix: np.ndarray
    roc_auc: Optional[float] = None
    support: Optional[Dict[str, int]] = None
    per_class_metrics: Optional[Dict[str, Dict]] = None

@dataclass
class RunMetrics:
    """Enhanced metrics tracking"""
    start_ts: float = field(default_factory=time.time)
    steps: int = 0
    success: int = 0
    fail: int = 0
    waf_encounters: int = 0
    waf_bypasses: int = 0
    exploitation_attempts: int = 0
    unique_vulnerabilities: set = field(default_factory=set)
    
    def log_step(self, step_name: str, data: Dict[str, Any] = None) -> None:
        """Enhanced log_step that accepts both bool and dict"""
        self.steps += 1
        
        if isinstance(step_name, bool):
            ok = step_name
            self.success += int(ok)
            self.fail += int(not ok)
        elif isinstance(data, dict):
            ok = data.get('success', True)
            self.success += int(ok)
            self.fail += int(not ok)
            
            # Track enhanced metrics
            if data.get('waf_detected'):
                self.waf_encounters += 1
            if data.get('waf_bypassed'):
                self.waf_bypasses += 1
            if data.get('vulnerability_type'):
                self.unique_vulnerabilities.add(data['vulnerability_type'])
        else:
            self.success += 1
        
        self.exploitation_attempts = self.success + self.fail
    
    def summary(self) -> Dict[str, Any]:
        dur = time.perf_counter() - self.start_ts
        return {
            'steps': self.steps,
            'success': self.success,
            'fail': self.fail,
            'success_rate': float(self.success) / max(1, self.steps),
            'duration_s': dur,
            'waf_encounters': self.waf_encounters,
            'waf_bypasses': self.waf_bypasses,
            'waf_bypass_rate': float(self.waf_bypasses) / max(1, self.waf_encounters),
            'unique_vulnerabilities': len(self.unique_vulnerabilities),
            'exploitation_attempts': self.exploitation_attempts
        }

@dataclass
class NVDSample:
    """Sample from NVD data for training"""
    text: str
    labels: Dict[str, int]

# ============================================================================
# MODEL PERSISTENCE
# ============================================================================

class ModelStore(Generic[T]):
    """Type-safe model storage with atomic file operations"""
    
    def __init__(self, path: str = "models/cybershell_model.joblib"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
    
    def save(self, model: T, metadata: Optional[Dict] = None) -> None:
        """Save model with optional metadata using atomic write"""
        target_path = self.path
        parent_dir = target_path.parent
        os.makedirs(parent_dir, exist_ok=True)
        
        try:
            with tempfile.NamedTemporaryFile(
                mode='wb',
                dir=parent_dir,
                prefix='.tmp_',
                suffix='.joblib',
                delete=False
            ) as tmp_file:
                temp_path = tmp_file.name
                
                if metadata:
                    bundle = {'model': model, 'metadata': metadata}
                else:
                    bundle = model
                
                joblib.dump(bundle, tmp_file)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            
            os.replace(temp_path, str(target_path))
            logger.debug(f"Model saved to {self.path}")
            
        except Exception as e:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.unlink(temp_path)
            logger.error(f"Failed to save model: {e}")
            raise
    
    def load(self) -> Optional[T]:
        """Load model from disk"""
        if not self.path.exists():
            logger.debug(f"Model file does not exist: {self.path}")
            return None
        
        try:
            data = joblib.load(self.path)
            
            if isinstance(data, dict) and 'model' in data:
                return data['model']
            return data
            
        except Exception as e:
            logger.warning(f"Failed to load model: {e}")
            return None
    
    def load_with_metadata(self) -> Optional[Tuple[T, Dict]]:
        """Load model and metadata if available"""
        if not self.path.exists():
            return None
        
        try:
            data = joblib.load(self.path)
            if isinstance(data, dict) and 'model' in data:
                return data['model'], data.get('metadata', {})
            return data, {}
        except Exception as e:
            logger.warning(f"Failed to load model with metadata: {e}")
            return None
    
    def exists(self) -> bool:
        """Check if model file exists"""
        return self.path.exists()
    
    def delete(self) -> bool:
        """Delete the model file"""
        if self.path.exists():
            try:
                self.path.unlink()
                logger.debug(f"Model file deleted: {self.path}")
                return True
            except OSError as e:
                logger.error(f"Failed to delete model file: {e}")
                raise
        return False
    
    def get_file_info(self) -> Optional[Dict]:
        """Get information about the stored model file"""
        if not self.path.exists():
            return None
        
        stat = self.path.stat()
        return {
            'path': str(self.path.absolute()),
            'size_bytes': stat.st_size,
            'modified_time': stat.st_mtime,
            'created_time': stat.st_ctime
        }

# ============================================================================
# FEATURE EXTRACTION MODULE
# ============================================================================

class FeatureExtractor:
    """Modular feature extraction for different data types"""
    
    def __init__(self, feature_config: Optional[Dict] = None):
        self.config = feature_config or self._default_config()
        self.feature_names = []
    
    def _default_config(self) -> Dict:
        return {
            'include_basic': True,
            'include_environmental': True,
            'include_payload': True,
            'include_waf': True,
            'include_temporal': True,
            'include_enhanced': True
        }
    
    def extract_from_attempt(self, attempt: ExploitAttempt) -> np.ndarray:
        """Extract features from ExploitAttempt"""
        features = []
        self.feature_names = []
        
        if self.config['include_basic']:
            features.extend(self._extract_basic_features(attempt))
        
        if self.config['include_environmental']:
            features.extend(self._extract_environmental_features(attempt))
        
        if self.config['include_payload']:
            features.extend(self._extract_payload_features(attempt))
        
        if self.config['include_waf']:
            features.extend(self._extract_waf_features(attempt))
        
        if self.config['include_temporal']:
            features.extend(self._extract_temporal_features(attempt))
        
        if self.config['include_enhanced']:
            features.extend(self._extract_enhanced_features(attempt))
        
        return np.array(features)
    
    def extract_from_exploitation_result(self, result: 'ExploitationResult') -> np.ndarray:
        """Extract features from ExploitationResult (enhanced integration)"""
        # Convert to ExploitAttempt for unified processing
        attempt = self._convert_result_to_attempt(result)
        return self.extract_from_attempt(attempt)
    
    def _extract_basic_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract basic features"""
        features = [
            attempt.confidence_score,
            attempt.evidence_score,
            attempt.execution_time,
            float(attempt.success)
        ]
        self.feature_names.extend(['confidence', 'evidence', 'exec_time', 'success'])
        return features
    
    def _extract_environmental_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract environmental features"""
        env = attempt.environmental_factors or {}
        features = [
            env.get('response_time', 0),
            float(env.get('waf_detected', 0)),
            float(env.get('rate_limit_encountered', 0)),
            env.get('server_load', 0.5),
            env.get('network_latency', 0)
        ]
        self.feature_names.extend(['resp_time', 'waf_detect', 'rate_limit', 'server_load', 'latency'])
        return features
    
    def _extract_payload_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract payload characteristics"""
        payload = attempt.payload_characteristics or {}
        features = [
            payload.get('length', 0) / 1000.0,  # Normalize
            payload.get('complexity_score', 0),
            payload.get('encoding_layers', 0),
            float(payload.get('obfuscated', False)),
            payload.get('injection_points', 1)
        ]
        self.feature_names.extend(['payload_len', 'complexity', 'encoding', 'obfuscated', 'inj_points'])
        return features
    
    def _extract_waf_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract WAF-related features"""
        features = [
            float(attempt.waf_encountered),
            float(attempt.waf_type == 'cloudflare'),
            float(attempt.waf_type == 'akamai'),
            float(attempt.waf_type == 'aws_waf'),
            float(attempt.bypass_technique is not None)
        ]
        self.feature_names.extend(['waf_enc', 'waf_cf', 'waf_ak', 'waf_aws', 'bypass_used'])
        return features
    
    def _extract_temporal_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract temporal features"""
        hour = attempt.timestamp.hour
        day_of_week = attempt.timestamp.weekday()
        
        features = [
            np.sin(2 * np.pi * hour / 24),
            np.cos(2 * np.pi * hour / 24),
            np.sin(2 * np.pi * day_of_week / 7),
            np.cos(2 * np.pi * day_of_week / 7)
        ]
        self.feature_names.extend(['hour_sin', 'hour_cos', 'dow_sin', 'dow_cos'])
        return features
    
    def _extract_enhanced_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract enhanced features for better integration"""
        features = [
            float(attempt.javascript_rendered),
            float(attempt.api_endpoint),
            len(attempt.response_indicators) / 10.0,  # Normalize
            float('time' in attempt.vulnerability_type.lower()),
            float('union' in str(attempt.payload_characteristics).lower())
        ]
        self.feature_names.extend(['js_rendered', 'api_endpoint', 'indicators', 'time_based', 'union_based'])
        return features
    
    def _extract_vulnerability_encoding(self, vuln_type: str) -> List[float]:
        """One-hot encode vulnerability type"""
        vuln_types = ['SQLI', 'XSS', 'RCE', 'IDOR', 'SSRF', 'XXE', 'SSTI', 'LFI']
        encoding = [0.0] * len(vuln_types)
        
        for i, vt in enumerate(vuln_types):
            if vt.lower() in vuln_type.lower():
                encoding[i] = 1.0
                break
        
        self.feature_names.extend([f'vuln_{vt.lower()}' for vt in vuln_types])
        return encoding
    
    def _convert_result_to_attempt(self, result: 'ExploitationResult') -> ExploitAttempt:
        """Convert ExploitationResult to ExploitAttempt for unified processing"""
        return ExploitAttempt(
            timestamp=result.timestamp if hasattr(result, 'timestamp') else datetime.now(),
            target=result.target,
            vulnerability_type=result.vulnerability_type,
            plugin_used='enhanced',
            success=result.success,
            confidence_score=0.8 if result.success else 0.3,
            evidence_score=0.9 if result.success else 0.2,
            execution_time=result.response_time,
            error_details=None,
            environmental_factors={'response_time': result.response_time},
            payload_characteristics={'payload': result.payload},
            waf_encountered=result.waf_detected,
            waf_type=result.waf_type,
            bypass_technique=result.bypass_used,
            response_indicators=result.indicators
        )
    
    def get_feature_names(self) -> List[str]:
        """Get names of extracted features"""
        return self.feature_names

# ============================================================================
# PERFORMANCE CALCULATOR
# ============================================================================

class PerformanceCalculator:
    """Calculate comprehensive performance metrics"""
    
    @staticmethod
    def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray, 
                         y_proba: Optional[np.ndarray] = None,
                         labels: Optional[List[str]] = None) -> PerformanceMetrics:
        """Calculate comprehensive performance metrics"""
        
        # Basic metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true, y_pred, average='weighted', zero_division=0
        )
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # Calculate TP, TN, FP, FN for binary classification
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
        else:
            # For multiclass, aggregate
            tp = np.diag(cm).sum()
            fp = cm.sum(axis=0) - np.diag(cm)
            fn = cm.sum(axis=1) - np.diag(cm)
            tn = cm.sum() - (fp + fn + tp)
            tp, fp, fn, tn = int(tp), int(fp.sum()), int(fn.sum()), int(tn.sum())
        
        # ROC AUC if probabilities available
        roc_auc = None
        if y_proba is not None and len(np.unique(y_true)) == 2:
            try:
                roc_auc = roc_auc_score(y_true, y_proba[:, 1])
            except:
                pass
        
        # Per-class metrics if labels provided
        per_class_metrics = None
        if labels:
            report = classification_report(y_true, y_pred, target_names=labels, 
                                         output_dict=True, zero_division=0)
            per_class_metrics = {k: v for k, v in report.items() 
                               if k not in ['accuracy', 'macro avg', 'weighted avg']}
        
        return PerformanceMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            confusion_matrix=cm,
            roc_auc=roc_auc,
            support={'total': len(y_true)} if support is None else dict(enumerate(support)),
            per_class_metrics=per_class_metrics
        )

# ============================================================================
# NVD TRAINING MODULE
# ============================================================================

VULN_FAMILIES = [
    'sqli', 'xss', 'ssti', 'idor', 'ssrf', 'rce', 
    'deserialization', 'auth', 'csrf', 'lfi', 'rfi', 
    'open_redirect', 'jwt', 'xxe', 'nosql'
]

def load_nvd_json_folder(folder: str) -> List[NVDSample]:
    """Load NVD JSON data for training"""
    samples = []
    
    for path in sorted(glob.glob(os.path.join(folder, "nvdcve-1.1-*.json"))):
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        for item in data.get('CVE_Items', []):
            descs = item.get('cve', {}).get('description', {}).get('description_data', [])
            text = " ".join(d.get('value', '') for d in descs)
            
            if not text or text.startswith("** REJECT **"):
                continue
            
            labels = {k: 0 for k in VULN_FAMILIES}
            text_lower = text.lower()
            
            # Pattern matching for labels
            patterns = {
                'sqli': ['sql', 'injection', 'database'],
                'xss': ['cross-site scripting', 'xss', 'script'],
                'ssti': ['template', 'jinja', 'ssti'],
                'idor': ['insecure direct object', 'idor', 'authorization'],
                'ssrf': ['server-side request forgery', 'ssrf'],
                'rce': ['remote code execution', 'rce', 'command execution'],
                'deserialization': ['deserialization', 'unserialize'],
                'auth': ['authentication', 'auth bypass'],
                'csrf': ['csrf', 'cross-site request'],
                'lfi': ['directory traversal', '../', 'local file'],
                'rfi': ['file inclusion', 'remote file'],
                'open_redirect': ['open redirect', 'url redirect'],
                'jwt': ['jwt', 'jws', 'json web token'],
                'xxe': ['xxe', 'xml external'],
                'nosql': ['nosql', 'mongodb', 'couchdb']
            }
            
            for vuln_type, keywords in patterns.items():
                if any(kw in text_lower for kw in keywords):
                    labels[vuln_type] = 1
            
            if any(labels.values()):
                samples.append(NVDSample(text=text, labels=labels))
    
    return samples

def train_vulnerability_classifier(samples: List[NVDSample], 
                                  test_size: float = 0.2,
                                  random_state: int = 42) -> Tuple[Any, Dict, Any]:
    """Train a vulnerability classifier from NVD data"""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.multioutput import MultiOutputClassifier
    from sklearn.ensemble import RandomForestClassifier
    
    X_text = [s.text for s in samples]
    Y = np.array([[s.labels.get(f, 0) for f in VULN_FAMILIES] for s in samples], dtype=int)
    
    X_train_text, X_test_text, Y_train, Y_test = train_test_split(
        X_text, Y, test_size=test_size, random_state=random_state,
        stratify=(Y.sum(axis=1) > 0)
    )
    
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)
    
    base_classifier = RandomForestClassifier(n_estimators=100, random_state=random_state)
    classifier = MultiOutputClassifier(base_classifier)
    classifier.fit(X_train, Y_train)
    
    Y_pred = classifier.predict(X_test)
    report = classification_report(
        Y_test, Y_pred, 
        target_names=VULN_FAMILIES,
        zero_division=0,
        output_dict=True
    )
    
    cm = multilabel_confusion_matrix(Y_test, Y_pred)
    
    model_bundle = {
        'classifier': classifier,
        'vectorizer': vectorizer,
        'families': VULN_FAMILIES
    }
    
    return model_bundle, report, cm

# ============================================================================
# UNIFIED CONTINUOUS LEARNING PIPELINE
# ============================================================================

class UnifiedLearningPipeline:
    """
    Enhanced unified continuous learning system with deep integration
    """
    
    def __init__(self, model_dir: str = "models/adaptive", kb=None):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.kb = kb
        
        # Metrics tracking
        self.metrics = RunMetrics()
        
        # Feature extractor
        self.feature_extractor = FeatureExtractor()
        
        # Performance calculator
        self.perf_calculator = PerformanceCalculator()
        
        # Model stores
        self.model_stores = {
            'vulnerability_classifier': ModelStore(str(self.model_dir / "vuln_classifier.joblib")),
            'success_predictor': ModelStore(str(self.model_dir / "success_predictor.joblib")),
            'payload_optimizer': ModelStore(str(self.model_dir / "payload_optimizer.joblib")),
            'false_positive_detector': ModelStore(str(self.model_dir / "fp_detector.joblib")),
            'nvd_classifier': ModelStore(str(self.model_dir / "nvd_classifier.joblib")),
            'waf_bypass_predictor': ModelStore(str(self.model_dir / "waf_bypass.joblib"))
        }
        
        # Active models
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.performance_history = defaultdict(list)
        self.learning_history = []
        
        # Experience buffers
        self.experience_buffer = queue.Queue(maxsize=10000)
        self.exploitation_results_buffer = queue.Queue(maxsize=10000)
        self.training_threshold = 100
        
        # Enhanced learner integration
        self.enhanced_learner = None
        if ENHANCED_AVAILABLE:
            try:
                self.enhanced_learner = ExploitationLearner()
                logger.info("Enhanced learner integrated")
            except:
                logger.warning("Could not initialize enhanced learner")
        
        # Load existing models
        self._load_models()
        
        # Start background training
        self.training_thread = threading.Thread(target=self._background_training, daemon=True)
        self.training_thread.start()
    
    def _load_models(self):
        """Load all existing models from disk"""
        for name, store in self.model_stores.items():
            if store.exists():
                result = store.load_with_metadata()
                if result:
                    model, metadata = result
                    self.models[name] = model
                    if metadata.get('scaler'):
                        self.scalers[name] = metadata['scaler']
                    if metadata.get('performance'):
                        self.performance_history[name].append(metadata['performance'])
                    logger.info(f"Loaded model: {name}")
        
        # Initialize missing models
        if 'vulnerability_classifier' not in self.models:
            self.models['vulnerability_classifier'] = RandomForestClassifier(
                n_estimators=100, max_depth=10, random_state=42
            )
            self.scalers['vulnerability_classifier'] = StandardScaler()
        
        if 'success_predictor' not in self.models:
            self.models['success_predictor'] = GradientBoostingClassifier(
                n_estimators=100, learning_rate=0.1, random_state=42
            )
            self.scalers['success_predictor'] = StandardScaler()
        
        if 'waf_bypass_predictor' not in self.models:
            self.models['waf_bypass_predictor'] = RandomForestClassifier(
                n_estimators=50, random_state=42
            )
            self.scalers['waf_bypass_predictor'] = StandardScaler()
    
    def record_exploitation_attempt(self, attempt: ExploitAttempt):
        """Record an exploitation attempt for learning"""
        self.experience_buffer.put(attempt)
        self.metrics.log_step("record", {
            "success": attempt.success,
            "waf_detected": attempt.waf_encountered,
            "waf_bypassed": attempt.waf_encountered and attempt.success,
            "vulnerability_type": attempt.vulnerability_type
        })
        
        # Save to persistent storage
        self._save_experience(attempt)
        
        # Trigger retraining if threshold reached
        if self.experience_buffer.qsize() >= self.training_threshold:
            self._trigger_retraining()
    
    def ingest_exploitation_result(self, result: Union['ExploitationResult', Dict]):
        """
        Ingest ExploitationResult from enhanced_adaptive_learning.py
        This is the main integration point for enhanced results
        """
        if isinstance(result, dict):
            # Convert dict to ExploitationResult if needed
            result = ExploitationResult(**result)
        
        # Convert to ExploitAttempt for unified processing
        attempt = self.feature_extractor._convert_result_to_attempt(result)
        
        # Record in main pipeline
        self.record_exploitation_attempt(attempt)
        
        # Also queue for specialized processing
        self.exploitation_results_buffer.put(result)
        
        # If enhanced learner available, feed it directly
        if self.enhanced_learner and ENHANCED_AVAILABLE:
            self.enhanced_learner.learn_from_exploitation(result)
        
        logger.debug(f"Ingested exploitation result: {result.vulnerability_type} - Success: {result.success}")
    
    def record_outcome(self, used_titles: List[str], success: bool):
        """Simple interface for recording outcomes"""
        if self.kb:
            delta = 0.1 if success else -0.05
            for title in used_titles:
                if hasattr(self.kb, 'reinforce'):
                    self.kb.reinforce([title], delta)
        
        self.metrics.log_step(success)
    
    def train_from_nvd_data(self, nvd_folder: str):
        """Train vulnerability classifier from NVD data"""
        logger.info(f"Training from NVD data in {nvd_folder}")
        
        samples = load_nvd_json_folder(nvd_folder)
        if not samples:
            logger.warning("No NVD samples found")
            return
        
        model_bundle, report, cm = train_vulnerability_classifier(samples)
        
        self.models['nvd_classifier'] = model_bundle
        self.model_stores['nvd_classifier'].save(
            model_bundle,
            metadata={'report': report, 'confusion_matrix': cm.tolist()}
        )
        
        logger.info(f"NVD classifier trained on {len(samples)} samples")
        return report
    
    def _save_experience(self, attempt: ExploitAttempt):
        """Save experience to disk"""
        experience_file = self.model_dir / "experiences.jsonl"
        
        with open(experience_file, 'a') as f:
            experience_dict = asdict(attempt)
            experience_dict['timestamp'] = attempt.timestamp.isoformat()
            json.dump(experience_dict, f)
            f.write('\n')
    
    def _background_training(self):
        """Enhanced background thread for continuous training"""
        while True:
            try:
                # Collect experiences from both buffers
                experiences = []
                exploitation_results = []
                
                # Collect from main buffer
                while len(experiences) < self.training_threshold:
                    try:
                        attempt = self.experience_buffer.get(timeout=10)
                        experiences.append(attempt)
                    except queue.Empty:
                        break
                
                # Collect from exploitation results buffer
                while not self.exploitation_results_buffer.empty():
                    try:
                        result = self.exploitation_results_buffer.get_nowait()
                        exploitation_results.append(result)
                    except queue.Empty:
                        break
                
                # Convert exploitation results to attempts
                for result in exploitation_results:
                    attempt = self.feature_extractor._convert_result_to_attempt(result)
                    experiences.append(attempt)
                
                if len(experiences) >= 50:  # Lowered threshold for more frequent training
                    self._train_models(experiences)
                    
            except Exception as e:
                logger.error(f"Background training error: {e}")
                time.sleep(60)
    
    def _train_models(self, experiences: List[ExploitAttempt]):
        """Enhanced training with performance metrics calculation"""
        logger.info(f"Training on {len(experiences)} experiences")
        
        # Prepare features using modular extractor
        X = np.array([self.feature_extractor.extract_from_attempt(exp) for exp in experiences])
        
        # Track performance for each model
        model_performance = {}
        
        # Train vulnerability classifier
        y_vuln = [exp.vulnerability_type for exp in experiences]
        if len(set(y_vuln)) > 1:
            perf = self._train_single_model('vulnerability_classifier', X, y_vuln)
            model_performance['vulnerability_classifier'] = perf
        
        # Train success predictor
        y_success = [exp.success for exp in experiences]
        perf = self._train_single_model('success_predictor', X, y_success)
        model_performance['success_predictor'] = perf
        
        # Train WAF bypass predictor
        waf_experiences = [exp for exp in experiences if exp.waf_encountered]
        if len(waf_experiences) > 10:
            X_waf = np.array([self.feature_extractor.extract_from_attempt(exp) for exp in waf_experiences])
            y_waf = [exp.success for exp in waf_experiences]  # Success means bypass worked
            perf = self._train_single_model('waf_bypass_predictor', X_waf, y_waf)
            model_performance['waf_bypass_predictor'] = perf
        
        # Train false positive detector
        y_fp = [exp.evidence_score < 0.3 and exp.confidence_score > 0.7 for exp in experiences]
        if sum(y_fp) > 0:
            perf = self._train_single_model('false_positive_detector', X, y_fp)
            model_performance['false_positive_detector'] = perf
        
        # Update feature importance
        self._update_feature_importance()
        
        # Save models with performance metrics
        self._save_all_models(model_performance)
        
        # Record training session
        self.learning_history.append({
            'timestamp': datetime.now(),
            'samples_trained': len(experiences),
            'model_performance': model_performance,
            'feature_importance': self.feature_importance
        })
        
        # Log performance summary
        self._log_performance_summary(model_performance)
        
        # Update metrics
        self.metrics.log_step("training", {"samples": len(experiences)})
    
    def _train_single_model(self, model_name: str, X: np.ndarray, y: List) -> Dict:
        """Train a single model and calculate performance metrics"""
        try:
            # Prepare data
            X_scaled = self.scalers[model_name].fit_transform(X)
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
            )
            
            # Train model
            self.models[model_name].fit(X_train, y_train)
            
            # Get predictions
            y_pred = self.models[model_name].predict(X_test)
            y_proba = None
            if hasattr(self.models[model_name], 'predict_proba'):
                y_proba = self.models[model_name].predict_proba(X_test)
            
            # Calculate performance metrics
            metrics = self.perf_calculator.calculate_metrics(y_test, y_pred, y_proba)
            
            # Store in history
            self.performance_history[model_name].append({
                'timestamp': datetime.now().isoformat(),
                'accuracy': metrics.accuracy,
                'precision': metrics.precision,
                'recall': metrics.recall,
                'f1_score': metrics.f1_score,
                'samples': len(y_test)
            })
            
            logger.info(f"{model_name} - Accuracy: {metrics.accuracy:.3f}, "
                       f"Precision: {metrics.precision:.3f}, Recall: {metrics.recall:.3f}, "
                       f"F1: {metrics.f1_score:.3f}")
            
            return asdict(metrics)
            
        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
            return {}
    
    def _update_feature_importance(self):
        """Update feature importance scores"""
        feature_names = self.feature_extractor.get_feature_names()
        
        for name, model in self.models.items():
            if hasattr(model, 'feature_importances_'):
                importance = model.feature_importances_.tolist()
                if len(importance) == len(feature_names):
                    self.feature_importance[name] = dict(zip(feature_names, importance))
                else:
                    self.feature_importance[name] = importance
    
    def _save_all_models(self, performance_metrics: Dict = None):
        """Save all models to disk with metadata"""
        for name, model in self.models.items():
            if name in self.model_stores:
                metadata = {
                    'timestamp': datetime.now().isoformat(),
                    'feature_names': self.feature_extractor.get_feature_names()
                }
                
                if name in self.scalers:
                    metadata['scaler'] = self.scalers[name]
                
                if name in self.feature_importance:
                    metadata['feature_importance'] = self.feature_importance[name]
                
                if performance_metrics and name in performance_metrics:
                    metadata['performance'] = performance_metrics[name]
                
                self.model_stores[name].save(model, metadata)
    
    def _log_performance_summary(self, performance: Dict):
        """Log performance summary"""
        for model_name, metrics in performance.items():
            if metrics:
                logger.info(f"Performance Summary - {model_name}:")
                logger.info(f"  Accuracy: {metrics.get('accuracy', 0):.3f}")
                logger.info(f"  Precision: {metrics.get('precision', 0):.3f}")
                logger.info(f"  Recall: {metrics.get('recall', 0):.3f}")
                logger.info(f"  F1 Score: {metrics.get('f1_score', 0):.3f}")
                if 'true_positives' in metrics:
                    logger.info(f"  TP: {metrics['true_positives']}, TN: {metrics['true_negatives']}")
                    logger.info(f"  FP: {metrics['false_positives']}, FN: {metrics['false_negatives']}")
    
    def calculate_performance_metrics(self, model_name: str = None) -> Dict:
        """
        Calculate current performance metrics for specified model or all models
        Returns comprehensive metrics including precision, recall, F1
        """
        if model_name:
            if model_name in self.performance_history:
                history = self.performance_history[model_name]
                if history:
                    latest = history[-1]
                    return {
                        'model': model_name,
                        'latest_metrics': latest,
                        'historical_avg': {
                            'accuracy': np.mean([h['accuracy'] for h in history]),
                            'precision': np.mean([h['precision'] for h in history]),
                            'recall': np.mean([h['recall'] for h in history]),
                            'f1_score': np.mean([h['f1_score'] for h in history])
                        },
                        'trend': self._calculate_trend(history)
                    }
        else:
            # Return metrics for all models
            all_metrics = {}
            for name in self.models.keys():
                all_metrics[name] = self.calculate_performance_metrics(name)
            return all_metrics
        
        return {}
    
    def _calculate_trend(self, history: List[Dict]) -> str:
        """Calculate performance trend"""
        if len(history) < 2:
            return 'stable'
        
        recent_f1 = [h['f1_score'] for h in history[-5:]]
        if len(recent_f1) >= 2:
            trend = np.polyfit(range(len(recent_f1)), recent_f1, 1)[0]
            if trend > 0.01:
                return 'improving'
            elif trend < -0.01:
                return 'declining'
        
        return 'stable'
    
    def _trigger_retraining(self):
        """Trigger model retraining"""
        logger.info("Triggering retraining due to experience threshold")
    
    def predict_success_probability(self, vulnerability_type: str,
                                   target_characteristics: Dict,
                                   payload_characteristics: Dict) -> float:
        """Enhanced prediction with WAF consideration"""
        mock_attempt = ExploitAttempt(
            timestamp=datetime.now(),
            target="",
            vulnerability_type=vulnerability_type,
            plugin_used="",
            success=False,
            confidence_score=target_characteristics.get('confidence', 0.5),
            evidence_score=0,
            execution_time=0,
            error_details=None,
            environmental_factors=target_characteristics,
            payload_characteristics=payload_characteristics,
            waf_encountered=target_characteristics.get('waf_detected', False),
            waf_type=target_characteristics.get('waf_type')
        )
        
        features = self.feature_extractor.extract_from_attempt(mock_attempt).reshape(1, -1)
        
        if 'success_predictor' in self.models:
            try:
                features_scaled = self.scalers['success_predictor'].transform(features)
                prob = self.models['success_predictor'].predict_proba(features_scaled)[0, 1]
                
                # Adjust for WAF if detected
                if mock_attempt.waf_encountered and 'waf_bypass_predictor' in self.models:
                    waf_features_scaled = self.scalers['waf_bypass_predictor'].transform(features)
                    bypass_prob = self.models['waf_bypass_predictor'].predict_proba(waf_features_scaled)[0, 1]
                    prob *= bypass_prob
                
                return float(prob)
            except:
                pass
        
        return 0.5
    
    def detect_false_positive(self, confidence_score: float,
                             evidence_score: float,
                             exploit_details: Dict) -> Tuple[bool, float]:
        """Enhanced false positive detection"""
        if 'false_positive_detector' in self.models:
            mock_attempt = ExploitAttempt(
                timestamp=datetime.now(),
                target="",
                vulnerability_type=exploit_details.get('type', 'unknown'),
                plugin_used="",
                success=False,
                confidence_score=confidence_score,
                evidence_score=evidence_score,
                execution_time=exploit_details.get('time', 0),
                error_details=None,
                environmental_factors=exploit_details.get('env', {}),
                payload_characteristics=exploit_details.get('payload', {})
            )
            
            features = self.feature_extractor.extract_from_attempt(mock_attempt).reshape(1, -1)
            
            try:
                features_scaled = self.scalers['false_positive_detector'].transform(features)
                fp_prob = self.models['false_positive_detector'].predict_proba(features_scaled)[0, 1]
                return fp_prob > 0.5, float(fp_prob)
            except:
                pass
        
        # Fallback heuristic
        if evidence_score < 0.3 and confidence_score > 0.7:
            return True, 0.8
        return False, 0.2
    
    def get_optimal_payload_characteristics(self, vulnerability_type: str,
                                           target_info: Dict) -> Dict:
        """Enhanced payload optimization with ML insights"""
        recommendations = {
            'encoding_layers': 1,
            'obfuscation_level': 2,
            'complexity_score': 0.5,
            'recommended_techniques': []
        }
        
        # Use feature importance to guide optimization
        if 'payload_optimizer' in self.feature_importance:
            importance = self.feature_importance['payload_optimizer']
            
            # Find most important payload features
            payload_features = {k: v for k, v in importance.items() if 'payload' in k}
            if payload_features:
                top_feature = max(payload_features, key=payload_features.get)
                
                if 'encoding' in top_feature:
                    recommendations['encoding_layers'] = 2
                    recommendations['recommended_techniques'].append('multi-encoding')
                
                if 'obfuscated' in top_feature:
                    recommendations['obfuscation_level'] = 3
                    recommendations['recommended_techniques'].append('heavy-obfuscation')
        
        # WAF-specific recommendations
        if target_info.get('waf_detected'):
            recommendations['encoding_layers'] = 3
            recommendations['recommended_techniques'].append('waf-evasion')
            recommendations['complexity_score'] = 0.8
        
        return recommendations
    
    def get_learning_insights(self) -> Dict:
        """Enhanced learning insights with performance metrics"""
        return {
            'total_experiences': self.experience_buffer.qsize(),
            'exploitation_results': self.exploitation_results_buffer.qsize(),
            'model_performance': self.calculate_performance_metrics(),
            'feature_importance': self.feature_importance,
            'training_history': self.learning_history[-10:],
            'metrics': self.metrics.summary(),
            'models_loaded': list(self.models.keys()),
            'performance_trends': {
                name: self._calculate_trend(history)
                for name, history in self.performance_history.items()
            },
            'enhanced_learner_active': self.enhanced_learner is not None
        }

# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

ContinuousLearningPipeline = UnifiedLearningPipeline

class LearningLoop:
    """Backward compatibility wrapper"""
    def __init__(self, kb=None):
        self.pipeline = UnifiedLearningPipeline(kb=kb)
    
    def record_outcome(self, used_titles: List[str], success: bool):
        self.pipeline.record_outcome(used_titles, success)

# Helper functions
def create_model_store(model_type: str = 'generic', path: str = None) -> ModelStore:
    """Create a model store"""
    if not path:
        path = f"models/{model_type}_model.joblib"
    return ModelStore(path)

def save(key: str, data: Any, metadata: Dict = None):
    """Global save function"""
    store = ModelStore(f"models/{key}.joblib")
    store.save(data, metadata)

def load(key: str) -> Optional[Any]:
    """Global load function"""
    store = ModelStore(f"models/{key}.joblib")
    return store.load()

def exists(key: str) -> bool:
    """Check if model exists"""
    store = ModelStore(f"models/{key}.joblib")
    return store.exists()

def delete(key: str) -> bool:
    """Delete model"""
    store = ModelStore(f"models/{key}.joblib")
    return store.delete()

def get_file_info(key: str) -> Optional[Dict]:
    """Get file info"""
    store = ModelStore(f"models/{key}.joblib")
    return store.get_file_info()

def save_with_metadata(key: str, model: Any, metadata: Dict):
    """Save with metadata"""
    store = ModelStore(f"models/{key}.joblib")
    store.save(model, metadata)

def load_with_metadata(key: str) -> Optional[Tuple[Any, Dict]]:
    """Load with metadata"""
    store = ModelStore(f"models/{key}.joblib")
    return store.load_with_metadata()

def train_mapper(samples: List, test_size: float = 0.2, random_state: int = 42):
    """Train mapper"""
    return train_vulnerability_classifier(samples, test_size, random_state)
