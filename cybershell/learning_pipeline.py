"""
Unified Learning Pipeline
==========================
Combines all learning, training, metrics, and persistence functionality.
Merges continuous_learning_pipeline.py, metrics.py, persistence.py, train.py, and learning.py
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
from typing import Dict, List, Tuple, Optional, Any, TypeVar, Generic
from dataclasses import dataclass, asdict, field
import logging
import threading
import queue

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, classification_report, multilabel_confusion_matrix
import joblib

logger = logging.getLogger(__name__)

# Type variable for generic model storage
T = TypeVar('T')

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

@dataclass
class RunMetrics:
    """Simple metrics tracking (from adaptive/metrics.py)"""
    start_ts: float = field(default_factory=time.time)
    steps: int = 0
    success: int = 0
    fail: int = 0
    
    def log_step(self, step_name: str, data: Dict[str, Any] = None) -> None:
        """Enhanced log_step that accepts both bool and dict"""
        self.steps += 1
        
        # Handle different input types
        if isinstance(step_name, bool):
            # Legacy bool interface
            ok = step_name
            self.success += int(ok)
            self.fail += int(not ok)
        elif isinstance(data, dict):
            # New dict interface
            ok = data.get('success', True)
            self.success += int(ok)
            self.fail += int(not ok)
        else:
            # Default to success
            self.success += 1
    
    def summary(self) -> Dict[str, Any]:
        dur = time.perf_counter() - self.start_ts
        return {
            'steps': self.steps,
            'success': self.success,
            'fail': self.fail,
            'success_rate': float(self.success) / max(1, self.steps),
            'duration_s': dur,
        }

@dataclass
class NVDSample:
    """Sample from NVD data for training (from adaptive/train.py)"""
    text: str
    labels: Dict[str, int]

# ============================================================================
# MODEL PERSISTENCE (from adaptive/persistence.py)
# ============================================================================

class ModelStore(Generic[T]):
    """
    Type-safe model storage with atomic file operations.
    
    WARNING: Uses joblib/pickle - only load models from trusted sources.
    """
    
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
                
                # Save model with metadata if provided
                if metadata:
                    bundle = {'model': model, 'metadata': metadata}
                else:
                    bundle = model
                
                joblib.dump(bundle, tmp_file)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            
            # Atomic replace
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
            
            # Handle bundled data with metadata
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
# NVD TRAINING (from adaptive/train.py)
# ============================================================================

# Vulnerability families for classification
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
            
            # Label extraction
            labels = {k: 0 for k in VULN_FAMILIES}
            text_lower = text.lower()
            
            # Pattern matching for labels
            if "sql" in text_lower:
                labels['sqli'] = 1
            if "cross-site scripting" in text_lower or "xss" in text_lower:
                labels['xss'] = 1
            if "template" in text_lower or "jinja" in text_lower:
                labels['ssti'] = 1
            if "insecure direct object" in text_lower or "idor" in text_lower:
                labels['idor'] = 1
            if "server-side request forgery" in text_lower or "ssrf" in text_lower:
                labels['ssrf'] = 1
            if "remote code execution" in text_lower or "rce" in text_lower:
                labels['rce'] = 1
            if "deserialization" in text_lower:
                labels['deserialization'] = 1
            if "authentication" in text_lower or "auth" in text_lower:
                labels['auth'] = 1
            if "csrf" in text_lower:
                labels['csrf'] = 1
            if "directory traversal" in text_lower or "../" in text_lower:
                labels['lfi'] = 1
            if "file inclusion" in text_lower:
                labels['rfi'] = 1
            if "open redirect" in text_lower:
                labels['open_redirect'] = 1
            if "jwt" in text_lower or "jws" in text_lower:
                labels['jwt'] = 1
            if "xxe" in text_lower or "xml external" in text_lower:
                labels['xxe'] = 1
            if "nosql" in text_lower or "mongodb" in text_lower:
                labels['nosql'] = 1
            
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
    
    # Prepare data
    X_text = [s.text for s in samples]
    Y = np.array([[s.labels.get(f, 0) for f in VULN_FAMILIES] for s in samples], dtype=int)
    
    # Split data
    X_train_text, X_test_text, Y_train, Y_test = train_test_split(
        X_text, Y, test_size=test_size, random_state=random_state,
        stratify=(Y.sum(axis=1) > 0)
    )
    
    # Vectorize text
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)
    
    # Train classifier
    base_classifier = RandomForestClassifier(n_estimators=100, random_state=random_state)
    classifier = MultiOutputClassifier(base_classifier)
    classifier.fit(X_train, Y_train)
    
    # Evaluate
    Y_pred = classifier.predict(X_test)
    report = classification_report(
        Y_test, Y_pred, 
        target_names=VULN_FAMILIES,
        zero_division=0,
        output_dict=True
    )
    
    cm = multilabel_confusion_matrix(Y_test, Y_pred)
    
    # Bundle model with vectorizer
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
    Unified continuous learning system combining all learning functionality
    """
    
    def __init__(self, model_dir: str = "models/adaptive", kb=None):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.kb = kb  # Optional knowledge base reference
        
        # Metrics tracking
        self.metrics = RunMetrics()
        
        # Model stores
        self.model_stores = {
            'vulnerability_classifier': ModelStore(str(self.model_dir / "vuln_classifier.joblib")),
            'success_predictor': ModelStore(str(self.model_dir / "success_predictor.joblib")),
            'payload_optimizer': ModelStore(str(self.model_dir / "payload_optimizer.joblib")),
            'false_positive_detector': ModelStore(str(self.model_dir / "fp_detector.joblib")),
            'nvd_classifier': ModelStore(str(self.model_dir / "nvd_classifier.joblib"))
        }
        
        # Active models
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.learning_history = []
        self.experience_buffer = queue.Queue(maxsize=10000)
        self.training_threshold = 100
        
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
        
        if 'false_positive_detector' not in self.models:
            self.models['false_positive_detector'] = RandomForestClassifier(
                n_estimators=50, random_state=42
            )
            self.scalers['false_positive_detector'] = StandardScaler()
    
    def record_exploitation_attempt(self, attempt: ExploitAttempt):
        """Record an exploitation attempt for learning"""
        self.experience_buffer.put(attempt)
        self.metrics.log_step("record", {"success": attempt.success})
        
        # Save to persistent storage
        self._save_experience(attempt)
        
        # Trigger retraining if threshold reached
        if self.experience_buffer.qsize() >= self.training_threshold:
            self._trigger_retraining()
    
    def record_outcome(self, used_titles: List[str], success: bool):
        """Simple interface for recording outcomes (from learning.py)"""
        if self.kb:
            # Reinforce knowledge base
            delta = 0.1 if success else -0.05
            for title in used_titles:
                if hasattr(self.kb, 'reinforce'):
                    self.kb.reinforce([title], delta)
        
        # Also track in metrics
        self.metrics.log_step(success)
    
    def train_from_nvd_data(self, nvd_folder: str):
        """Train vulnerability classifier from NVD data"""
        logger.info(f"Training from NVD data in {nvd_folder}")
        
        # Load samples
        samples = load_nvd_json_folder(nvd_folder)
        if not samples:
            logger.warning("No NVD samples found")
            return
        
        # Train classifier
        model_bundle, report, cm = train_vulnerability_classifier(samples)
        
        # Save model
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
    
    def _extract_features(self, attempt: ExploitAttempt) -> np.ndarray:
        """Extract features from exploitation attempt"""
        features = []
        
        # Basic features
        features.append(attempt.confidence_score)
        features.append(attempt.evidence_score)
        features.append(attempt.execution_time)
        
        # Vulnerability type encoding
        vuln_types = ['SQLI', 'XSS', 'RCE', 'IDOR', 'SSRF', 'XXE', 'SSTI', 'LFI']
        for vt in vuln_types:
            features.append(1.0 if attempt.vulnerability_type == vt else 0.0)
        
        # Environmental factors
        env_factors = attempt.environmental_factors or {}
        features.append(env_factors.get('response_time', 0))
        features.append(env_factors.get('waf_detected', 0))
        features.append(env_factors.get('rate_limit_encountered', 0))
        
        # Payload characteristics
        payload_chars = attempt.payload_characteristics or {}
        features.append(payload_chars.get('length', 0))
        features.append(payload_chars.get('complexity_score', 0))
        features.append(payload_chars.get('encoding_layers', 0))
        
        # Time features
        hour = attempt.timestamp.hour
        features.append(np.sin(2 * np.pi * hour / 24))
        features.append(np.cos(2 * np.pi * hour / 24))
        
        return np.array(features)
    
    def _background_training(self):
        """Background thread for continuous training"""
        while True:
            try:
                experiences = []
                while len(experiences) < self.training_threshold:
                    attempt = self.experience_buffer.get(timeout=60)
                    experiences.append(attempt)
                
                if experiences:
                    self._train_models(experiences)
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Background training error: {e}")
    
    def _train_models(self, experiences: List[ExploitAttempt]):
        """Train all models on new experiences"""
        logger.info(f"Training on {len(experiences)} experiences")
        
        # Prepare features
        X = np.array([self._extract_features(exp) for exp in experiences])
        
        # Train each model
        for model_name, y_extractor in [
            ('vulnerability_classifier', lambda exp: exp.vulnerability_type),
            ('success_predictor', lambda exp: exp.success),
            ('false_positive_detector', lambda exp: exp.evidence_score < 0.3 and exp.confidence_score > 0.7)
        ]:
            y = [y_extractor(exp) for exp in experiences]
            self._train_single_model(model_name, X, y)
        
        # Update feature importance
        self._update_feature_importance()
        
        # Save models
        self._save_all_models()
        
        # Record training
        self.learning_history.append({
            'timestamp': datetime.now(),
            'samples_trained': len(experiences),
            'model_performance': self._evaluate_models(X, experiences)
        })
        
        # Update metrics
        self.metrics.log_step("training", {"samples": len(experiences)})
    
    def _train_single_model(self, model_name: str, X: np.ndarray, y: List):
        """Train a single model"""
        try:
            X_scaled = self.scalers[model_name].fit_transform(X)
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42
            )
            
            self.models[model_name].fit(X_train, y_train)
            score = self.models[model_name].score(X_test, y_test)
            logger.info(f"{model_name} accuracy: {score:.3f}")
            
        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
    
    def _update_feature_importance(self):
        """Update feature importance scores"""
        for name, model in self.models.items():
            if hasattr(model, 'feature_importances_'):
                self.feature_importance[name] = model.feature_importances_.tolist()
    
    def _save_all_models(self):
        """Save all models to disk"""
        for name, model in self.models.items():
            if name in self.model_stores:
                metadata = {}
                if name in self.scalers:
                    metadata['scaler'] = self.scalers[name]
                if name in self.feature_importance:
                    metadata['feature_importance'] = self.feature_importance[name]
                
                self.model_stores[name].save(model, metadata)
    
    def _evaluate_models(self, X: np.ndarray, experiences: List[ExploitAttempt]) -> Dict:
        """Evaluate model performance"""
        performance = {}
        
        for model_name in ['vulnerability_classifier', 'success_predictor']:
            if model_name not in self.models:
                continue
            
            try:
                X_scaled = self.scalers[model_name].transform(X)
                
                if model_name == 'vulnerability_classifier':
                    y_true = [exp.vulnerability_type for exp in experiences]
                else:
                    y_true = [exp.success for exp in experiences]
                
                cv_scores = cross_val_score(self.models[model_name], X_scaled, y_true, cv=3)
                performance[model_name] = {
                    'cv_mean': float(cv_scores.mean()),
                    'cv_std': float(cv_scores.std())
                }
                
            except Exception as e:
                logger.error(f"Error evaluating {model_name}: {e}")
        
        return performance
    
    def _trigger_retraining(self):
        """Trigger model retraining"""
        logger.info("Triggering retraining due to experience threshold")
    
    def predict_success_probability(self, vulnerability_type: str,
                                   target_characteristics: Dict,
                                   payload_characteristics: Dict) -> float:
        """Predict probability of successful exploitation"""
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
            payload_characteristics=payload_characteristics
        )
        
        features = self._extract_features(mock_attempt).reshape(1, -1)
        
        if 'success_predictor' in self.models:
            try:
                features_scaled = self.scalers['success_predictor'].transform(features)
                prob = self.models['success_predictor'].predict_proba(features_scaled)[0, 1]
                return float(prob)
            except:
                pass
        
        return 0.5
    
    def detect_false_positive(self, confidence_score: float,
                             evidence_score: float,
                             exploit_details: Dict) -> Tuple[bool, float]:
        """Detect potential false positives"""
        if evidence_score < 0.3 and confidence_score > 0.7:
            return True, 0.8
        return False, 0.2
    
    def get_optimal_payload_characteristics(self, vulnerability_type: str,
                                           target_info: Dict) -> Dict:
        """Get optimal payload characteristics based on learning"""
        return {
            'encoding_layers': 1,
            'obfuscation_level': 2,
            'complexity_score': 0.5,
            'recommended_techniques': []
        }
    
    def get_learning_insights(self) -> Dict:
        """Get insights from the learning system"""
        return {
            'total_experiences': self.experience_buffer.qsize(),
            'model_performance': self.learning_history[-1] if self.learning_history else {},
            'feature_importance': self.feature_importance,
            'training_history': self.learning_history[-10:],
            'metrics': self.metrics.summary(),
            'models_loaded': list(self.models.keys())
        }

# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

# Aliases for backward compatibility
ContinuousLearningPipeline = UnifiedLearningPipeline

class LearningLoop:
    """Backward compatibility wrapper"""
    def __init__(self, kb=None):
        self.pipeline = UnifiedLearningPipeline(kb=kb)
    
    def record_outcome(self, used_titles: List[str], success: bool):
        self.pipeline.record_outcome(used_titles, success)

# Helper functions for backward compatibility
def create_model_store(model_type: str = 'generic', path: str = None) -> ModelStore:
    """Create a model store (backward compatible)"""
    if not path:
        path = f"models/{model_type}_model.joblib"
    return ModelStore(path)

def save(key: str, data: Any, metadata: Dict = None):
    """Global save function (backward compatible)"""
    store = ModelStore(f"models/{key}.joblib")
    store.save(data, metadata)

def load(key: str) -> Optional[Any]:
    """Global load function (backward compatible)"""
    store = ModelStore(f"models/{key}.joblib")
    return store.load()

def exists(key: str) -> bool:
    """Check if model exists (backward compatible)"""
    store = ModelStore(f"models/{key}.joblib")
    return store.exists()

def delete(key: str) -> bool:
    """Delete model (backward compatible)"""
    store = ModelStore(f"models/{key}.joblib")
    return store.delete()

def get_file_info(key: str) -> Optional[Dict]:
    """Get file info (backward compatible)"""
    store = ModelStore(f"models/{key}.joblib")
    return store.get_file_info()

def save_with_metadata(key: str, model: Any, metadata: Dict):
    """Save with metadata (backward compatible)"""
    store = ModelStore(f"models/{key}.joblib")
    store.save(model, metadata)

def load_with_metadata(key: str) -> Optional[Tuple[Any, Dict]]:
    """Load with metadata (backward compatible)"""
    store = ModelStore(f"models/{key}.joblib")
    return store.load_with_metadata()

# Export functions for NVD training
def train_mapper(samples: List, test_size: float = 0.2, random_state: int = 42):
    """Train mapper (backward compatible with adaptive/train.py)"""
    return train_vulnerability_classifier(samples, test_size, random_state)
