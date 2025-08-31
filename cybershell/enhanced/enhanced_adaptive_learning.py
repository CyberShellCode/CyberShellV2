"""
Enhanced Adaptive Learning for WAF Evasion
Improves ML models to learn from exploitation results and adapt to WAF patterns
"""

import numpy as np
import time
import json
import pickle
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
from collections import defaultdict
import logging

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Neural network for deep pattern learning
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class WAFPattern:
    """WAF behavior pattern"""
    waf_type: str
    trigger_pattern: str
    blocked_payload: str
    evasion_technique: Optional[str] = None
    success: bool = False
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ExploitationResult:
    """Result of exploitation attempt with learning data"""
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
    timestamp: float = field(default_factory=time.time)


@dataclass
class AdaptiveModel:
    """Adaptive model for specific target/WAF combination"""
    target_domain: str
    waf_type: str
    successful_patterns: List[str]
    failed_patterns: List[str]
    evasion_techniques: Dict[str, float]  # technique -> success_rate
    model: Optional[Any] = None
    last_updated: float = field(default_factory=time.time)


class WAFPatternLearner:
    """Learns WAF patterns and evasion techniques"""
    
    def __init__(self):
        self.waf_patterns = defaultdict(list)
        self.evasion_success = defaultdict(lambda: defaultdict(float))
        self.pattern_vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.pattern_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
    
    def learn_from_blocking(self, waf_type: str, blocked_payload: str, 
                           response_indicators: List[str]):
        """Learn what triggers WAF blocking"""
        
        # Extract features from blocked payload
        features = self._extract_payload_features(blocked_payload)
        
        pattern = WAFPattern(
            waf_type=waf_type,
            trigger_pattern=self._identify_trigger_pattern(blocked_payload, response_indicators),
            blocked_payload=blocked_payload,
            success=False
        )
        
        self.waf_patterns[waf_type].append(pattern)
        
        # Update pattern model if we have enough data
        if len(self.waf_patterns[waf_type]) >= 20:
            self._update_pattern_model(waf_type)
    
    def learn_from_success(self, waf_type: str, successful_payload: str,
                          evasion_technique: str):
        """Learn successful evasion techniques"""
        
        pattern = WAFPattern(
            waf_type=waf_type,
            trigger_pattern="",
            blocked_payload="",
            evasion_technique=evasion_technique,
            success=True,
            confidence=0.9
        )
        
        self.waf_patterns[waf_type].append(pattern)
        
        # Update evasion success rates
        self.evasion_success[waf_type][evasion_technique] += 1
    
    def predict_blocking_probability(self, payload: str, waf_type: str) -> float:
        """Predict if payload will be blocked by WAF"""
        
        if not self.is_trained or waf_type not in self.waf_patterns:
            return 0.5  # Unknown
        
        try:
            # Vectorize payload
            payload_vector = self.pattern_vectorizer.transform([payload])
            
            # Predict blocking probability
            prob = self.pattern_model.predict_proba(payload_vector)[0][1]
            return float(prob)
        except:
            return 0.5
    
    def suggest_evasion_technique(self, waf_type: str, payload: str) -> str:
        """Suggest best evasion technique for WAF"""
        
        if waf_type not in self.evasion_success:
            return "encoding"  # Default
        
        # Sort techniques by success rate
        techniques = self.evasion_success[waf_type]
        if not techniques:
            return "encoding"
        
        best_technique = max(techniques.items(), key=lambda x: x[1])[0]
        return best_technique
    
    def _extract_payload_features(self, payload: str) -> Dict[str, Any]:
        """Extract features from payload for learning"""
        
        features = {
            'length': len(payload),
            'has_quotes': "'" in payload or '"' in payload,
            'has_sql_keywords': any(kw in payload.lower() for kw in ['select', 'union', 'from']),
            'has_script_tags': '<script' in payload.lower(),
            'has_encoding': '%' in payload,
            'special_char_ratio': len([c for c in payload if not c.isalnum()]) / max(1, len(payload)),
            'entropy': self._calculate_entropy(payload)
        }
        
        return features
    
    def _identify_trigger_pattern(self, payload: str, indicators: List[str]) -> str:
        """Identify what part of payload triggered WAF"""
        
        # Common trigger patterns
        patterns = [
            r'<script[^>]*>',
            r'(union|select|from|where)',
            r'(\.\.\/|\.\.\\)',
            r'(exec|system|eval)\s*\(',
            r'javascript:',
            r'on\w+\s*=',
        ]
        
        import re
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return pattern
        
        # Check indicators for hints
        for indicator in indicators:
            if 'sql' in indicator.lower():
                return 'sql_pattern'
            elif 'xss' in indicator.lower() or 'script' in indicator.lower():
                return 'xss_pattern'
            elif 'traversal' in indicator.lower():
                return 'traversal_pattern'
        
        return 'unknown_pattern'
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        from collections import Counter
        import math
        
        prob = [float(count) / len(text) for count in Counter(text).values()]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        
        return entropy
    
    def _update_pattern_model(self, waf_type: str):
        """Update ML model for pattern recognition"""
        
        patterns = self.waf_patterns[waf_type]
        if len(patterns) < 20:
            return
        
        # Prepare training data
        X_text = [p.blocked_payload for p in patterns]
        y = [0 if p.success else 1 for p in patterns]  # 1 = blocked
        
        try:
            # Fit vectorizer and model
            X = self.pattern_vectorizer.fit_transform(X_text)
            self.pattern_model.fit(X, y)
            self.is_trained = True
            
            logger.info(f"Updated pattern model for {waf_type} with {len(patterns)} samples")
        except Exception as e:
            logger.error(f"Failed to update pattern model: {e}")


class ExploitationLearner:
    """Main learning system for exploitation"""
    
    def __init__(self, model_dir: str = "models/adaptive"):
        self.model_dir = model_dir
        self.waf_learner = WAFPatternLearner()
        self.target_models = {}  # target -> AdaptiveModel
        self.exploitation_history = []
        self.success_patterns = defaultdict(list)
        self.failure_patterns = defaultdict(list)
        
        # Feature extractors
        self.payload_vectorizer = CountVectorizer(max_features=500, ngram_range=(1, 2))
        self.response_vectorizer = TfidfVectorizer(max_features=500)
        
        # Main models
        self.vulnerability_classifier = RandomForestClassifier(n_estimators=100)
        self.success_predictor = GradientBoostingClassifier(n_estimators=100)
        self.waf_detector = RandomForestClassifier(n_estimators=50)
        
        # Neural network for deep learning (if available)
        self.deep_model = None
        if TF_AVAILABLE:
            self.deep_model = self._build_deep_model()
        
        self.is_trained = False
        self._load_models()
    
    def _build_deep_model(self):
        """Build deep learning model for pattern recognition"""
        if not TF_AVAILABLE:
            return None
        
        model = keras.Sequential([
            layers.Dense(256, activation='relu', input_shape=(1000,)),
            layers.Dropout(0.3),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu'),
            layers.Dense(32, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def learn_from_exploitation(self, result: ExploitationResult):
        """Learn from exploitation attempt"""
        
        # Store in history
        self.exploitation_history.append(result)
        
        # Learn WAF patterns
        if result.waf_detected and result.waf_type:
            if result.success:
                self.waf_learner.learn_from_success(
                    result.waf_type,
                    result.payload,
                    result.bypass_used or "unknown"
                )
            else:
                self.waf_learner.learn_from_blocking(
                    result.waf_type,
                    result.payload,
                    result.indicators
                )
        
        # Update success/failure patterns
        if result.success:
            self.success_patterns[result.vulnerability_type].append(result.payload)
        else:
            self.failure_patterns[result.vulnerability_type].append(result.payload)
        
        # Update target-specific model
        self._update_target_model(result)
        
        # Retrain models periodically
        if len(self.exploitation_history) % 100 == 0:
            self.retrain_models()
    
    def _update_target_model(self, result: ExploitationResult):
        """Update target-specific adaptive model"""
        
        from urllib.parse import urlparse
        domain = urlparse(result.target).netloc
        
        if domain not in self.target_models:
            self.target_models[domain] = AdaptiveModel(
                target_domain=domain,
                waf_type=result.waf_type or "unknown",
                successful_patterns=[],
                failed_patterns=[],
                evasion_techniques={}
            )
        
        model = self.target_models[domain]
        
        if result.success:
            model.successful_patterns.append(result.payload)
            if result.bypass_used:
                current_rate = model.evasion_techniques.get(result.bypass_used, 0)
                model.evasion_techniques[result.bypass_used] = (current_rate + 1) / 2
        else:
            model.failed_patterns.append(result.payload)
            if result.bypass_used:
                current_rate = model.evasion_techniques.get(result.bypass_used, 1)
                model.evasion_techniques[result.bypass_used] = current_rate * 0.8
        
        model.last_updated = time.time()
    
    def predict_exploitation_success(self, target: str, vulnerability_type: str,
                                    payload: str) -> Tuple[float, Dict[str, Any]]:
        """Predict success probability and suggest improvements"""
        
        # Extract features
        features = self._extract_features(target, vulnerability_type, payload)
        
        # Default prediction
        base_probability = 0.5
        suggestions = {}
        
        # Use target-specific model if available
        from urllib.parse import urlparse
        domain = urlparse(target).netloc
        
        if domain in self.target_models:
            model = self.target_models[domain]
            
            # Check against known patterns
            if any(payload.startswith(p[:10]) for p in model.successful_patterns):
                base_probability += 0.2
            
            if any(payload.startswith(p[:10]) for p in model.failed_patterns):
                base_probability -= 0.3
            
            # Suggest best evasion technique
            if model.evasion_techniques:
                best_technique = max(model.evasion_techniques.items(), key=lambda x: x[1])
                suggestions['recommended_evasion'] = best_technique[0]
                suggestions['evasion_confidence'] = best_technique[1]
        
        # Use ML models if trained
        if self.is_trained:
            try:
                # Prepare features for ML
                X = self._prepare_features_for_ml([features])
                
                # Predict with ensemble
                prob1 = self.success_predictor.predict_proba(X)[0][1]
                
                # Average predictions
                base_probability = (base_probability + prob1) / 2
                
                # Use deep model if available
                if self.deep_model and TF_AVAILABLE:
                    deep_prob = self.deep_model.predict(X)[0][0]
                    base_probability = (base_probability + deep_prob) / 2
                
            except Exception as e:
                logger.error(f"Prediction error: {e}")
        
        # Check WAF blocking probability
        waf_block_prob = 0.0
        if domain in self.target_models and self.target_models[domain].waf_type:
            waf_block_prob = self.waf_learner.predict_blocking_probability(
                payload,
                self.target_models[domain].waf_type
            )
            
            if waf_block_prob > 0.7:
                suggestions['waf_evasion_needed'] = True
                suggestions['suggested_technique'] = self.waf_learner.suggest_evasion_technique(
                    self.target_models[domain].waf_type,
                    payload
                )
        
        # Adjust probability based on WAF
        final_probability = base_probability * (1 - waf_block_prob * 0.5)
        
        # Add confidence metrics
        suggestions['confidence'] = self._calculate_confidence(features, len(self.exploitation_history))
        suggestions['waf_block_probability'] = waf_block_prob
        
        return final_probability, suggestions
    
    def _extract_features(self, target: str, vuln_type: str, payload: str) -> Dict:
        """Extract features for ML"""
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        
        features = {
            # Target features
            'domain_length': len(parsed.netloc),
            'path_depth': len(parsed.path.split('/')),
            'has_params': bool(parsed.query),
            'is_https': parsed.scheme == 'https',
            
            # Vulnerability type features
            'vuln_type': vuln_type,
            'is_sqli': 'sql' in vuln_type.lower(),
            'is_xss': 'xss' in vuln_type.lower(),
            'is_rce': 'rce' in vuln_type.lower() or 'command' in vuln_type.lower(),
            
            # Payload features
            'payload_length': len(payload),
            'payload_entropy': self.waf_learner._calculate_entropy(payload),
            'has_encoding': '%' in payload or '\\' in payload,
            'special_chars': len([c for c in payload if not c.isalnum()]),
            'keyword_count': sum(1 for kw in ['select', 'script', 'exec', 'union'] if kw in payload.lower()),
            
            # Historical features
            'previous_attempts': len([h for h in self.exploitation_history if parsed.netloc in h.target]),
            'success_rate': self._get_historical_success_rate(parsed.netloc)
        }
        
        return features
    
    def _prepare_features_for_ml(self, features_list: List[Dict]) -> np.ndarray:
        """Prepare features for ML models"""
        
        # Convert to numeric array
        numeric_features = []
        
        for features in features_list:
            row = [
                features.get('domain_length', 0),
                features.get('path_depth', 0),
                int(features.get('has_params', False)),
                int(features.get('is_https', False)),
                int(features.get('is_sqli', False)),
                int(features.get('is_xss', False)),
                int(features.get('is_rce', False)),
                features.get('payload_length', 0),
                features.get('payload_entropy', 0),
                int(features.get('has_encoding', False)),
                features.get('special_chars', 0),
                features.get('keyword_count', 0),
                features.get('previous_attempts', 0),
                features.get('success_rate', 0)
            ]
            numeric_features.append(row)
        
        return np.array(numeric_features)
    
    def _get_historical_success_rate(self, domain: str) -> float:
        """Get historical success rate for domain"""
        
        domain_attempts = [h for h in self.exploitation_history if domain in h.target]
        
        if not domain_attempts:
            return 0.5
        
        successes = sum(1 for h in domain_attempts if h.success)
        return successes / len(domain_attempts)
    
    def _calculate_confidence(self, features: Dict, history_size: int) -> float:
        """Calculate confidence in prediction"""
        
        confidence = 0.5
        
        # More history = more confidence
        if history_size > 100:
            confidence += 0.2
        elif history_size > 50:
            confidence += 0.1
        
        # Previous attempts on target
        if features.get('previous_attempts', 0) > 10:
            confidence += 0.2
        elif features.get('previous_attempts', 0) > 5:
            confidence += 0.1
        
        return min(confidence, 0.9)
    
    def retrain_models(self):
        """Retrain all models with accumulated data"""
        
        if len(self.exploitation_history) < 50:
            logger.info("Not enough data for retraining")
            return
        
        logger.info(f"Retraining models with {len(self.exploitation_history)} samples")
        
        # Prepare training data
        X = []
        y_success = []
        y_waf = []
        
        for result in self.exploitation_history:
            features = self._extract_features(
                result.target,
                result.vulnerability_type,
                result.payload
            )
            X.append(features)
            y_success.append(int(result.success))
            y_waf.append(int(result.waf_detected))
        
        X = self._prepare_features_for_ml(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_success, test_size=0.2, random_state=42
        )
        
        # Train success predictor
        try:
            self.success_predictor.fit(X_train, y_train)
            score = self.success_predictor.score(X_test, y_test)
            logger.info(f"Success predictor accuracy: {score:.3f}")
            
            # Train WAF detector
            X_train_waf, X_test_waf, y_train_waf, y_test_waf = train_test_split(
                X, y_waf, test_size=0.2, random_state=42
            )
            self.waf_detector.fit(X_train_waf, y_train_waf)
            waf_score = self.waf_detector.score(X_test_waf, y_test_waf)
            logger.info(f"WAF detector accuracy: {waf_score:.3f}")
            
            # Train deep model if available
            if self.deep_model and TF_AVAILABLE:
                # Normalize features
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)
                
                X_train_deep, X_test_deep, y_train_deep, y_test_deep = train_test_split(
                    X_scaled, y_success, test_size=0.2, random_state=42
                )
                
                # Pad to expected input size
                X_train_padded = np.pad(X_train_deep, ((0, 0), (0, 1000 - X_train_deep.shape[1])))
                X_test_padded = np.pad(X_test_deep, ((0, 0), (0, 1000 - X_test_deep.shape[1])))
                
                self.deep_model.fit(
                    X_train_padded, y_train_deep,
                    epochs=10,
                    batch_size=32,
                    validation_data=(X_test_padded, y_test_deep),
                    verbose=0
                )
                
                deep_score = self.deep_model.evaluate(X_test_padded, y_test_deep, verbose=0)[1]
                logger.info(f"Deep model accuracy: {deep_score:.3f}")
            
            self.is_trained = True
            self._save_models()
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
    
    def _save_models(self):
        """Save trained models"""
        
        import os
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Save sklearn models
        joblib.dump(self.success_predictor, f"{self.model_dir}/success_predictor.joblib")
        joblib.dump(self.waf_detector, f"{self.model_dir}/waf_detector.joblib")
        
        # Save WAF patterns
        with open(f"{self.model_dir}/waf_patterns.json", 'w') as f:
            json.dump(
                {k: [asdict(p) for p in v] for k, v in self.waf_learner.waf_patterns.items()},
                f
            )
        
        # Save target models
        with open(f"{self.model_dir}/target_models.pkl", 'wb') as f:
            pickle.dump(self.target_models, f)
        
        # Save deep model if available
        if self.deep_model and TF_AVAILABLE:
            self.deep_model.save(f"{self.model_dir}/deep_model.h5")
        
        logger.info(f"Models saved to {self.model_dir}")
    
    def _load_models(self):
        """Load existing models"""
        
        import os
        
        try:
            if os.path.exists(f"{self.model_dir}/success_predictor.joblib"):
                self.success_predictor = joblib.load(f"{self.model_dir}/success_predictor.joblib")
                self.is_trained = True
                logger.info("Loaded success predictor")
            
            if os.path.exists(f"{self.model_dir}/waf_detector.joblib"):
                self.waf_detector = joblib.load(f"{self.model_dir}/waf_detector.joblib")
                logger.info("Loaded WAF detector")
            
            if os.path.exists(f"{self.model_dir}/waf_patterns.json"):
                with open(f"{self.model_dir}/waf_patterns.json", 'r') as f:
                    patterns = json.load(f)
                    for waf_type, pattern_list in patterns.items():
                        self.waf_learner.waf_patterns[waf_type] = [
                            WAFPattern(**p) for p in pattern_list
                        ]
                logger.info("Loaded WAF patterns")
            
            if os.path.exists(f"{self.model_dir}/target_models.pkl"):
                with open(f"{self.model_dir}/target_models.pkl", 'rb') as f:
                    self.target_models = pickle.load(f)
                logger.info(f"Loaded {len(self.target_models)} target models")
            
            if self.deep_model and TF_AVAILABLE and os.path.exists(f"{self.model_dir}/deep_model.h5"):
                self.deep_model = keras.models.load_model(f"{self.model_dir}/deep_model.h5")
                logger.info("Loaded deep model")
                
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
    
    def get_insights(self) -> Dict[str, Any]:
        """Get learning insights"""
        
        insights = {
            'total_exploitations': len(self.exploitation_history),
            'models_trained': self.is_trained,
            'targets_profiled': len(self.target_models),
            'waf_types_learned': list(self.waf_learner.waf_patterns.keys()),
            'success_rate': 0.0,
            'top_evasion_techniques': {},
            'vulnerability_success_rates': {}
        }
        
        if self.exploitation_history:
            successes = sum(1 for h in self.exploitation_history if h.success)
            insights['success_rate'] = successes / len(self.exploitation_history)
        
        # Get top evasion techniques
        technique_success = defaultdict(lambda: {'attempts': 0, 'successes': 0})
        for result in self.exploitation_history:
            if result.bypass_used:
                technique_success[result.bypass_used]['attempts'] += 1
                if result.success:
                    technique_success[result.bypass_used]['successes'] += 1
        
        for technique, stats in technique_success.items():
            if stats['attempts'] > 0:
                insights['top_evasion_techniques'][technique] = stats['successes'] / stats['attempts']
        
        # Get vulnerability success rates
        vuln_stats = defaultdict(lambda: {'attempts': 0, 'successes': 0})
        for result in self.exploitation_history:
            vuln_stats[result.vulnerability_type]['attempts'] += 1
            if result.success:
                vuln_stats[result.vulnerability_type]['successes'] += 1
        
        for vuln_type, stats in vuln_stats.items():
            if stats['attempts'] > 0:
                insights['vulnerability_success_rates'][vuln_type] = stats['successes'] / stats['attempts']
        
        return insights


# Export main learner
adaptive_learner = ExploitationLearner()