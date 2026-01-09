"""
Model manager for training, loading, and ensemble predictions.
"""
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import logging
import time

from .random_forest import RandomForestClassifierModel
from .isolation_forest import IsolationForestModel
from .autoencoder import AutoencoderModel
from data.preprocessor import DataPreprocessor

logger = logging.getLogger(__name__)


class ModelManager:
    """Manage multiple models and provide ensemble predictions."""
    
    def __init__(self, model_dir: str = "trained_models"):
        """
        Initialize model manager.
        
        Args:
            model_dir: Directory for saving/loading models
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.random_forest: Optional[RandomForestClassifierModel] = None
        self.isolation_forest: Optional[IsolationForestModel] = None
        self.autoencoder: Optional[AutoencoderModel] = None
        self.preprocessor: Optional[DataPreprocessor] = None
        
        self.is_loaded = False
    
    def train_all(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
        class_labels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Train all models.
        
        Args:
            X_train: Training features
            y_train: Training labels (encoded)
            X_val: Optional validation features
            feature_names: List of feature names
            class_labels: List of class labels
        
        Returns:
            Training metrics for all models
        """
        metrics = {}
        
        # Train Random Forest (supervised)
        logger.info("Training Random Forest classifier...")
        start_time = time.time()
        self.random_forest = RandomForestClassifierModel()
        rf_metrics = self.random_forest.train(
            X_train, y_train, 
            feature_names=feature_names,
            class_labels=class_labels
        )
        rf_metrics['training_time'] = time.time() - start_time
        metrics['random_forest'] = rf_metrics
        
        # Train Isolation Forest (on normal traffic)
        logger.info("Training Isolation Forest for anomaly detection...")
        start_time = time.time()
        # Train on normal traffic (assuming y_train=0 is BENIGN)
        normal_mask = y_train == 0
        X_normal = X_train[normal_mask]
        
        self.isolation_forest = IsolationForestModel()
        if_metrics = self.isolation_forest.train(
            X_normal if len(X_normal) > 100 else X_train,
            feature_names=feature_names
        )
        if_metrics['training_time'] = time.time() - start_time
        metrics['isolation_forest'] = if_metrics
        
        # Train Autoencoder (on normal traffic)
        logger.info("Training Autoencoder for deep anomaly detection...")
        start_time = time.time()
        self.autoencoder = AutoencoderModel(epochs=30)
        ae_metrics = self.autoencoder.train(
            X_normal if len(X_normal) > 100 else X_train,
            feature_names=feature_names,
            X_val=X_val
        )
        ae_metrics['training_time'] = time.time() - start_time
        metrics['autoencoder'] = ae_metrics
        
        logger.info("All models trained successfully")
        return metrics
    
    def save_all(self) -> None:
        """Save all trained models."""
        if self.random_forest and self.random_forest.is_trained:
            self.random_forest.save(str(self.model_dir / "random_forest.joblib"))
        
        if self.isolation_forest and self.isolation_forest.is_trained:
            self.isolation_forest.save(str(self.model_dir / "isolation_forest.joblib"))
        
        if self.autoencoder and self.autoencoder.is_trained:
            self.autoencoder.save(str(self.model_dir / "autoencoder.pt"))
        
        logger.info(f"All models saved to {self.model_dir}")
    
    def load_all(self) -> bool:
        """
        Load all models from disk.
        
        Returns:
            True if at least one model was loaded
        """
        loaded_any = False
        
        rf_path = self.model_dir / "random_forest.joblib"
        if rf_path.exists():
            self.random_forest = RandomForestClassifierModel.load(str(rf_path))
            loaded_any = True
        
        if_path = self.model_dir / "isolation_forest.joblib"
        if if_path.exists():
            self.isolation_forest = IsolationForestModel.load(str(if_path))
            loaded_any = True
        
        ae_path = self.model_dir / "autoencoder.pt"
        if ae_path.exists():
            self.autoencoder = AutoencoderModel.load(str(ae_path))
            loaded_any = True
        
        self.is_loaded = loaded_any
        return loaded_any
    
    def predict(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Get predictions from all models.
        
        Args:
            X: Feature array
        
        Returns:
            Dictionary with predictions from each model
        """
        results = {
            'random_forest': None,
            'isolation_forest': None,
            'autoencoder': None,
            'ensemble': None
        }
        
        # Random Forest predictions
        if self.random_forest and self.random_forest.is_trained:
            rf_preds = self.random_forest.predict_with_confidence(X)
            results['random_forest'] = [
                {
                    'prediction': pred[0],
                    'confidence': pred[1],
                    'probabilities': pred[2]
                }
                for pred in rf_preds
            ]
        
        # Isolation Forest predictions
        if self.isolation_forest and self.isolation_forest.is_trained:
            if_preds = self.isolation_forest.predict_with_scores(X)
            results['isolation_forest'] = [
                {
                    'is_anomaly': pred[0],
                    'score': pred[1],
                    'severity': pred[2]
                }
                for pred in if_preds
            ]
        
        # Autoencoder predictions
        if self.autoencoder and self.autoencoder.is_trained:
            ae_preds = self.autoencoder.predict_with_scores(X)
            results['autoencoder'] = [
                {
                    'is_anomaly': pred[0],
                    'reconstruction_error': pred[1],
                    'severity': pred[2]
                }
                for pred in ae_preds
            ]
        
        # Ensemble decision
        results['ensemble'] = self._ensemble_predict(results, X)
        
        return results
    
    def _ensemble_predict(
        self, 
        individual_results: Dict[str, Any],
        X: np.ndarray
    ) -> List[Dict[str, Any]]:
        """
        Combine predictions from all models.
        
        Args:
            individual_results: Results from each model
            X: Original features
        
        Returns:
            List of ensemble predictions
        """
        ensemble = []
        n_samples = len(X)
        
        for i in range(n_samples):
            result = {
                'is_malicious': False,
                'attack_type': 'BENIGN',
                'confidence': 1.0,
                'severity': 'Low',
                'anomaly_detected': False,
                'detection_sources': []
            }
            
            # Random Forest prediction
            if individual_results['random_forest']:
                rf = individual_results['random_forest'][i]
                if self.random_forest.class_labels:
                    attack_type = self.random_forest.class_labels[rf['prediction']]
                else:
                    attack_type = str(rf['prediction'])
                
                if attack_type != 'BENIGN':
                    result['is_malicious'] = True
                    result['attack_type'] = attack_type
                    result['confidence'] = rf['confidence']
                    result['detection_sources'].append('classifier')
            
            # Isolation Forest anomaly detection
            if individual_results['isolation_forest']:
                ifo = individual_results['isolation_forest'][i]
                if ifo['is_anomaly']:
                    result['anomaly_detected'] = True
                    result['detection_sources'].append('isolation_forest')
                    if not result['is_malicious']:
                        result['is_malicious'] = True
                        result['attack_type'] = 'Unknown (Anomaly)'
                    # Update severity if higher
                    result['severity'] = self._max_severity(
                        result['severity'], 
                        ifo['severity']
                    )
            
            # Autoencoder anomaly detection
            if individual_results['autoencoder']:
                ae = individual_results['autoencoder'][i]
                if ae['is_anomaly']:
                    result['anomaly_detected'] = True
                    result['detection_sources'].append('autoencoder')
                    if not result['is_malicious']:
                        result['is_malicious'] = True
                        result['attack_type'] = 'Unknown (Anomaly)'
                    result['severity'] = self._max_severity(
                        result['severity'], 
                        ae['severity']
                    )
            
            # Determine final severity based on attack type and confidence
            if result['is_malicious'] and result['attack_type'] != 'BENIGN':
                if 'DDoS' in result['attack_type'] or 'DoS' in result['attack_type']:
                    result['severity'] = 'High'
                elif 'SQL Injection' in result['attack_type'] or 'XSS' in result['attack_type']:
                    result['severity'] = 'Critical'
                elif 'Brute Force' in result['attack_type']:
                    result['severity'] = 'High'
                elif result['confidence'] > 0.9:
                    result['severity'] = self._max_severity(result['severity'], 'High')
            
            ensemble.append(result)
        
        return ensemble
    
    def _max_severity(self, sev1: str, sev2: str) -> str:
        """Get the higher severity level."""
        order = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
        return sev1 if order.get(sev1, 0) >= order.get(sev2, 0) else sev2
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        info = {
            'random_forest': None,
            'isolation_forest': None,
            'autoencoder': None
        }
        
        if self.random_forest and self.random_forest.is_trained:
            info['random_forest'] = {
                'type': 'Random Forest Classifier',
                'n_classes': len(self.random_forest.class_labels or []),
                'class_labels': self.random_forest.class_labels,
                'n_features': len(self.random_forest.feature_names or [])
            }
        
        if self.isolation_forest and self.isolation_forest.is_trained:
            info['isolation_forest'] = {
                'type': 'Isolation Forest',
                'threshold': self.isolation_forest.threshold,
                'n_features': len(self.isolation_forest.feature_names or [])
            }
        
        if self.autoencoder and self.autoencoder.is_trained:
            info['autoencoder'] = {
                'type': 'Deep Autoencoder',
                'threshold': self.autoencoder.threshold,
                'input_dim': self.autoencoder.input_dim,
                'encoding_dim': self.autoencoder.encoding_dim
            }
        
        return info
