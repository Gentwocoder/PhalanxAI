"""
Isolation Forest for unsupervised anomaly detection.
"""
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score
import joblib
import logging

logger = logging.getLogger(__name__)


class IsolationForestModel:
    """Isolation Forest for zero-day and anomaly detection."""
    
    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.1,
        max_samples: str = 'auto',
        max_features: float = 1.0,
        n_jobs: int = -1,
        random_state: int = 42
    ):
        """
        Initialize Isolation Forest model.
        
        Args:
            n_estimators: Number of base estimators
            contamination: Expected proportion of outliers (anomalies)
            max_samples: Number of samples to draw for training
            max_features: Features to draw for training
            n_jobs: Number of parallel jobs
            random_state: Random seed
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=max_samples,
            max_features=max_features,
            n_jobs=n_jobs,
            random_state=random_state,
            warm_start=False
        )
        self.is_trained = False
        self.feature_names: Optional[List[str]] = None
        self.threshold: float = 0.0
    
    def train(
        self, 
        X_train: np.ndarray,
        feature_names: Optional[List[str]] = None,
        y_train: Optional[np.ndarray] = None  # For evaluation only
    ) -> Dict[str, Any]:
        """
        Train the Isolation Forest (unsupervised).
        
        Args:
            X_train: Training features (should be mostly normal traffic)
            feature_names: Optional list of feature names
            y_train: Optional labels for evaluation (0=normal, 1=anomaly)
        
        Returns:
            Training metrics dictionary
        """
        logger.info(f"Training Isolation Forest with {len(X_train)} samples")
        
        self.model.fit(X_train)
        self.is_trained = True
        self.feature_names = feature_names
        
        # Calculate anomaly scores for threshold calibration
        scores = self.model.decision_function(X_train)
        self.threshold = np.percentile(scores, 10)  # Bottom 10% as anomalies
        
        metrics = {
            'n_samples': len(X_train),
            'n_features': X_train.shape[1],
            'threshold': float(self.threshold),
            'mean_score': float(np.mean(scores)),
            'std_score': float(np.std(scores))
        }
        
        # If labels provided, calculate detection metrics
        if y_train is not None:
            y_pred = self.predict(X_train)
            # Convert to binary: 1=anomaly, 0=normal
            y_binary = (y_train != 0).astype(int) if y_train.dtype != bool else y_train.astype(int)
            y_pred_binary = (y_pred == -1).astype(int)
            
            metrics['precision'] = precision_score(y_binary, y_pred_binary, zero_division=0)
            metrics['recall'] = recall_score(y_binary, y_pred_binary, zero_division=0)
            metrics['f1'] = f1_score(y_binary, y_pred_binary, zero_division=0)
        
        logger.info(f"Training completed. Threshold: {self.threshold:.4f}")
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict if samples are anomalies.
        
        Args:
            X: Feature array
        
        Returns:
            Array of predictions: 1 for normal, -1 for anomaly
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        return self.model.predict(X)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores for samples.
        
        Args:
            X: Feature array
        
        Returns:
            Anomaly scores (lower = more anomalous)
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        return self.model.decision_function(X)
    
    def predict_with_scores(
        self, 
        X: np.ndarray
    ) -> List[Tuple[bool, float, str]]:
        """
        Predict with anomaly scores and severity.
        
        Args:
            X: Feature array
        
        Returns:
            List of (is_anomaly, score, severity)
        """
        predictions = self.predict(X)
        scores = self.score_samples(X)
        
        results = []
        for pred, score in zip(predictions, scores):
            is_anomaly = pred == -1
            
            # Determine severity based on score
            if score < -0.5:
                severity = "Critical"
            elif score < -0.3:
                severity = "High"
            elif score < -0.1:
                severity = "Medium"
            else:
                severity = "Low"
            
            results.append((is_anomaly, float(score), severity))
        
        return results
    
    def evaluate(
        self, 
        X_test: np.ndarray, 
        y_test: np.ndarray
    ) -> Dict[str, Any]:
        """
        Evaluate model on labeled test data.
        
        Args:
            X_test: Test features
            y_test: Test labels (0=normal, non-0=attack)
        
        Returns:
            Evaluation metrics
        """
        y_pred = self.predict(X_test)
        scores = self.score_samples(X_test)
        
        # Convert to binary
        y_binary = (y_test != 0).astype(int)
        y_pred_binary = (y_pred == -1).astype(int)
        
        # Calculate metrics
        tp = np.sum((y_pred_binary == 1) & (y_binary == 1))
        tn = np.sum((y_pred_binary == 0) & (y_binary == 0))
        fp = np.sum((y_pred_binary == 1) & (y_binary == 0))
        fn = np.sum((y_pred_binary == 0) & (y_binary == 1))
        
        metrics = {
            'precision': precision_score(y_binary, y_pred_binary, zero_division=0),
            'recall': recall_score(y_binary, y_pred_binary, zero_division=0),
            'f1': f1_score(y_binary, y_pred_binary, zero_division=0),
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'detection_rate': float(tp / (tp + fn)) if (tp + fn) > 0 else 0,
            'false_alarm_rate': float(fp / (fp + tn)) if (fp + tn) > 0 else 0,
            'mean_score_normal': float(np.mean(scores[y_binary == 0])) if np.any(y_binary == 0) else 0,
            'mean_score_anomaly': float(np.mean(scores[y_binary == 1])) if np.any(y_binary == 1) else 0
        }
        
        return metrics
    
    def set_threshold(self, threshold: float) -> None:
        """Set custom anomaly threshold."""
        self.threshold = threshold
        logger.info(f"Threshold updated to {threshold}")
    
    def save(self, path: str) -> None:
        """Save model to disk."""
        save_dict = {
            'model': self.model,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names,
            'threshold': self.threshold
        }
        joblib.dump(save_dict, path)
        logger.info(f"Isolation Forest model saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'IsolationForestModel':
        """Load model from disk."""
        save_dict = joblib.load(path)
        instance = cls()
        instance.model = save_dict['model']
        instance.is_trained = save_dict['is_trained']
        instance.feature_names = save_dict['feature_names']
        instance.threshold = save_dict['threshold']
        logger.info(f"Isolation Forest model loaded from {path}")
        return instance
