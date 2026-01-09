"""
Random Forest classifier for attack type classification.
"""
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, classification_report, confusion_matrix
)
import joblib
import logging

logger = logging.getLogger(__name__)


class RandomForestClassifierModel:
    """Random Forest classifier for multi-class attack detection."""
    
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: Optional[int] = 20,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        n_jobs: int = -1,
        random_state: int = 42
    ):
        """
        Initialize Random Forest model.
        
        Args:
            n_estimators: Number of trees in the forest
            max_depth: Maximum depth of trees
            min_samples_split: Minimum samples required to split
            min_samples_leaf: Minimum samples in leaf nodes
            n_jobs: Number of parallel jobs (-1 for all cores)
            random_state: Random seed for reproducibility
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            n_jobs=n_jobs,
            random_state=random_state,
            class_weight='balanced'  # Handle imbalanced classes
        )
        self.is_trained = False
        self.class_labels: Optional[List[str]] = None
        self.feature_names: Optional[List[str]] = None
    
    def train(
        self, 
        X_train: np.ndarray, 
        y_train: np.ndarray,
        feature_names: Optional[List[str]] = None,
        class_labels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Train the Random Forest classifier.
        
        Args:
            X_train: Training features
            y_train: Training labels (encoded)
            feature_names: Optional list of feature names
            class_labels: Optional list of class labels
        
        Returns:
            Training metrics dictionary
        """
        logger.info(f"Training Random Forest with {len(X_train)} samples")
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        self.feature_names = feature_names
        self.class_labels = class_labels
        
        # Calculate training metrics
        y_pred = self.model.predict(X_train)
        
        metrics = {
            'accuracy': accuracy_score(y_train, y_pred),
            'n_samples': len(X_train),
            'n_features': X_train.shape[1],
            'n_classes': len(np.unique(y_train))
        }
        
        logger.info(f"Training completed. Accuracy: {metrics['accuracy']:.4f}")
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict attack types.
        
        Args:
            X: Feature array
        
        Returns:
            Predicted class indices
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities.
        
        Args:
            X: Feature array
        
        Returns:
            Probability array of shape (n_samples, n_classes)
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        return self.model.predict_proba(X)
    
    def predict_with_confidence(
        self, 
        X: np.ndarray
    ) -> List[Tuple[int, float, Dict[str, float]]]:
        """
        Predict with confidence scores and per-class probabilities.
        
        Args:
            X: Feature array
        
        Returns:
            List of (predicted_class, confidence, class_probabilities)
        """
        predictions = self.predict(X)
        probabilities = self.predict_proba(X)
        
        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            confidence = float(probs.max())
            class_probs = {}
            if self.class_labels:
                class_probs = {
                    self.class_labels[j]: float(p) 
                    for j, p in enumerate(probs)
                }
            else:
                class_probs = {str(j): float(p) for j, p in enumerate(probs)}
            results.append((int(pred), confidence, class_probs))
        
        return results
    
    def evaluate(
        self, 
        X_test: np.ndarray, 
        y_test: np.ndarray
    ) -> Dict[str, Any]:
        """
        Evaluate model on test data.
        
        Args:
            X_test: Test features
            y_test: Test labels
        
        Returns:
            Evaluation metrics dictionary
        """
        y_pred = self.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision_macro': precision_score(y_test, y_pred, average='macro', zero_division=0),
            'recall_macro': recall_score(y_test, y_pred, average='macro', zero_division=0),
            'f1_macro': f1_score(y_test, y_pred, average='macro', zero_division=0),
            'precision_weighted': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall_weighted': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_weighted': f1_score(y_test, y_pred, average='weighted', zero_division=0),
        }
        
        # Add per-class metrics if class labels available
        if self.class_labels:
            report = classification_report(
                y_test, y_pred, 
                target_names=self.class_labels,
                output_dict=True,
                zero_division=0
            )
            metrics['per_class'] = {
                label: report.get(label, {})
                for label in self.class_labels
            }
        
        return metrics
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance scores.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not self.is_trained:
            raise ValueError("Model must be trained first")
        
        importances = self.model.feature_importances_
        
        if self.feature_names:
            return dict(zip(self.feature_names, importances))
        return {f"feature_{i}": imp for i, imp in enumerate(importances)}
    
    def get_top_features(self, n: int = 10) -> List[Tuple[str, float]]:
        """Get top N most important features."""
        importance = self.get_feature_importance()
        return sorted(importance.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def save(self, path: str) -> None:
        """Save model to disk."""
        save_dict = {
            'model': self.model,
            'is_trained': self.is_trained,
            'class_labels': self.class_labels,
            'feature_names': self.feature_names
        }
        joblib.dump(save_dict, path)
        logger.info(f"Random Forest model saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'RandomForestClassifierModel':
        """Load model from disk."""
        save_dict = joblib.load(path)
        instance = cls()
        instance.model = save_dict['model']
        instance.is_trained = save_dict['is_trained']
        instance.class_labels = save_dict['class_labels']
        instance.feature_names = save_dict['feature_names']
        logger.info(f"Random Forest model loaded from {path}")
        return instance
