"""
SHAP (SHapley Additive exPlanations) for model interpretability.
"""
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
import logging

logger = logging.getLogger(__name__)

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logger.warning("SHAP not installed. Run: pip install shap")


class SHAPExplainer:
    """SHAP-based explanations for Random Forest predictions."""
    
    def __init__(self, model: Any, feature_names: Optional[List[str]] = None):
        """
        Initialize SHAP explainer.
        
        Args:
            model: Trained sklearn Random Forest model
            feature_names: List of feature names
        """
        if not SHAP_AVAILABLE:
            raise ImportError("SHAP is required. Install with: pip install shap")
        
        self.model = model
        self.feature_names = feature_names
        self.explainer: Optional[shap.TreeExplainer] = None
        self.background_data: Optional[np.ndarray] = None
    
    def fit(self, background_data: np.ndarray) -> 'SHAPExplainer':
        """
        Fit the explainer with background data.
        
        Args:
            background_data: Sample of training data for baseline
        
        Returns:
            self
        """
        # Use a sample for efficiency
        if len(background_data) > 100:
            indices = np.random.choice(len(background_data), 100, replace=False)
            self.background_data = background_data[indices]
        else:
            self.background_data = background_data
        
        self.explainer = shap.TreeExplainer(self.model)
        logger.info("SHAP TreeExplainer initialized")
        return self
    
    def explain(self, X: np.ndarray) -> List[Dict[str, Any]]:
        """
        Generate SHAP explanations for predictions.
        
        Args:
            X: Feature array to explain
        
        Returns:
            List of explanation dictionaries
        """
        if self.explainer is None:
            raise ValueError("Explainer must be fitted first")
        
        # Get SHAP values
        shap_values = self.explainer.shap_values(X)
        
        # Get predictions
        predictions = self.model.predict(X)
        probas = self.model.predict_proba(X)
        
        explanations = []
        
        for i in range(len(X)):
            pred_class = predictions[i]
            
            # Get SHAP values for predicted class
            if isinstance(shap_values, list):
                # Multi-class: shap_values is a list per class
                sample_shap = shap_values[pred_class][i]
            else:
                sample_shap = shap_values[i]
            
            # Get top contributing features
            feature_importance = {}
            for j, (shap_val, feat_val) in enumerate(zip(sample_shap, X[i])):
                name = self.feature_names[j] if self.feature_names else f"feature_{j}"
                feature_importance[name] = {
                    'shap_value': float(shap_val),
                    'feature_value': float(feat_val),
                    'contribution': 'positive' if shap_val > 0 else 'negative'
                }
            
            # Sort by absolute SHAP value
            sorted_features = sorted(
                feature_importance.items(),
                key=lambda x: abs(x[1]['shap_value']),
                reverse=True
            )
            
            explanation = {
                'predicted_class': int(pred_class),
                'confidence': float(probas[i][pred_class]),
                'base_value': float(self.explainer.expected_value[pred_class]) 
                    if hasattr(self.explainer.expected_value, '__iter__') 
                    else float(self.explainer.expected_value),
                'top_features': dict(sorted_features[:10]),
                'all_features': feature_importance,
                'shap_values': sample_shap.tolist()
            }
            
            explanations.append(explanation)
        
        return explanations
    
    def get_feature_importance_global(
        self, 
        X: np.ndarray
    ) -> Dict[str, float]:
        """
        Get global feature importance using mean absolute SHAP values.
        
        Args:
            X: Feature array
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.explainer is None:
            raise ValueError("Explainer must be fitted first")
        
        shap_values = self.explainer.shap_values(X)
        
        # Handle multi-class
        if isinstance(shap_values, list):
            # Average across classes
            mean_shap = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        else:
            mean_shap = np.abs(shap_values).mean(axis=0)
        
        importance = {}
        for i, val in enumerate(mean_shap):
            name = self.feature_names[i] if self.feature_names else f"feature_{i}"
            importance[name] = float(val)
        
        return dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
    
    def generate_text_explanation(
        self, 
        explanation: Dict[str, Any],
        class_labels: Optional[List[str]] = None
    ) -> str:
        """
        Generate human-readable text explanation.
        
        Args:
            explanation: Explanation dictionary from explain()
            class_labels: Optional class label names
        
        Returns:
            Human-readable explanation string
        """
        pred_class = explanation['predicted_class']
        confidence = explanation['confidence']
        
        if class_labels and pred_class < len(class_labels):
            class_name = class_labels[pred_class]
        else:
            class_name = f"Class {pred_class}"
        
        text = f"Prediction: {class_name} (Confidence: {confidence:.1%})\n\n"
        text += "Key Contributing Factors:\n"
        
        for i, (feature, info) in enumerate(explanation['top_features'].items()):
            if i >= 5:
                break
            direction = "↑ increases" if info['contribution'] == 'positive' else "↓ decreases"
            text += f"  • {feature}: {info['feature_value']:.2f} {direction} likelihood\n"
        
        return text
