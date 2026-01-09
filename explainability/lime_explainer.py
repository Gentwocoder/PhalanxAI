"""
LIME (Local Interpretable Model-agnostic Explanations) for model interpretability.
"""
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Callable
import logging

logger = logging.getLogger(__name__)

try:
    from lime.lime_tabular import LimeTabularExplainer
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    logger.warning("LIME not installed. Run: pip install lime")


class LIMEExplainer:
    """LIME-based explanations for any classifier."""
    
    def __init__(
        self,
        training_data: np.ndarray,
        feature_names: Optional[List[str]] = None,
        class_names: Optional[List[str]] = None,
        mode: str = 'classification'
    ):
        """
        Initialize LIME explainer.
        
        Args:
            training_data: Training data for discretization
            feature_names: List of feature names
            class_names: List of class names
            mode: 'classification' or 'regression'
        """
        if not LIME_AVAILABLE:
            raise ImportError("LIME is required. Install with: pip install lime")
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(training_data.shape[1])]
        self.class_names = class_names
        
        self.explainer = LimeTabularExplainer(
            training_data,
            feature_names=self.feature_names,
            class_names=class_names,
            mode=mode,
            discretize_continuous=True
        )
        
        logger.info("LIME TabularExplainer initialized")
    
    def explain(
        self,
        X: np.ndarray,
        predict_fn: Callable,
        num_features: int = 10,
        num_samples: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Generate LIME explanations for predictions.
        
        Args:
            X: Feature array to explain
            predict_fn: Prediction function (returns probabilities)
            num_features: Number of top features to include
            num_samples: Number of samples for LIME
        
        Returns:
            List of explanation dictionaries
        """
        explanations = []
        
        for i in range(len(X)):
            sample = X[i]
            
            # Generate LIME explanation
            exp = self.explainer.explain_instance(
                sample,
                predict_fn,
                num_features=num_features,
                num_samples=num_samples
            )
            
            # Get prediction
            probs = predict_fn(sample.reshape(1, -1))[0]
            pred_class = int(np.argmax(probs))
            
            # Extract feature contributions
            feature_weights = exp.as_list(label=pred_class)
            
            top_features = {}
            for feature_desc, weight in feature_weights:
                # Parse feature description to get name
                # LIME returns strings like "feature_name <= 0.5"
                parts = feature_desc.split()
                feature_name = parts[0] if parts else feature_desc
                
                top_features[feature_name] = {
                    'weight': float(weight),
                    'description': feature_desc,
                    'contribution': 'positive' if weight > 0 else 'negative'
                }
            
            explanation = {
                'predicted_class': pred_class,
                'class_name': self.class_names[pred_class] if self.class_names else str(pred_class),
                'confidence': float(probs[pred_class]),
                'probabilities': probs.tolist(),
                'top_features': top_features,
                'intercept': float(exp.intercept[pred_class]) if hasattr(exp, 'intercept') else 0.0
            }
            
            explanations.append(explanation)
        
        return explanations
    
    def explain_single(
        self,
        sample: np.ndarray,
        predict_fn: Callable,
        num_features: int = 10,
        num_samples: int = 1000
    ) -> Dict[str, Any]:
        """
        Explain a single sample.
        
        Args:
            sample: Single feature vector
            predict_fn: Prediction function
            num_features: Number of features to show
            num_samples: LIME samples
        
        Returns:
            Explanation dictionary
        """
        return self.explain(
            sample.reshape(1, -1), 
            predict_fn, 
            num_features, 
            num_samples
        )[0]
    
    def generate_text_explanation(
        self,
        explanation: Dict[str, Any]
    ) -> str:
        """
        Generate human-readable text explanation.
        
        Args:
            explanation: Explanation from explain()
        
        Returns:
            Human-readable string
        """
        class_name = explanation['class_name']
        confidence = explanation['confidence']
        
        text = f"Prediction: {class_name} (Confidence: {confidence:.1%})\n\n"
        text += "Contributing Factors (LIME):\n"
        
        # Sort by absolute weight
        sorted_features = sorted(
            explanation['top_features'].items(),
            key=lambda x: abs(x[1]['weight']),
            reverse=True
        )
        
        for feature_name, info in sorted_features[:5]:
            weight = info['weight']
            direction = "supports" if weight > 0 else "opposes"
            text += f"  • {info['description']}: {direction} prediction (weight: {weight:+.3f})\n"
        
        return text
    
    def compare_explanations(
        self,
        normal_sample: np.ndarray,
        anomaly_sample: np.ndarray,
        predict_fn: Callable
    ) -> Dict[str, Any]:
        """
        Compare explanations between normal and anomaly samples.
        
        Args:
            normal_sample: Normal traffic sample
            anomaly_sample: Anomaly/attack sample
            predict_fn: Prediction function
        
        Returns:
            Comparison dictionary
        """
        normal_exp = self.explain_single(normal_sample, predict_fn)
        anomaly_exp = self.explain_single(anomaly_sample, predict_fn)
        
        # Find differentiating features
        normal_features = set(normal_exp['top_features'].keys())
        anomaly_features = set(anomaly_exp['top_features'].keys())
        
        common = normal_features & anomaly_features
        differentiating = []
        
        for feature in common:
            normal_weight = normal_exp['top_features'][feature]['weight']
            anomaly_weight = anomaly_exp['top_features'][feature]['weight']
            
            if abs(normal_weight - anomaly_weight) > 0.1:
                differentiating.append({
                    'feature': feature,
                    'normal_weight': normal_weight,
                    'anomaly_weight': anomaly_weight,
                    'difference': anomaly_weight - normal_weight
                })
        
        differentiating.sort(key=lambda x: abs(x['difference']), reverse=True)
        
        return {
            'normal_prediction': normal_exp['class_name'],
            'anomaly_prediction': anomaly_exp['class_name'],
            'differentiating_features': differentiating[:5],
            'normal_explanation': normal_exp,
            'anomaly_explanation': anomaly_exp
        }
