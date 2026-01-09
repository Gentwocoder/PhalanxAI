"""
Data preprocessing pipeline for network traffic data.
"""
import pandas as pd
import numpy as np
from typing import Optional, List, Tuple, Dict, Any
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """Preprocess network traffic data for ML models."""
    
    def __init__(self, feature_columns: Optional[List[str]] = None):
        """
        Initialize preprocessor.
        
        Args:
            feature_columns: List of feature columns to use. If None, uses all numeric columns.
        """
        self.feature_columns = feature_columns
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_fitted = False
        self._feature_columns_fitted: Optional[List[str]] = None
    
    def fit(self, df: pd.DataFrame, label_column: str = 'Label') -> 'DataPreprocessor':
        """
        Fit the preprocessor on training data.
        
        Args:
            df: Training DataFrame
            label_column: Name of the label column
        
        Returns:
            self
        """
        # Clean data first
        df_clean = self._clean_data(df.copy())
        
        # Determine feature columns
        if self.feature_columns:
            self._feature_columns_fitted = [
                col for col in self.feature_columns 
                if col in df_clean.columns and col != label_column
            ]
        else:
            self._feature_columns_fitted = [
                col for col in df_clean.select_dtypes(include=[np.number]).columns
                if col != label_column
            ]
        
        # Fit scaler on features
        X = df_clean[self._feature_columns_fitted].values
        self.scaler.fit(X)
        
        # Fit label encoder
        if label_column in df_clean.columns:
            self.label_encoder.fit(df_clean[label_column])
        
        self.is_fitted = True
        logger.info(f"Preprocessor fitted with {len(self._feature_columns_fitted)} features")
        return self
    
    def transform(
        self, 
        df: pd.DataFrame, 
        label_column: str = 'Label',
        include_labels: bool = True
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Transform data using fitted preprocessor.
        
        Args:
            df: DataFrame to transform
            label_column: Name of the label column
            include_labels: Whether to return encoded labels
        
        Returns:
            Tuple of (features array, labels array or None)
        """
        if not self.is_fitted:
            raise ValueError("Preprocessor must be fitted before transform")
        
        df_clean = self._clean_data(df.copy())
        
        # Get features
        missing_cols = set(self._feature_columns_fitted) - set(df_clean.columns)
        if missing_cols:
            logger.warning(f"Missing columns: {missing_cols}. Filling with zeros.")
            for col in missing_cols:
                df_clean[col] = 0
        
        X = df_clean[self._feature_columns_fitted].values
        X_scaled = self.scaler.transform(X)
        
        # Get labels if requested
        y = None
        if include_labels and label_column in df_clean.columns:
            y = self.label_encoder.transform(df_clean[label_column])
        
        return X_scaled, y
    
    def fit_transform(
        self, 
        df: pd.DataFrame, 
        label_column: str = 'Label',
        include_labels: bool = True
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fit and transform in one step."""
        self.fit(df, label_column)
        return self.transform(df, label_column, include_labels)
    
    def transform_single(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Transform a single sample (for real-time prediction).
        
        Args:
            features: Dictionary of feature name -> value
        
        Returns:
            Scaled feature array of shape (1, n_features)
        """
        if not self.is_fitted:
            raise ValueError("Preprocessor must be fitted before transform")
        
        # Create array in correct order
        X = np.zeros((1, len(self._feature_columns_fitted)))
        for i, col in enumerate(self._feature_columns_fitted):
            if col in features:
                X[0, i] = features[col]
        
        return self.scaler.transform(X)
    
    def inverse_transform_labels(self, y: np.ndarray) -> np.ndarray:
        """Convert encoded labels back to original strings."""
        return self.label_encoder.inverse_transform(y)
    
    def _clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean data by handling missing values and infinities.
        
        Args:
            df: Input DataFrame
        
        Returns:
            Cleaned DataFrame
        """
        # Replace infinities with NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Fill NaN with median for numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if df[col].isna().any():
                median_val = df[col].median()
                if pd.isna(median_val):
                    median_val = 0
                df[col] = df[col].fillna(median_val)
        
        # Clip extreme values
        for col in numeric_cols:
            q99 = df[col].quantile(0.99)
            q01 = df[col].quantile(0.01)
            if q99 > q01:
                df[col] = df[col].clip(lower=q01, upper=q99)
        
        return df
    
    def save(self, path: str) -> None:
        """Save preprocessor to disk."""
        save_dict = {
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_columns': self._feature_columns_fitted,
            'is_fitted': self.is_fitted
        }
        joblib.dump(save_dict, path)
        logger.info(f"Preprocessor saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'DataPreprocessor':
        """Load preprocessor from disk."""
        save_dict = joblib.load(path)
        preprocessor = cls()
        preprocessor.scaler = save_dict['scaler']
        preprocessor.label_encoder = save_dict['label_encoder']
        preprocessor._feature_columns_fitted = save_dict['feature_columns']
        preprocessor.is_fitted = save_dict['is_fitted']
        logger.info(f"Preprocessor loaded from {path}")
        return preprocessor
    
    @property
    def feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self._feature_columns_fitted or []
    
    @property
    def class_labels(self) -> List[str]:
        """Get list of class labels."""
        if self.is_fitted:
            return list(self.label_encoder.classes_)
        return []
