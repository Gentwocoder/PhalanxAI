"""
Feature extraction and engineering utilities.
"""
import pandas as pd
import numpy as np
from typing import List, Optional, Dict, Tuple
from sklearn.feature_selection import SelectKBest, mutual_info_classif, f_classif
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract and engineer features for intrusion detection."""
    
    # Key feature groups for network traffic analysis
    FLOW_FEATURES = [
        'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min'
    ]
    
    PACKET_FEATURES = [
        'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean'
    ]
    
    FLAG_FEATURES = [
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
        'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags'
    ]
    
    TIMING_FEATURES = [
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Max', 'Bwd IAT Min',
        'Active Mean', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Max', 'Idle Min'
    ]
    
    def __init__(self, n_top_features: int = 50):
        """
        Initialize feature extractor.
        
        Args:
            n_top_features: Number of top features to select
        """
        self.n_top_features = n_top_features
        self.selected_features: Optional[List[str]] = None
        self.feature_scores: Optional[Dict[str, float]] = None
        self.selector: Optional[SelectKBest] = None
    
    def select_features(
        self, 
        X: pd.DataFrame, 
        y: pd.Series,
        method: str = 'mutual_info'
    ) -> List[str]:
        """
        Select top features using statistical methods.
        
        Args:
            X: Feature DataFrame
            y: Target labels
            method: Selection method ('mutual_info' or 'f_classif')
        
        Returns:
            List of selected feature names
        """
        # Get numeric columns only
        numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
        X_numeric = X[numeric_cols].copy()
        
        # Handle any remaining NaN/inf
        X_numeric = X_numeric.replace([np.inf, -np.inf], np.nan)
        X_numeric = X_numeric.fillna(0)
        
        # Select scoring function
        score_func = mutual_info_classif if method == 'mutual_info' else f_classif
        
        # Fit selector
        n_features = min(self.n_top_features, len(numeric_cols))
        self.selector = SelectKBest(score_func=score_func, k=n_features)
        self.selector.fit(X_numeric, y)
        
        # Get feature scores
        scores = self.selector.scores_
        self.feature_scores = dict(zip(numeric_cols, scores))
        
        # Get selected features (sorted by importance)
        feature_importance = sorted(
            self.feature_scores.items(), 
            key=lambda x: x[1] if not np.isnan(x[1]) else 0, 
            reverse=True
        )
        self.selected_features = [f[0] for f in feature_importance[:n_features]]
        
        logger.info(f"Selected {len(self.selected_features)} features using {method}")
        return self.selected_features
    
    def extract_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create derived features from raw network flow data.
        
        Args:
            df: Input DataFrame with raw features
        
        Returns:
            DataFrame with additional derived features
        """
        df = df.copy()
        
        # Packet ratios
        if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            total_packets = df['Total Fwd Packets'] + df['Total Backward Packets']
            df['Fwd_Packet_Ratio'] = df['Total Fwd Packets'] / (total_packets + 1e-10)
            df['Bwd_Packet_Ratio'] = df['Total Backward Packets'] / (total_packets + 1e-10)
        
        # Bytes ratios
        if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
            total_bytes = df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']
            df['Fwd_Bytes_Ratio'] = df['Total Length of Fwd Packets'] / (total_bytes + 1e-10)
            df['Bwd_Bytes_Ratio'] = df['Total Length of Bwd Packets'] / (total_bytes + 1e-10)
        
        # Flow intensity
        if 'Flow Duration' in df.columns and 'Flow Packets/s' in df.columns:
            df['Flow_Intensity'] = df['Flow Packets/s'] * np.log1p(df['Flow Duration'])
        
        # IAT variability
        if 'Flow IAT Std' in df.columns and 'Flow IAT Mean' in df.columns:
            df['IAT_Coefficient_Variation'] = df['Flow IAT Std'] / (df['Flow IAT Mean'] + 1e-10)
        
        # Flag combinations
        if all(f in df.columns for f in ['SYN Flag Count', 'ACK Flag Count', 'FIN Flag Count']):
            df['SYN_ACK_Ratio'] = df['SYN Flag Count'] / (df['ACK Flag Count'] + 1e-10)
            df['Has_FIN'] = (df['FIN Flag Count'] > 0).astype(int)
            df['Has_RST'] = (df.get('RST Flag Count', 0) > 0).astype(int) if 'RST Flag Count' in df.columns else 0
        
        # Segment size difference
        if 'Avg Fwd Segment Size' in df.columns and 'Avg Bwd Segment Size' in df.columns:
            df['Segment_Size_Diff'] = abs(df['Avg Fwd Segment Size'] - df['Avg Bwd Segment Size'])
        
        # Window size features
        if 'Init_Win_bytes_forward' in df.columns and 'Init_Win_bytes_backward' in df.columns:
            df['Win_Size_Ratio'] = df['Init_Win_bytes_forward'] / (df['Init_Win_bytes_backward'] + 1e-10)
        
        # Activity ratio
        if 'Active Mean' in df.columns and 'Idle Mean' in df.columns:
            df['Activity_Ratio'] = df['Active Mean'] / (df['Idle Mean'] + 1e-10)
        
        return df
    
    def get_feature_importance_report(self) -> List[Tuple[str, float]]:
        """
        Get feature importance report sorted by score.
        
        Returns:
            List of (feature_name, score) tuples
        """
        if self.feature_scores is None:
            return []
        
        return sorted(
            [(k, v) for k, v in self.feature_scores.items() if not np.isnan(v)],
            key=lambda x: x[1],
            reverse=True
        )
    
    def get_feature_groups(self) -> Dict[str, List[str]]:
        """Get feature groups for analysis."""
        return {
            'flow': self.FLOW_FEATURES,
            'packet': self.PACKET_FEATURES,
            'flags': self.FLAG_FEATURES,
            'timing': self.TIMING_FEATURES
        }
