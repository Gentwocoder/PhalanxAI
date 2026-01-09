"""
Dataset loaders for various intrusion detection datasets.
"""
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, Optional, List, Union
from sklearn.model_selection import train_test_split
import logging

logger = logging.getLogger(__name__)


class DatasetLoader:
    """Load and manage intrusion detection datasets."""
    
    # CICIDS2017 attack label mappings
    CICIDS_LABELS = {
        "BENIGN": "BENIGN",
        "Bot": "Bot",
        "DDoS": "DDoS",
        "DoS GoldenEye": "DoS GoldenEye",
        "DoS Hulk": "DoS Hulk",
        "DoS Slowhttptest": "DoS Slowhttptest",
        "DoS slowloris": "DoS slowloris",
        "FTP-Patator": "FTP-Patator",
        "Heartbleed": "Heartbleed",
        "Infiltration": "Infiltration",
        "PortScan": "PortScan",
        "SSH-Patator": "SSH-Patator",
        "Web Attack – Brute Force": "Web Attack - Brute Force",
        "Web Attack – Sql Injection": "Web Attack - SQL Injection",
        "Web Attack – XSS": "Web Attack - XSS",
        "Web Attack - Brute Force": "Web Attack - Brute Force",
        "Web Attack - Sql Injection": "Web Attack - SQL Injection",
        "Web Attack - XSS": "Web Attack - XSS",
    }
    
    def __init__(self, data_dir: Optional[str] = None):
        """Initialize loader with optional data directory."""
        self.data_dir = Path(data_dir) if data_dir else Path("sample_data")
    
    def load_cicids2017(
        self, 
        file_paths: Union[str, List[str]], 
        sample_size: Optional[int] = None
    ) -> pd.DataFrame:
        """
        Load CICIDS2017 dataset from CSV file(s).
        
        Args:
            file_paths: Path or list of paths to CSV files
            sample_size: Optional number of rows to sample (for large datasets)
        
        Returns:
            Combined DataFrame with all data
        """
        if isinstance(file_paths, str):
            file_paths = [file_paths]
        
        dfs = []
        for path in file_paths:
            logger.info(f"Loading dataset from {path}")
            try:
                df = pd.read_csv(path, encoding='utf-8', low_memory=False)
                # Clean column names (remove leading/trailing spaces)
                df.columns = df.columns.str.strip()
                dfs.append(df)
            except Exception as e:
                logger.error(f"Error loading {path}: {e}")
                raise
        
        combined = pd.concat(dfs, ignore_index=True)
        
        # Normalize labels
        if 'Label' in combined.columns:
            combined['Label'] = combined['Label'].str.strip().map(
                lambda x: self.CICIDS_LABELS.get(x, x)
            )
        
        if sample_size and len(combined) > sample_size:
            # Stratified sampling to maintain class distribution
            combined = combined.groupby('Label', group_keys=False).apply(
                lambda x: x.sample(min(len(x), sample_size // combined['Label'].nunique()))
            ).reset_index(drop=True)
        
        logger.info(f"Loaded {len(combined)} samples with {combined['Label'].nunique()} classes")
        return combined
    
    def split_data(
        self, 
        df: pd.DataFrame,
        label_column: str = 'Label',
        test_size: float = 0.2,
        random_state: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        """
        Split data into training and test sets with stratification.
        
        Args:
            df: Input DataFrame
            label_column: Name of the label column
            test_size: Proportion for test set
            random_state: Random seed for reproducibility
        
        Returns:
            X_train, X_test, y_train, y_test
        """
        X = df.drop(columns=[label_column])
        y = df[label_column]
        
        return train_test_split(
            X, y, 
            test_size=test_size, 
            random_state=random_state,
            stratify=y
        )


def load_sample_data(n_samples: int = 1000) -> pd.DataFrame:
    """
    Generate synthetic sample data for testing and demonstration.
    
    Args:
        n_samples: Number of samples to generate
    
    Returns:
        DataFrame with synthetic network flow data
    """
    np.random.seed(42)
    
    # Attack type distribution
    attack_types = [
        ("BENIGN", 0.70),
        ("DDoS", 0.08),
        ("PortScan", 0.07),
        ("DoS Hulk", 0.05),
        ("Bot", 0.03),
        ("FTP-Patator", 0.02),
        ("SSH-Patator", 0.02),
        ("Web Attack - Brute Force", 0.02),
        ("Web Attack - SQL Injection", 0.01),
    ]
    
    labels = []
    for attack, prob in attack_types:
        labels.extend([attack] * int(n_samples * prob))
    
    # Pad to exact n_samples
    while len(labels) < n_samples:
        labels.append("BENIGN")
    labels = labels[:n_samples]
    np.random.shuffle(labels)
    
    # Generate features based on attack type
    data = {
        'Destination Port': np.random.choice([80, 443, 22, 21, 8080, 3306], n_samples),
        'Flow Duration': np.random.exponential(1000000, n_samples),
        'Total Fwd Packets': np.random.poisson(10, n_samples),
        'Total Backward Packets': np.random.poisson(8, n_samples),
        'Total Length of Fwd Packets': np.random.exponential(1000, n_samples),
        'Total Length of Bwd Packets': np.random.exponential(800, n_samples),
        'Fwd Packet Length Max': np.random.exponential(500, n_samples),
        'Fwd Packet Length Min': np.random.exponential(20, n_samples),
        'Fwd Packet Length Mean': np.random.exponential(100, n_samples),
        'Fwd Packet Length Std': np.random.exponential(50, n_samples),
        'Bwd Packet Length Max': np.random.exponential(400, n_samples),
        'Bwd Packet Length Min': np.random.exponential(15, n_samples),
        'Bwd Packet Length Mean': np.random.exponential(80, n_samples),
        'Bwd Packet Length Std': np.random.exponential(40, n_samples),
        'Flow Bytes/s': np.random.exponential(10000, n_samples),
        'Flow Packets/s': np.random.exponential(100, n_samples),
        'Flow IAT Mean': np.random.exponential(50000, n_samples),
        'Flow IAT Std': np.random.exponential(30000, n_samples),
        'Flow IAT Max': np.random.exponential(100000, n_samples),
        'Flow IAT Min': np.random.exponential(1000, n_samples),
        'Fwd IAT Total': np.random.exponential(500000, n_samples),
        'Fwd IAT Mean': np.random.exponential(50000, n_samples),
        'Fwd IAT Std': np.random.exponential(30000, n_samples),
        'Fwd IAT Max': np.random.exponential(100000, n_samples),
        'Fwd IAT Min': np.random.exponential(1000, n_samples),
        'Bwd IAT Total': np.random.exponential(400000, n_samples),
        'Bwd IAT Mean': np.random.exponential(40000, n_samples),
        'Bwd IAT Std': np.random.exponential(25000, n_samples),
        'Bwd IAT Max': np.random.exponential(80000, n_samples),
        'Bwd IAT Min': np.random.exponential(800, n_samples),
        'Fwd PSH Flags': np.random.randint(0, 2, n_samples),
        'Bwd PSH Flags': np.random.randint(0, 2, n_samples),
        'Fwd URG Flags': np.random.randint(0, 2, n_samples),
        'Bwd URG Flags': np.random.randint(0, 2, n_samples),
        'Fwd Header Length': np.random.exponential(200, n_samples),
        'Bwd Header Length': np.random.exponential(180, n_samples),
        'Fwd Packets/s': np.random.exponential(50, n_samples),
        'Bwd Packets/s': np.random.exponential(40, n_samples),
        'Min Packet Length': np.random.exponential(20, n_samples),
        'Max Packet Length': np.random.exponential(500, n_samples),
        'Packet Length Mean': np.random.exponential(100, n_samples),
        'Packet Length Std': np.random.exponential(50, n_samples),
        'Packet Length Variance': np.random.exponential(2500, n_samples),
        'FIN Flag Count': np.random.randint(0, 3, n_samples),
        'SYN Flag Count': np.random.randint(0, 3, n_samples),
        'RST Flag Count': np.random.randint(0, 2, n_samples),
        'PSH Flag Count': np.random.randint(0, 5, n_samples),
        'ACK Flag Count': np.random.randint(0, 10, n_samples),
        'URG Flag Count': np.random.randint(0, 2, n_samples),
        'CWE Flag Count': np.random.randint(0, 2, n_samples),
        'ECE Flag Count': np.random.randint(0, 2, n_samples),
        'Down/Up Ratio': np.random.exponential(1, n_samples),
        'Average Packet Size': np.random.exponential(200, n_samples),
        'Avg Fwd Segment Size': np.random.exponential(100, n_samples),
        'Avg Bwd Segment Size': np.random.exponential(80, n_samples),
        'Fwd Avg Bytes/Bulk': np.random.exponential(100, n_samples),
        'Fwd Avg Packets/Bulk': np.random.exponential(5, n_samples),
        'Fwd Avg Bulk Rate': np.random.exponential(1000, n_samples),
        'Bwd Avg Bytes/Bulk': np.random.exponential(80, n_samples),
        'Bwd Avg Packets/Bulk': np.random.exponential(4, n_samples),
        'Bwd Avg Bulk Rate': np.random.exponential(800, n_samples),
        'Subflow Fwd Packets': np.random.poisson(5, n_samples),
        'Subflow Fwd Bytes': np.random.exponential(500, n_samples),
        'Subflow Bwd Packets': np.random.poisson(4, n_samples),
        'Subflow Bwd Bytes': np.random.exponential(400, n_samples),
        'Init_Win_bytes_forward': np.random.randint(0, 65535, n_samples),
        'Init_Win_bytes_backward': np.random.randint(0, 65535, n_samples),
        'act_data_pkt_fwd': np.random.poisson(3, n_samples),
        'min_seg_size_forward': np.random.randint(20, 100, n_samples),
        'Active Mean': np.random.exponential(10000, n_samples),
        'Active Std': np.random.exponential(5000, n_samples),
        'Active Max': np.random.exponential(20000, n_samples),
        'Active Min': np.random.exponential(1000, n_samples),
        'Idle Mean': np.random.exponential(100000, n_samples),
        'Idle Std': np.random.exponential(50000, n_samples),
        'Idle Max': np.random.exponential(200000, n_samples),
        'Idle Min': np.random.exponential(10000, n_samples),
        'Label': labels
    }
    
    df = pd.DataFrame(data)
    
    # Modify features based on attack type to make them distinguishable
    for i, label in enumerate(labels):
        if label == "DDoS":
            df.loc[i, 'Flow Packets/s'] *= 10
            df.loc[i, 'Flow Bytes/s'] *= 8
            df.loc[i, 'SYN Flag Count'] += 5
        elif label == "PortScan":
            df.loc[i, 'Destination Port'] = np.random.randint(1, 65535)
            df.loc[i, 'Flow Duration'] *= 0.1
            df.loc[i, 'SYN Flag Count'] += 3
        elif label in ["DoS Hulk", "DoS GoldenEye"]:
            df.loc[i, 'Total Fwd Packets'] *= 5
            df.loc[i, 'Flow Bytes/s'] *= 5
        elif label == "Bot":
            df.loc[i, 'Idle Mean'] *= 0.5
            df.loc[i, 'Active Mean'] *= 2
        elif label in ["FTP-Patator", "SSH-Patator"]:
            df.loc[i, 'Flow Duration'] *= 3
            df.loc[i, 'RST Flag Count'] += 2
        elif "Web Attack" in label:
            df.loc[i, 'Destination Port'] = 80
            df.loc[i, 'Total Length of Fwd Packets'] *= 3
    
    return df
