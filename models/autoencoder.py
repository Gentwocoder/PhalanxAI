"""
Autoencoder for deep learning-based anomaly detection.
"""
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import logging

logger = logging.getLogger(__name__)


class AutoencoderNetwork(nn.Module):
    """PyTorch Autoencoder architecture."""
    
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        """
        Initialize autoencoder.
        
        Args:
            input_dim: Number of input features
            encoding_dim: Dimension of the encoded representation
        """
        super().__init__()
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.2),
            nn.Linear(64, encoding_dim),
            nn.ReLU()
        )
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.2),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Dropout(0.2),
            nn.Linear(128, input_dim)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        return self.encoder(x)


class AutoencoderModel:
    """Autoencoder for reconstruction-based anomaly detection."""
    
    def __init__(
        self,
        encoding_dim: int = 32,
        learning_rate: float = 0.001,
        epochs: int = 50,
        batch_size: int = 256,
        device: Optional[str] = None
    ):
        """
        Initialize Autoencoder model.
        
        Args:
            encoding_dim: Dimension of latent space
            learning_rate: Learning rate for optimizer
            epochs: Training epochs
            batch_size: Batch size for training
            device: 'cuda' or 'cpu' (auto-detected if None)
        """
        self.encoding_dim = encoding_dim
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.batch_size = batch_size
        
        if device is None:
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = torch.device(device)
        
        self.model: Optional[AutoencoderNetwork] = None
        self.threshold: float = 0.0
        self.is_trained = False
        self.feature_names: Optional[List[str]] = None
        self.input_dim: Optional[int] = None
    
    def train(
        self, 
        X_train: np.ndarray,
        feature_names: Optional[List[str]] = None,
        X_val: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Train the autoencoder on normal traffic.
        
        Args:
            X_train: Training features (should be normal traffic)
            feature_names: Optional feature names
            X_val: Optional validation data
        
        Returns:
            Training metrics
        """
        logger.info(f"Training Autoencoder with {len(X_train)} samples on {self.device}")
        
        self.input_dim = X_train.shape[1]
        self.feature_names = feature_names
        
        # Initialize model
        self.model = AutoencoderNetwork(self.input_dim, self.encoding_dim).to(self.device)
        
        # Prepare data
        X_tensor = torch.FloatTensor(X_train).to(self.device)
        dataset = TensorDataset(X_tensor, X_tensor)
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        
        # Training setup
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=self.learning_rate)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', factor=0.5, patience=5
        )
        
        # Training loop
        history = {'train_loss': [], 'val_loss': []}
        
        for epoch in range(self.epochs):
            self.model.train()
            train_loss = 0.0
            
            for batch_x, _ in dataloader:
                optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = criterion(outputs, batch_x)
                loss.backward()
                optimizer.step()
                train_loss += loss.item()
            
            train_loss /= len(dataloader)
            history['train_loss'].append(train_loss)
            
            # Validation
            if X_val is not None:
                self.model.eval()
                with torch.no_grad():
                    X_val_tensor = torch.FloatTensor(X_val).to(self.device)
                    val_outputs = self.model(X_val_tensor)
                    val_loss = criterion(val_outputs, X_val_tensor).item()
                    history['val_loss'].append(val_loss)
                    scheduler.step(val_loss)
            else:
                scheduler.step(train_loss)
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch + 1}/{self.epochs}, Loss: {train_loss:.6f}")
        
        # Calculate threshold from reconstruction errors
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1).cpu().numpy()
            self.threshold = float(np.percentile(errors, 95))  # 95th percentile
        
        self.is_trained = True
        
        metrics = {
            'final_loss': history['train_loss'][-1],
            'threshold': self.threshold,
            'n_samples': len(X_train),
            'n_features': self.input_dim,
            'epochs': self.epochs
        }
        
        logger.info(f"Training completed. Threshold: {self.threshold:.6f}")
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict if samples are anomalies based on reconstruction error.
        
        Args:
            X: Feature array
        
        Returns:
            Array of predictions: 0 for normal, 1 for anomaly
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        errors = self.get_reconstruction_error(X)
        return (errors > self.threshold).astype(int)
    
    def get_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """
        Calculate reconstruction error for samples.
        
        Args:
            X: Feature array
        
        Returns:
            Array of reconstruction errors (MSE)
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X).to(self.device)
            reconstructed = self.model(X_tensor)
            errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
            return errors.cpu().numpy()
    
    def predict_with_scores(
        self, 
        X: np.ndarray
    ) -> List[Tuple[bool, float, str]]:
        """
        Predict with reconstruction error scores and severity.
        
        Args:
            X: Feature array
        
        Returns:
            List of (is_anomaly, error, severity)
        """
        errors = self.get_reconstruction_error(X)
        predictions = errors > self.threshold
        
        results = []
        for is_anomaly, error in zip(predictions, errors):
            # Severity based on how much error exceeds threshold
            ratio = error / self.threshold if self.threshold > 0 else error
            
            if ratio > 5:
                severity = "Critical"
            elif ratio > 3:
                severity = "High"
            elif ratio > 1.5:
                severity = "Medium"
            else:
                severity = "Low"
            
            results.append((bool(is_anomaly), float(error), severity))
        
        return results
    
    def get_feature_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """
        Get per-feature reconstruction errors (for explainability).
        
        Args:
            X: Feature array
        
        Returns:
            Array of shape (n_samples, n_features) with per-feature errors
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X).to(self.device)
            reconstructed = self.model(X_tensor)
            errors = (X_tensor - reconstructed) ** 2
            return errors.cpu().numpy()
    
    def set_threshold(self, threshold: float) -> None:
        """Set custom anomaly threshold."""
        self.threshold = threshold
        logger.info(f"Threshold updated to {threshold}")
    
    def save(self, path: str) -> None:
        """Save model to disk."""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")
        
        save_dict = {
            'model_state': self.model.state_dict(),
            'input_dim': self.input_dim,
            'encoding_dim': self.encoding_dim,
            'threshold': self.threshold,
            'feature_names': self.feature_names
        }
        torch.save(save_dict, path)
        logger.info(f"Autoencoder model saved to {path}")
    
    @classmethod
    def load(cls, path: str, device: Optional[str] = None) -> 'AutoencoderModel':
        """Load model from disk."""
        save_dict = torch.load(path, map_location='cpu')
        
        instance = cls(
            encoding_dim=save_dict['encoding_dim'],
            device=device
        )
        instance.input_dim = save_dict['input_dim']
        instance.threshold = save_dict['threshold']
        instance.feature_names = save_dict['feature_names']
        
        instance.model = AutoencoderNetwork(
            instance.input_dim, 
            instance.encoding_dim
        ).to(instance.device)
        instance.model.load_state_dict(save_dict['model_state'])
        instance.model.eval()
        instance.is_trained = True
        
        logger.info(f"Autoencoder model loaded from {path}")
        return instance
