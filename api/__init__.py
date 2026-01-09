"""API module for AI-IDS."""
from .routes import router
from .schemas import (
    NetworkFlowInput, PredictionResponse, AlertResponse,
    DashboardStats, ModelInfo, TrainRequest, TrainResponse
)

__all__ = [
    "router",
    "NetworkFlowInput", "PredictionResponse", "AlertResponse",
    "DashboardStats", "ModelInfo", "TrainRequest", "TrainResponse"
]
