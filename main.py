"""
AI-Based Intrusion Detection System (PhalanxAI)

A machine learning-powered intrusion detection system with:
- Real-time network traffic analysis
- Multiple ML models (Random Forest, Isolation Forest, Autoencoder)
- Explainable AI alerts (SHAP, LIME)
- MITRE ATT&CK framework mapping
- Modern dashboard interface
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import os

from config import settings
from api import router as api_router
from database import init_db, close_db


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown."""
    # Startup
    logger.info("Starting PhalanxAI...")
    
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Database initialization skipped: {e}")
    
    # Try to load models
    try:
        from models import ModelManager
        mm = ModelManager(settings.MODEL_DIR)
        if mm.load_all():
            logger.info("ML models loaded successfully")
        else:
            logger.info("No pre-trained models found. Train models via /api/train")
    except Exception as e:
        logger.warning(f"Model loading skipped: {e}")
    
    logger.info(f"PhalanxAI v{settings.APP_VERSION} started on http://localhost:8000")
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhalanxAI...")
    await close_db()


# Create FastAPI application
app = FastAPI(
    title="PhalanxAI",
    description="AI-Based Intrusion Detection System with ML-powered threat detection and MITRE ATT&CK mapping",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Include API router
app.include_router(api_router)


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    """Serve the main dashboard page."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "PhalanxAI API is running. Visit /docs for API documentation."}


@app.get("/docs-info")
async def docs_info():
    """API documentation information."""
    return {
        "swagger": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
