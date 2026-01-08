"""
AI-Based Intrusion Detection System - Database Models
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Float, Integer, DateTime, Text, JSON, Boolean, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from config import settings


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class Alert(Base):
    """Intrusion detection alert."""
    __tablename__ = "alerts"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    # Source and destination
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    
    # Detection results
    attack_type: Mapped[str] = mapped_column(String(100), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(20), index=True)  # Critical, High, Medium, Low
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Explainability
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    top_features: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # MITRE ATT&CK mapping
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_technique_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Status
    status: Mapped[str] = mapped_column(String(20), default="new")  # new, investigating, resolved, false_positive
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Raw features stored for reference
    raw_features: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class ModelMetrics(Base):
    """Model training and evaluation metrics."""
    __tablename__ = "model_metrics"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    model_name: Mapped[str] = mapped_column(String(100), index=True)
    model_type: Mapped[str] = mapped_column(String(50))  # random_forest, isolation_forest, autoencoder
    trained_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Performance metrics
    accuracy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    precision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    f1_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    auc_roc: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # Training info
    training_samples: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    test_samples: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    training_duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # Hyperparameters
    hyperparameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    model_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


class DashboardStats(Base):
    """Cached dashboard statistics for quick retrieval."""
    __tablename__ = "dashboard_stats"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    # Counts
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Attack type distribution
    attack_distribution: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Hourly traffic volume
    hourly_traffic: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


# Database engine and session factory
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    pool_size=5,
    max_overflow=10
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def get_db() -> AsyncSession:
    """Dependency to get database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Close database connections."""
    await engine.dispose()
