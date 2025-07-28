"""
Database models for PatchFrame.
"""

from sqlalchemy import create_engine, Column, String, DateTime, Integer, Float, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import os

Base = declarative_base()

class ScanRecord(Base):
    """Model for storing scan records."""
    __tablename__ = 'scan_records'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, nullable=False)
    project_path = Column(String(500), nullable=False)
    status = Column(String(20), nullable=False, default='pending')  # pending, running, completed, failed
    progress = Column(Float, default=0.0)
    message = Column(Text)
    result = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

class VulnerabilityRecord(Base):
    """Model for storing vulnerability records."""
    __tablename__ = 'vulnerability_records'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), nullable=False)
    dependency_name = Column(String(200), nullable=False)
    dependency_version = Column(String(50), nullable=False)
    patch_sha = Column(String(40), nullable=False)
    patch_message = Column(Text)
    patch_author = Column(String(200))
    patch_date = Column(DateTime)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    description = Column(Text)
    cve_id = Column(String(20))
    confidence = Column(Float)
    detection_method = Column(String(50))
    risk_factors = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)

class DependencyRecord(Base):
    """Model for storing dependency records."""
    __tablename__ = 'dependency_records'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), nullable=False)
    name = Column(String(200), nullable=False)
    version = Column(String(50), nullable=False)
    git_url = Column(String(500))
    registry_url = Column(String(500))
    package_type = Column(String(20), nullable=False)
    file_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.now)

class TrustScoreRecord(Base):
    """Model for storing trust score records."""
    __tablename__ = 'trust_score_records'
    
    id = Column(Integer, primary_key=True)
    dependency_name = Column(String(200), nullable=False)
    patch_sha = Column(String(40), nullable=False)
    author_trust_score = Column(Float)
    commit_trust_score = Column(Float)
    overall_trust_score = Column(Float)
    factors = Column(JSON)
    explanation = Column(Text)
    created_at = Column(DateTime, default=datetime.now)

class AnomalyRecord(Base):
    """Model for storing anomaly detection records."""
    __tablename__ = 'anomaly_records'
    
    id = Column(Integer, primary_key=True)
    dependency_name = Column(String(200), nullable=False)
    patch_sha = Column(String(40), nullable=False)
    is_anomaly = Column(Boolean, nullable=False)
    anomaly_score = Column(Float)
    anomaly_type = Column(String(20))  # low, medium, high, critical, none
    description = Column(Text)
    recommendations = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)

class SBOMRecord(Base):
    """Model for storing SBOM records."""
    __tablename__ = 'sbom_records'
    
    id = Column(Integer, primary_key=True)
    project_path = Column(String(500), nullable=False)
    format = Column(String(20), nullable=False)  # spdx, cyclonedx, swid
    content = Column(Text, nullable=False)
    total_components = Column(Integer)
    vulnerabilities_found = Column(Integer)
    generated_at = Column(DateTime, default=datetime.now)

class NotificationRecord(Base):
    """Model for storing notification records."""
    __tablename__ = 'notification_records'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), nullable=False)
    notification_type = Column(String(50), nullable=False)  # email, slack, teams
    recipient = Column(String(200))
    subject = Column(String(500))
    content = Column(Text)
    status = Column(String(20), default='pending')  # pending, sent, failed
    error_message = Column(Text)
    sent_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.now)

# Database configuration
def get_database_url():
    """Get database URL from environment or use default."""
    return os.getenv('DATABASE_URL', 'sqlite:///patchframe.db')

def create_database_engine():
    """Create database engine."""
    database_url = get_database_url()
    return create_engine(database_url, echo=False)

def create_database_session():
    """Create database session factory."""
    engine = create_database_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal

def get_db():
    """Get database session."""
    SessionLocal = create_database_session()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_database():
    """Initialize database tables."""
    engine = create_database_engine()
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully")

def drop_database():
    """Drop all database tables."""
    engine = create_database_engine()
    Base.metadata.drop_all(bind=engine)
    print("Database dropped successfully") 