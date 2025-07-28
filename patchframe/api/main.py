"""
FastAPI application for PatchFrame API.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from .models import (
    ScanRequest, ScanResult, ScanStatus, TrustScoreRequest, TrustScore,
    AnomalyDetectionRequest, AnomalyResult, SBOMRequest, SBOMResult,
    ProjectConfig, ErrorResponse
)
from ..core.scanner import PatchFrameScanner
from ..services.trust_scorer import TrustScorer
from ..services.anomaly_detector import AnomalyDetector
from ..services.sbom_generator import SBOMGenerator
from ..services.notification_service import NotificationService
from ..database.models import get_db, ScanRecord

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="PatchFrame API",
    description="Real-Time Patch-Level Vulnerability Scanner for Open Source Dependencies",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global services
scanner = PatchFrameScanner()
trust_scorer = TrustScorer()
anomaly_detector = AnomalyDetector()
sbom_generator = SBOMGenerator()
notification_service = NotificationService()

# In-memory storage for scan status (use Redis/DB in production)
scan_statuses: Dict[str, ScanStatus] = {}

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal Server Error",
            message="An unexpected error occurred",
            details={"exception": str(exc)}
        ).dict()
    )

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "PatchFrame API",
        "version": "1.0.0",
        "description": "Real-Time Patch-Level Vulnerability Scanner",
        "endpoints": {
            "scan": "/api/v1/scan",
            "status": "/api/v1/scan/{scan_id}",
            "trust": "/api/v1/trust",
            "anomaly": "/api/v1/anomaly",
            "sbom": "/api/v1/sbom",
            "docs": "/docs"
        }
    }

@app.post("/api/v1/scan", response_model=ScanStatus)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db)
):
    """Start a new vulnerability scan."""
    try:
        # Validate project path
        project_path = Path(request.project_path)
        if not project_path.exists():
            raise HTTPException(status_code=400, detail="Project path does not exist")
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create initial scan status
        scan_status = ScanStatus(
            scan_id=scan_id,
            status="pending",
            progress=0.0,
            message="Scan queued",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        scan_statuses[scan_id] = scan_status
        
        # Add scan to background tasks
        background_tasks.add_task(
            run_scan,
            scan_id=scan_id,
            project_path=str(project_path),
            max_commits=request.max_commits,
            include_dev_dependencies=request.include_dev_dependencies,
            scan_depth=request.scan_depth
        )
        
        # Save to database
        scan_record = ScanRecord(
            scan_id=scan_id,
            project_path=str(project_path),
            status="pending",
            created_at=datetime.now()
        )
        db.add(scan_record)
        db.commit()
        
        return scan_status
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str, db = Depends(get_db)):
    """Get the status of a scan."""
    try:
        # Check in-memory status first
        if scan_id in scan_statuses:
            return scan_statuses[scan_id]
        
        # Check database
        scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        if not scan_record:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Convert database record to ScanStatus
        scan_status = ScanStatus(
            scan_id=scan_record.scan_id,
            status=scan_record.status,
            progress=scan_record.progress or 0.0,
            message=scan_record.message,
            result=scan_record.result,
            created_at=scan_record.created_at,
            updated_at=scan_record.updated_at or scan_record.created_at
        )
        
        return scan_status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scans", response_model=list[ScanStatus])
async def list_scans(
    limit: int = Query(default=10, le=100),
    offset: int = Query(default=0, ge=0),
    db = Depends(get_db)
):
    """List recent scans."""
    try:
        scan_records = db.query(ScanRecord).order_by(
            ScanRecord.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        scans = []
        for record in scan_records:
            scan_status = ScanStatus(
                scan_id=record.scan_id,
                status=record.status,
                progress=record.progress or 0.0,
                message=record.message,
                result=record.result,
                created_at=record.created_at,
                updated_at=record.updated_at or record.created_at
            )
            scans.append(scan_status)
        
        return scans
        
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/trust", response_model=TrustScore)
async def calculate_trust_score(request: TrustScoreRequest):
    """Calculate trust score for a patch."""
    try:
        trust_score = await trust_scorer.calculate_trust_score(
            dependency_name=request.dependency_name,
            patch_sha=request.patch_sha,
            author_email=request.author_email
        )
        return trust_score
        
    except Exception as e:
        logger.error(f"Failed to calculate trust score: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/anomaly", response_model=AnomalyResult)
async def detect_anomaly(request: AnomalyDetectionRequest):
    """Detect anomalies in a patch."""
    try:
        anomaly_result = await anomaly_detector.detect_anomaly(
            dependency_name=request.dependency_name,
            patch_sha=request.patch_sha,
            diff_content=request.diff_content
        )
        return anomaly_result
        
    except Exception as e:
        logger.error(f"Failed to detect anomaly: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/sbom", response_model=SBOMResult)
async def generate_sbom(request: SBOMRequest):
    """Generate Software Bill of Materials."""
    try:
        # Validate project path
        project_path = Path(request.project_path)
        if not project_path.exists():
            raise HTTPException(status_code=400, detail="Project path does not exist")
        
        sbom_result = await sbom_generator.generate_sbom(
            project_path=str(project_path),
            format=request.format
        )
        return sbom_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate SBOM: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "scanner": "operational",
            "trust_scorer": "operational",
            "anomaly_detector": "operational",
            "sbom_generator": "operational"
        }
    }

@app.get("/api/v1/stats")
async def get_stats(db = Depends(get_db)):
    """Get API statistics."""
    try:
        total_scans = db.query(ScanRecord).count()
        completed_scans = db.query(ScanRecord).filter(ScanRecord.status == "completed").count()
        failed_scans = db.query(ScanRecord).filter(ScanRecord.status == "failed").count()
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0,
            "active_scans": len([s for s in scan_statuses.values() if s.status == "running"])
        }
        
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_scan(
    scan_id: str,
    project_path: str,
    max_commits: int,
    include_dev_dependencies: bool,
    scan_depth: str
):
    """Run a scan in the background."""
    try:
        # Update status to running
        scan_statuses[scan_id].status = "running"
        scan_statuses[scan_id].progress = 10.0
        scan_statuses[scan_id].message = "Scanning dependencies..."
        scan_statuses[scan_id].updated_at = datetime.now()
        
        # Run the scan
        result = await scanner.scan_project(project_path)
        
        # Update status to completed
        scan_statuses[scan_id].status = "completed"
        scan_statuses[scan_id].progress = 100.0
        scan_statuses[scan_id].message = "Scan completed successfully"
        scan_statuses[scan_id].result = ScanResult(**result)
        scan_statuses[scan_id].updated_at = datetime.now()
        
        # Send notifications if vulnerabilities found
        if result['summary']['total_vulnerabilities'] > 0:
            await notification_service.send_vulnerability_notification(result)
        
        # Update database
        db = next(get_db())
        scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        if scan_record:
            scan_record.status = "completed"
            scan_record.progress = 100.0
            scan_record.message = "Scan completed successfully"
            scan_record.result = result
            scan_record.updated_at = datetime.now()
            db.commit()
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        
        # Update status to failed
        scan_statuses[scan_id].status = "failed"
        scan_statuses[scan_id].message = f"Scan failed: {str(e)}"
        scan_statuses[scan_id].updated_at = datetime.now()
        
        # Update database
        try:
            db = next(get_db())
            scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
            if scan_record:
                scan_record.status = "failed"
                scan_record.message = f"Scan failed: {str(e)}"
                scan_record.updated_at = datetime.now()
                db.commit()
        except Exception as db_error:
            logger.error(f"Failed to update database for failed scan: {db_error}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 