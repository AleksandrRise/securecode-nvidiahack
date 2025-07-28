"""
Pydantic models for PatchFrame API.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    """Request model for starting a scan."""
    project_path: str = Field(..., description="Path to the project to scan")
    max_commits: int = Field(default=100, description="Maximum number of commits to analyze per dependency")
    include_dev_dependencies: bool = Field(default=True, description="Include dev dependencies in scan")
    scan_depth: str = Field(default="medium", description="Scan depth: quick, medium, deep")

class DependencyModel(BaseModel):
    """Model for dependency information."""
    name: str
    version: str
    git_url: Optional[str] = None
    registry_url: Optional[str] = None
    package_type: str
    file_path: Optional[str] = None

class PatchModel(BaseModel):
    """Model for patch information."""
    sha: str
    message: str
    author: str
    date: datetime
    files_changed: List[str]
    risk_score: float
    risk_factors: List[str]
    diff_content: Optional[str] = None

class VulnerabilityModel(BaseModel):
    """Model for vulnerability information."""
    dependency_name: str
    dependency_version: str
    patch_sha: str
    patch_message: str
    patch_author: str
    patch_date: datetime
    severity: str
    description: str
    cve_id: Optional[str] = None
    confidence: float
    detection_method: str
    risk_factors: List[str]

class ScanSummary(BaseModel):
    """Model for scan summary."""
    total_dependencies: int
    total_vulnerabilities: int
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int

class ScanResult(BaseModel):
    """Model for complete scan result."""
    project_path: str
    scan_timestamp: datetime
    dependencies: List[DependencyModel]
    vulnerabilities: List[VulnerabilityModel]
    summary: ScanSummary

class ScanStatus(BaseModel):
    """Model for scan status."""
    scan_id: str
    status: str  # pending, running, completed, failed
    progress: float = Field(ge=0, le=100)
    message: Optional[str] = None
    result: Optional[ScanResult] = None
    created_at: datetime
    updated_at: datetime

class TrustScoreRequest(BaseModel):
    """Request model for calculating trust scores."""
    dependency_name: str
    patch_sha: str
    author_email: Optional[str] = None

class TrustScore(BaseModel):
    """Model for trust score information."""
    dependency_name: str
    patch_sha: str
    author_trust_score: float = Field(ge=0, le=1)
    commit_trust_score: float = Field(ge=0, le=1)
    overall_trust_score: float = Field(ge=0, le=1)
    factors: List[str]
    explanation: str

class AnomalyDetectionRequest(BaseModel):
    """Request model for anomaly detection."""
    dependency_name: str
    patch_sha: str
    diff_content: str

class AnomalyResult(BaseModel):
    """Model for anomaly detection result."""
    dependency_name: str
    patch_sha: str
    is_anomaly: bool
    anomaly_score: float = Field(ge=0, le=1)
    anomaly_type: Optional[str] = None
    description: str
    recommendations: List[str]

class SBOMRequest(BaseModel):
    """Request model for SBOM generation."""
    project_path: str
    format: str = Field(default="spdx", description="SBOM format: spdx, cyclonedx, swid")

class SBOMResult(BaseModel):
    """Model for SBOM result."""
    project_path: str
    format: str
    content: str
    generated_at: datetime
    total_components: int
    vulnerabilities_found: int

class WebhookConfig(BaseModel):
    """Model for webhook configuration."""
    url: str
    events: List[str] = Field(default=["scan.completed", "vulnerability.found"])
    secret: Optional[str] = None
    enabled: bool = True

class NotificationConfig(BaseModel):
    """Model for notification configuration."""
    email: Optional[str] = None
    slack_webhook: Optional[str] = None
    teams_webhook: Optional[str] = None
    severity_threshold: str = Field(default="medium", description="Minimum severity to notify about")

class ProjectConfig(BaseModel):
    """Model for project configuration."""
    project_path: str
    auto_scan: bool = True
    scan_schedule: Optional[str] = None  # cron expression
    webhooks: List[WebhookConfig] = []
    notifications: NotificationConfig = NotificationConfig()
    ignore_patterns: List[str] = []
    trust_threshold: float = Field(default=0.7, ge=0, le=1)

class ErrorResponse(BaseModel):
    """Model for error responses."""
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now) 