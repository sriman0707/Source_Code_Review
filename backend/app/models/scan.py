"""
SQLAlchemy Models — Scan
Represents a single security scan run against a codebase.
"""
import uuid
import enum
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, DateTime, ForeignKey, Text, Integer, Float, Enum as SAEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    FILE_UPLOAD = "file_upload"
    FOLDER_UPLOAD = "folder_upload"
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    ZIP_UPLOAD = "zip_upload"


class ScanProfile(str, enum.Enum):
    QUICK = "quick"             # Pattern + secret detection only (~30s)
    STANDARD = "standard"       # Full SAST + taint + secrets (~2min)
    DEEP = "deep"               # Standard + AI reasoning (~5min)
    BUG_BOUNTY = "bug_bounty"   # Deep + business logic + PoC generation


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Scan configuration
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(SAEnum(ScanType), nullable=False)
    scan_profile: Mapped[ScanProfile] = mapped_column(
        SAEnum(ScanProfile), default=ScanProfile.STANDARD
    )
    target_url: Mapped[Optional[str]] = mapped_column(String(500))  # GitHub/GitLab URL
    upload_path: Mapped[Optional[str]] = mapped_column(String(500))  # Local upload path
    branch: Mapped[Optional[str]] = mapped_column(String(255))
    commit_sha: Mapped[Optional[str]] = mapped_column(String(100))

    # Languages detected
    detected_languages: Mapped[Optional[dict]] = mapped_column(JSON)  # {"python": 60, "js": 40}
    frameworks_detected: Mapped[Optional[list]] = mapped_column(JSON)

    # Status tracking
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255))
    progress: Mapped[int] = mapped_column(Integer, default=0)        # 0-100
    current_phase: Mapped[Optional[str]] = mapped_column(String(100))  # e.g. "taint_analysis"
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Scan metadata
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    lines_scanned: Mapped[int] = mapped_column(Integer, default=0)
    scan_duration_seconds: Mapped[Optional[float]] = mapped_column(Float)

    # Results summary
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)  # 0-100

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    project: Mapped[Optional["Project"]] = relationship(  # noqa: F821
        "Project", back_populates="scans"
    )
    created_by: Mapped["User"] = relationship(  # noqa: F821
        "User", back_populates="scans"
    )
    findings: Mapped[List["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="scan", lazy="select", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan {self.name} [{self.status}]>"
