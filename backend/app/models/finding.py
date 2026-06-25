"""
SQLAlchemy Models — Finding
Represents a single security vulnerability finding from a scan.
"""
import uuid
import enum
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey, Text, Integer, Float, Boolean, Enum as SAEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    IN_REVIEW = "in_review"


class FindingCategory(str, enum.Enum):
    INJECTION = "injection"
    XSS = "xss"
    AUTH = "authentication"
    AUTHZ = "authorization"
    CRYPTO = "cryptography"
    SECRET = "secret"
    IDOR = "idor"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    RCE = "rce"
    PATH_TRAVERSAL = "path_traversal"
    BUSINESS_LOGIC = "business_logic"
    DEPENDENCY = "dependency"
    IAC = "iac"
    GRAPHQL = "graphql"
    API = "api"
    SUPPLY_CHAIN = "supply_chain"
    MISCONFIGURATION = "misconfiguration"
    DATA_EXPOSURE = "data_exposure"
    OTHER = "other"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )

    # ─── Vulnerability Details ────────────────────────────────
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[FindingCategory] = mapped_column(SAEnum(FindingCategory), nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(SAEnum(FindingStatus), default=FindingStatus.OPEN)

    # ─── Location ─────────────────────────────────────────────
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    line_start: Mapped[Optional[int]] = mapped_column(Integer)
    line_end: Mapped[Optional[int]] = mapped_column(Integer)
    column_start: Mapped[Optional[int]] = mapped_column(Integer)
    affected_function: Mapped[Optional[str]] = mapped_column(String(500))
    affected_class: Mapped[Optional[str]] = mapped_column(String(500))
    code_snippet: Mapped[Optional[str]] = mapped_column(Text)   # Surrounding code context

    # ─── Classification ───────────────────────────────────────
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50))        # e.g. "CWE-89"
    cwe_name: Mapped[Optional[str]] = mapped_column(String(255))
    owasp_category: Mapped[Optional[str]] = mapped_column(String(100))  # e.g. "A03:2021"
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200))
    rule_id: Mapped[Optional[str]] = mapped_column(String(100))      # Rule that triggered this

    # ─── AI Analysis ──────────────────────────────────────────
    ai_analyzed: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float)   # 0.0 - 1.0
    exploitability: Mapped[Optional[str]] = mapped_column(String(50))  # HIGH, MEDIUM, LOW
    attack_scenario: Mapped[Optional[str]] = mapped_column(Text)
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text)
    business_impact: Mapped[Optional[str]] = mapped_column(Text)
    ai_remediation: Mapped[Optional[str]] = mapped_column(Text)
    secure_code_example: Mapped[Optional[str]] = mapped_column(Text)
    references: Mapped[Optional[list]] = mapped_column(JSON)         # List of URLs

    # ─── Taint Analysis ───────────────────────────────────────
    taint_source: Mapped[Optional[str]] = mapped_column(Text)        # Source of tainted data
    taint_sink: Mapped[Optional[str]] = mapped_column(Text)          # Dangerous sink
    taint_path: Mapped[Optional[list]] = mapped_column(JSON)         # List of path nodes

    # ─── Detection Metadata ───────────────────────────────────
    detection_method: Mapped[Optional[str]] = mapped_column(String(100))  # "sast", "ai", "taint"
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive_reason: Mapped[Optional[str]] = mapped_column(Text)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(255), index=True)  # For dedup

    # ─── Bug Bounty Fields ────────────────────────────────────
    bug_bounty_title: Mapped[Optional[str]] = mapped_column(String(500))
    bug_bounty_report: Mapped[Optional[str]] = mapped_column(Text)   # Full HackerOne-style report
    estimated_bounty: Mapped[Optional[str]] = mapped_column(String(50))  # e.g. "$500-$5000"

    # ─── Timestamps ───────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Finding [{self.severity}] {self.title} @ {self.file_path}:{self.line_start}>"
