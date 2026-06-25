"""
Findings Router — CRUD, Filtering, Export
"""
import uuid
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func

from app.core.rbac import get_current_active_user
from app.database import get_db
from app.models.user import User
from app.models.finding import Finding, Severity, FindingStatus, FindingCategory
from app.models.scan import Scan

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    category: str
    severity: str
    status: str
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    code_snippet: Optional[str]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    ai_analyzed: bool
    ai_confidence: Optional[float]
    exploitability: Optional[str]
    attack_scenario: Optional[str]
    proof_of_concept: Optional[str]
    business_impact: Optional[str]
    ai_remediation: Optional[str]
    secure_code_example: Optional[str]
    references: Optional[list]
    taint_source: Optional[str]
    taint_sink: Optional[str]
    detection_method: Optional[str]
    bug_bounty_title: Optional[str]
    bug_bounty_report: Optional[str]
    estimated_bounty: Optional[str]
    created_at: datetime


class UpdateFindingRequest(BaseModel):
    status: Optional[str] = None
    is_false_positive: Optional[bool] = None
    false_positive_reason: Optional[str] = None


def _finding_to_response(f: Finding) -> FindingResponse:
    return FindingResponse(
        id=str(f.id),
        scan_id=str(f.scan_id),
        title=f.title,
        description=f.description,
        category=f.category.value,
        severity=f.severity.value,
        status=f.status.value,
        file_path=f.file_path,
        line_start=f.line_start,
        line_end=f.line_end,
        code_snippet=f.code_snippet,
        cwe_id=f.cwe_id,
        owasp_category=f.owasp_category,
        cvss_score=f.cvss_score,
        cvss_vector=f.cvss_vector,
        ai_analyzed=f.ai_analyzed,
        ai_confidence=f.ai_confidence,
        exploitability=f.exploitability,
        attack_scenario=f.attack_scenario,
        proof_of_concept=f.proof_of_concept,
        business_impact=f.business_impact,
        ai_remediation=f.ai_remediation,
        secure_code_example=f.secure_code_example,
        references=f.references,
        taint_source=f.taint_source,
        taint_sink=f.taint_sink,
        detection_method=f.detection_method,
        bug_bounty_title=f.bug_bounty_title,
        bug_bounty_report=f.bug_bounty_report,
        estimated_bounty=f.estimated_bounty,
        created_at=f.created_at,
    )


@router.get("/scan/{scan_id}", response_model=List[FindingResponse])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all findings for a scan, with filtering."""
    query = select(Finding).where(Finding.scan_id == uuid.UUID(scan_id))

    if severity:
        try:
            query = query.where(Finding.severity == Severity(severity.upper()))
        except ValueError:
            pass
    if category:
        try:
            query = query.where(Finding.category == FindingCategory(category))
        except ValueError:
            pass
    if status_filter:
        try:
            query = query.where(Finding.status == FindingStatus(status_filter))
        except ValueError:
            pass

    query = query.order_by(Finding.severity.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()
    return [_finding_to_response(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single finding by ID."""
    result = await db.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_to_response(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    data: UpdateFindingRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Update finding status (mark FP, confirm, fix, etc.)."""
    result = await db.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = {}
    if data.status:
        try:
            update_data["status"] = FindingStatus(data.status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {data.status}")
    if data.is_false_positive is not None:
        update_data["is_false_positive"] = data.is_false_positive
        if data.is_false_positive:
            update_data["status"] = FindingStatus.FALSE_POSITIVE
    if data.false_positive_reason:
        update_data["false_positive_reason"] = data.false_positive_reason

    if update_data:
        await db.execute(
            update(Finding).where(Finding.id == finding.id).values(**update_data)
        )
        await db.commit()
        await db.refresh(finding)

    return _finding_to_response(finding)
