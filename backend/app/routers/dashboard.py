"""
Dashboard Router — Aggregate Metrics, Trends, Risk Scores
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from app.core.rbac import get_current_active_user
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, Severity, FindingCategory, FindingStatus

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_dashboard_summary(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Executive dashboard summary — totals, severity distribution, risk score."""
    # Total scans
    scans_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.created_by_id == current_user.id)
    )
    total_scans = scans_result.scalar() or 0

    # Active scans
    active_result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.created_by_id == current_user.id,
            Scan.status == ScanStatus.RUNNING,
        )
    )
    active_scans = active_result.scalar() or 0

    # Total findings by severity
    severity_counts = {}
    for sev in Severity:
        result = await db.execute(
            select(func.count(Finding.id)).join(Scan).where(
                Scan.created_by_id == current_user.id,
                Finding.severity == sev,
                Finding.is_false_positive == False,
            )
        )
        severity_counts[sev.value] = result.scalar() or 0

    total_findings = sum(severity_counts.values())

    # Risk score (weighted average across all scans)
    risk_result = await db.execute(
        select(func.avg(Scan.risk_score)).where(
            Scan.created_by_id == current_user.id,
            Scan.status == ScanStatus.COMPLETED,
        )
    )
    avg_risk = round(risk_result.scalar() or 0, 1)

    # OWASP category breakdown
    owasp_map = {
        FindingCategory.INJECTION: "A03:2021",
        FindingCategory.XSS: "A03:2021",
        FindingCategory.AUTH: "A07:2021",
        FindingCategory.AUTHZ: "A01:2021",
        FindingCategory.CRYPTO: "A02:2021",
        FindingCategory.SECRET: "A02:2021",
        FindingCategory.IDOR: "A01:2021",
        FindingCategory.SSRF: "A10:2021",
        FindingCategory.XXE: "A05:2021",
        FindingCategory.DEPENDENCY: "A06:2021",
        FindingCategory.MISCONFIGURATION: "A05:2021",
    }

    owasp_counts: dict[str, int] = {}
    for cat in FindingCategory:
        result = await db.execute(
            select(func.count(Finding.id)).join(Scan).where(
                Scan.created_by_id == current_user.id,
                Finding.category == cat,
                Finding.is_false_positive == False,
            )
        )
        count = result.scalar() or 0
        owasp_label = owasp_map.get(cat, "Other")
        owasp_counts[owasp_label] = owasp_counts.get(owasp_label, 0) + count

    # Recent scans (last 7 days)
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.created_by_id == current_user.id,
            Scan.created_at >= seven_days_ago,
        )
    )
    recent_scans = recent_result.scalar() or 0

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "recent_scans_7d": recent_scans,
        "total_findings": total_findings,
        "severity_distribution": severity_counts,
        "risk_score": avg_risk,
        "owasp_breakdown": owasp_counts,
    }


@router.get("/trends")
async def get_trends(
    days: int = 30,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get finding trends over time for charts."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(
            func.date(Finding.created_at).label("date"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .join(Scan)
        .where(
            Scan.created_by_id == current_user.id,
            Finding.created_at >= cutoff,
        )
        .group_by(func.date(Finding.created_at), Finding.severity)
        .order_by(func.date(Finding.created_at))
    )
    rows = result.fetchall()

    trends: dict[str, dict] = {}
    for row in rows:
        date_str = str(row.date)
        if date_str not in trends:
            trends[date_str] = {"date": date_str, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        trends[date_str][row.severity.value] = row.count

    return {"trends": list(trends.values())}


@router.get("/top-findings")
async def get_top_findings(
    limit: int = 10,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the most critical open findings across all scans."""
    result = await db.execute(
        select(Finding, Scan.name.label("scan_name"))
        .join(Scan)
        .where(
            Scan.created_by_id == current_user.id,
            Finding.status == FindingStatus.OPEN,
            Finding.is_false_positive == False,
        )
        .order_by(
            Finding.severity.desc(),
            Finding.cvss_score.desc(),
        )
        .limit(limit)
    )
    rows = result.fetchall()

    findings = []
    for finding, scan_name in rows:
        findings.append({
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity.value,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "cwe_id": finding.cwe_id,
            "cvss_score": finding.cvss_score,
            "scan_name": scan_name,
        })

    return {"findings": findings}


@router.get("/cwe-breakdown")
async def get_cwe_breakdown(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """CWE distribution across all findings."""
    result = await db.execute(
        select(
            Finding.cwe_id,
            Finding.cwe_name,
            func.count(Finding.id).label("count"),
        )
        .join(Scan)
        .where(
            Scan.created_by_id == current_user.id,
            Finding.cwe_id.isnot(None),
            Finding.is_false_positive == False,
        )
        .group_by(Finding.cwe_id, Finding.cwe_name)
        .order_by(func.count(Finding.id).desc())
        .limit(20)
    )
    rows = result.fetchall()
    return {
        "cwe_breakdown": [
            {"cwe": r.cwe_id, "name": r.cwe_name or r.cwe_id, "count": r.count}
            for r in rows
        ]
    }
