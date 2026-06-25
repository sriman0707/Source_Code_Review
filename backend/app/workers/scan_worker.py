"""
Celery Scan Worker
==================
Executes security scans asynchronously.
Updates scan status and findings in the database.
"""
import asyncio
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from celery import Task
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.workers.celery_app import celery_app
from app.engines.sast_engine import sast_engine, ScanResult
from app.config import settings

logger = logging.getLogger(__name__)


def run_async(coro):
    """Run a coroutine in a new event loop (for Celery worker context)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="app.workers.scan_worker.run_scan",
    max_retries=2,
    default_retry_delay=10,
)
def run_scan(self: Task, scan_id: str, upload_path: str, profile: str = "standard"):
    """
    Main scan task.
    - Runs the full SAST engine on the uploaded code
    - Updates scan status in real-time via DB
    - Stores all findings
    """
    logger.info(f"[{scan_id}] Scan task started (profile={profile})")

    try:
        result = run_async(_execute_scan(self, scan_id, upload_path, profile))
        return {"scan_id": scan_id, "status": "completed", "findings": result.total_findings}
    except Exception as e:
        logger.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
        run_async(_update_scan_failed(scan_id, str(e)))
        raise self.retry(exc=e)


async def _execute_scan(task: Task, scan_id: str, upload_path: str, profile: str):
    """Core async scan execution."""
    from app.database import AsyncSessionLocal
    from app.models.scan import Scan, ScanStatus
    from app.models.finding import Finding, Severity, FindingStatus, FindingCategory

    async with AsyncSessionLocal() as db:
        # Mark as running
        await db.execute(
            update(Scan)
            .where(Scan.id == uuid.UUID(scan_id))
            .values(
                status=ScanStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
                current_phase="initializing",
                progress=5,
            )
        )
        await db.commit()

    def progress_callback(progress: int, phase: str):
        """Update scan progress in DB (fire-and-forget)."""
        async def _update():
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id))
                    .values(progress=progress, current_phase=phase)
                )
                await db.commit()
        asyncio.create_task(_update())

    # Run scan
    scan_result: ScanResult = await sast_engine.scan_directory(
        scan_id=scan_id,
        directory=upload_path,
        profile=profile,
        progress_callback=progress_callback,
    )

    # Save findings to DB
    async with AsyncSessionLocal() as db:
        finding_objs = []
        for f in scan_result.findings:
            # Map category
            cat_map = {
                "injection": FindingCategory.INJECTION,
                "xss": FindingCategory.XSS,
                "authentication": FindingCategory.AUTH,
                "authorization": FindingCategory.AUTHZ,
                "cryptography": FindingCategory.CRYPTO,
                "secret": FindingCategory.SECRET,
                "idor": FindingCategory.IDOR,
                "ssrf": FindingCategory.SSRF,
                "xxe": FindingCategory.XXE,
                "ssti": FindingCategory.SSTI,
                "rce": FindingCategory.RCE,
                "path_traversal": FindingCategory.PATH_TRAVERSAL,
                "business_logic": FindingCategory.BUSINESS_LOGIC,
                "dependency": FindingCategory.DEPENDENCY,
                "iac": FindingCategory.IAC,
                "graphql": FindingCategory.GRAPHQL,
                "misconfiguration": FindingCategory.MISCONFIGURATION,
                "data_exposure": FindingCategory.DATA_EXPOSURE,
            }
            sev_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFO": Severity.INFO,
            }
            finding = Finding(
                scan_id=uuid.UUID(scan_id),
                title=f.title[:500],
                description=f.description,
                category=cat_map.get(f.category, FindingCategory.OTHER),
                severity=sev_map.get(f.severity, Severity.MEDIUM),
                status=FindingStatus.OPEN,
                file_path=_relative_path(f.file_path, upload_path),
                line_start=f.line_start,
                line_end=f.line_end,
                column_start=f.col_start,
                code_snippet=f.code_snippet[:2000] if f.code_snippet else None,
                cwe_id=f.cwe_id,
                owasp_category=f.owasp_category,
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                rule_id=f.rule_id,
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
                fingerprint=f.fingerprint,
                bug_bounty_title=f.bug_bounty_title,
                bug_bounty_report=f.bug_bounty_report,
                estimated_bounty=f.estimated_bounty,
                is_false_positive=f.is_false_positive,
            )
            finding_objs.append(finding)
            db.add(finding)

        severity_counts = scan_result.by_severity
        await db.execute(
            update(Scan)
            .where(Scan.id == uuid.UUID(scan_id))
            .values(
                status=ScanStatus.COMPLETED,
                completed_at=datetime.now(timezone.utc),
                progress=100,
                current_phase="complete",
                files_scanned=scan_result.files_scanned,
                lines_scanned=scan_result.lines_scanned,
                total_findings=scan_result.total_findings,
                critical_count=severity_counts.get("CRITICAL", 0),
                high_count=severity_counts.get("HIGH", 0),
                medium_count=severity_counts.get("MEDIUM", 0),
                low_count=severity_counts.get("LOW", 0),
                info_count=severity_counts.get("INFO", 0),
                risk_score=scan_result.risk_score,
                detected_languages=scan_result.detected_languages,
                frameworks_detected=scan_result.frameworks_detected,
            )
        )
        await db.commit()

    # Cleanup uploaded files after scan (optional, keep for re-scan)
    logger.info(f"[{scan_id}] Scan complete — {scan_result.total_findings} findings saved")
    return scan_result


async def _update_scan_failed(scan_id: str, error: str):
    from app.database import AsyncSessionLocal
    from app.models.scan import Scan, ScanStatus
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Scan)
            .where(Scan.id == uuid.UUID(scan_id))
            .values(status=ScanStatus.FAILED, error_message=error[:500])
        )
        await db.commit()


def _relative_path(absolute_path: str, base_dir: str) -> str:
    """Convert absolute path to relative for storage."""
    try:
        return str(Path(absolute_path).relative_to(base_dir))
    except ValueError:
        return absolute_path
