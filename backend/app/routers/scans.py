"""
Scans Router — Trigger, Monitor, and Manage Security Scans
"""
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.rbac import get_current_active_user, require_developer_or_above
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan, ScanStatus, ScanType, ScanProfile
from app.config import settings

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class ScanResponse(BaseModel):
    id: str
    name: str
    status: str
    profile: str
    progress: int
    current_phase: Optional[str]
    files_scanned: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: int
    created_at: datetime
    completed_at: Optional[datetime]


def _scan_to_response(scan: Scan) -> ScanResponse:
    return ScanResponse(
        id=str(scan.id),
        name=scan.name,
        status=scan.status.value,
        profile=scan.scan_profile.value,
        progress=scan.progress,
        current_phase=scan.current_phase,
        files_scanned=scan.files_scanned,
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@router.post("/upload", response_model=ScanResponse, status_code=202)
async def scan_upload(
    file: UploadFile = File(...),
    name: str = Form(...),
    profile: str = Form("standard"),
    project_id: Optional[str] = Form(None),
    current_user: User = Depends(require_developer_or_above),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload a file or ZIP archive for scanning.
    Returns immediately with scan ID; scan runs asynchronously.
    """
    scan_id = str(uuid.uuid4())
    upload_dir = Path(settings.upload_dir) / scan_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Validate file size
    content = await file.read()
    if len(content) > settings.max_file_size_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large")

    # Determine scan type
    filename = file.filename or "upload"
    if filename.endswith(".zip"):
        scan_type = ScanType.ZIP_UPLOAD
        zip_path = upload_dir / filename
        zip_path.write_bytes(content)
        # Extract
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(upload_dir / "extracted")
            upload_path = str(upload_dir / "extracted")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid ZIP file")
    else:
        scan_type = ScanType.FILE_UPLOAD
        file_path = upload_dir / filename
        file_path.write_bytes(content)
        upload_path = str(file_path)

    # Validate profile
    try:
        profile_enum = ScanProfile(profile)
    except ValueError:
        profile_enum = ScanProfile.STANDARD

    # Create scan record
    scan = Scan(
        id=uuid.UUID(scan_id),
        created_by_id=current_user.id,
        project_id=uuid.UUID(project_id) if project_id else None,
        name=name,
        scan_type=scan_type,
        scan_profile=profile_enum,
        upload_path=upload_path,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Dispatch to Celery
    from app.workers.scan_worker import run_scan
    task = run_scan.apply_async(
        kwargs={"scan_id": scan_id, "upload_path": upload_path, "profile": profile},
        queue="scans",
    )
    await db.execute(
        update(Scan).where(Scan.id == scan.id).values(celery_task_id=task.id)
    )
    await db.commit()

    return _scan_to_response(scan)


@router.post("/github", response_model=ScanResponse, status_code=202)
async def scan_github(
    repo_url: str = Form(...),
    name: str = Form(...),
    branch: str = Form("main"),
    profile: str = Form("standard"),
    current_user: User = Depends(require_developer_or_above),
    db: AsyncSession = Depends(get_db),
):
    """Clone a GitHub repository and scan it."""
    scan_id = str(uuid.uuid4())
    clone_dir = Path(settings.upload_dir) / scan_id / "repo"
    clone_dir.mkdir(parents=True, exist_ok=True)

    # Clone repo
    import subprocess
    git_cmd = ["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(clone_dir)]
    if settings.github_token:
        # Inject token into URL for private repos
        repo_url_auth = repo_url.replace(
            "https://", f"https://{settings.github_token}@"
        )
        git_cmd[4] = repo_url_auth

    try:
        result = subprocess.run(
            git_cmd, capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Git clone failed: {result.stderr[:200]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Git clone timed out")

    try:
        profile_enum = ScanProfile(profile)
    except ValueError:
        profile_enum = ScanProfile.STANDARD

    scan = Scan(
        id=uuid.UUID(scan_id),
        created_by_id=current_user.id,
        name=name,
        scan_type=ScanType.GITHUB,
        scan_profile=profile_enum,
        target_url=repo_url,
        branch=branch,
        upload_path=str(clone_dir),
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.workers.scan_worker import run_scan
    task = run_scan.apply_async(
        kwargs={"scan_id": scan_id, "upload_path": str(clone_dir), "profile": profile},
        queue="scans",
    )
    await db.execute(
        update(Scan).where(Scan.id == scan.id).values(celery_task_id=task.id)
    )
    await db.commit()

    return _scan_to_response(scan)


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    status_filter: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List all scans for the current user."""
    query = select(Scan).where(Scan.created_by_id == current_user.id)
    if status_filter:
        try:
            query = query.where(Scan.status == ScanStatus(status_filter))
        except ValueError:
            pass
    query = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()
    return [_scan_to_response(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan details by ID."""
    result = await db.execute(
        select(Scan).where(Scan.id == uuid.UUID(scan_id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_response(scan)


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a pending or running scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == uuid.UUID(scan_id), Scan.created_by_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.celery_task_id:
        from app.workers.celery_app import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    await db.execute(
        update(Scan).where(Scan.id == scan.id).values(status=ScanStatus.CANCELLED)
    )
    await db.commit()


@router.websocket("/{scan_id}/progress")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """WebSocket endpoint for real-time scan progress updates."""
    import asyncio
    import json
    await websocket.accept()
    try:
        while True:
            result = await db.execute(
                select(Scan).where(Scan.id == uuid.UUID(scan_id))
            )
            scan = result.scalar_one_or_none()
            if not scan:
                await websocket.close(code=1008)
                return

            await websocket.send_text(json.dumps({
                "scan_id": scan_id,
                "status": scan.status.value,
                "progress": scan.progress,
                "phase": scan.current_phase,
                "findings": scan.total_findings,
            }))

            if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                break

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
