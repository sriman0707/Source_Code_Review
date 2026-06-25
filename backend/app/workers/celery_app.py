"""Celery Application Setup"""
from celery import Celery
from app.config import settings

celery_app = Celery(
    "securereview",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.scan_worker"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={"app.workers.scan_worker.*": {"queue": "scans"}},
    task_soft_time_limit=settings.max_scan_timeout_seconds,
    task_time_limit=settings.max_scan_timeout_seconds + 60,
    result_expires=86400,  # 24 hours
)
