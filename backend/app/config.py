"""
Application Configuration
Loads all settings from environment variables with sane defaults.
"""
from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Application ─────────────────────────────────────────
    app_name: str = "SecureReview AI Platform"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False
    secret_key: str = ""
    allowed_origins: str = "http://localhost:3000,http://localhost:5173"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    # ─── Database ────────────────────────────────────────────
    database_url: str = ""
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # ─── Redis ───────────────────────────────────────────────
    redis_url: str = ""

    # ─── JWT ─────────────────────────────────────────────────
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # ─── AI Engine ───────────────────────────────────────────
    ai_provider: str = "gemini"           # "gemini" | "ollama" | "none"
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.0-flash"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ai_max_tokens: int = 8192
    ai_temperature: float = 0.1            # Low temp = deterministic security analysis

    # ─── Scan Settings ────────────────────────────────────────
    max_file_size_mb: int = 50
    max_scan_files: int = 1000
    upload_dir: str = "./uploads"
    max_scan_timeout_seconds: int = 300    # 5 minutes per scan
    scan_concurrency: int = 4

    # ─── GitHub / GitLab ─────────────────────────────────────
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None

    # ─── Dependency Scanning ─────────────────────────────────
    nvd_api_key: Optional[str] = None
    osv_api_url: str = "https://api.osv.dev/v1"
    github_advisory_url: str = "https://api.github.com/advisories"

    # ─── Severity Thresholds ─────────────────────────────────
    ai_analysis_min_severity: str = "LOW"   # Minimum severity to trigger AI analysis
    false_positive_threshold: float = 0.3   # Confidence below this → mark as potential FP

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def celery_broker_url(self) -> str:
        return self.redis_url

    @property
    def celery_result_backend(self) -> str:
        return self.redis_url


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
