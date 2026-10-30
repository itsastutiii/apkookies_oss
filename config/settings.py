"""Central configuration loaded from environment / .env.

All modules import settings from here rather than reading os.environ directly,
so config is validated once and overridable in tests.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # API
    apk_env: str = "dev"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    # Ephemeral storage policy
    ephemeral_sample_ttl_seconds: int = 3600
    artifact_store_path: Path = Path("./.artifacts")
    # Remembered verdicts + audit log (hashes and verdicts only, never samples).
    verdict_db_path: Path = Path("./.artifacts/verdicts.sqlite3")
    # Analyst override/clear endpoints are disabled unless this is set; callers must
    # send it as X-Analyst-Token. Stop-gap until per-user API authentication exists.
    analyst_token: str = ""

    # Knowledge graph
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "CHANGE_ME"

    # GenAI
    gemini_api_key: str = "CHANGE_ME"
    gemini_model: str = "gemini-3.7-flash"
    gemini_fallback_model: str = "gemini-3.7-flash"
    gemini_agent: str = "antigravity-preview-05-2026"
    gemini_environment: str = "remote"
    vector_store_path: Path = Path("./.chroma")

    # Threat intel
    threatfox_api_key: str = "CHANGE_ME"

    # Sandbox
    sandbox_avd_name: str = "apkookies_clean"
    sandbox_snapshot: str = "clean_state"
    mitm_proxy_port: int = 8080
    adb_path: str = ""          # empty -> auto-detect (see sandbox.emulator.resolve_adb_path)
    android_serial: str = ""    # empty -> first online ADB device

    # Optional Quark-Engine behaviour rules (pip install -e ".[quark]"; docs/QUARK.md)
    quark_rules_dir: str = ""   # empty -> Quark disabled
    quark_min_confidence: int = 80

    # Touchpoints
    telegram_getme_endpoint: str = "https://api.telegram.org/bot{token}/getMe"
    play_integrity_project_number: str = "CHANGE_ME"


@lru_cache
def get_settings() -> Settings:
    return Settings()
