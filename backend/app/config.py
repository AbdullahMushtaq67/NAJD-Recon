"""Application settings, loaded from environment variables (or a .env file)."""

import os
import shutil
import sys
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_nmap_path() -> str:
    executable = shutil.which("nmap")
    if executable:
        return executable
    if sys.platform == "win32":
        candidates = [
            Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
            / "Nmap"
            / "nmap.exe",
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
            / "Nmap"
            / "nmap.exe",
        ]
        if executable := next((path for path in candidates if path.is_file()), None):
            return str(executable)
    return "nmap"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Target safety -----------------------------------------------------------------
    # Comma-separated hostnames, IPs and CIDR ranges that may be scanned.
    # The defaults cover Nmap's official test host, localhost and the bundled Docker lab.
    allowed_targets: str = "scanme.nmap.org,127.0.0.1,172.28.0.0/24"
    # Set to true ONLY on a private, self-hosted instance where you own every reachable host.
    allow_any_target: bool = False

    # --- Scanning ------------------------------------------------------------------------
    nmap_path: str = Field(default_factory=_default_nmap_path)
    # True when nmap has raw-socket capability (root, or `setcap cap_net_raw+eip`).
    # Enables SYN / UDP / OS-detection profiles.
    nmap_privileged: bool = False
    scan_timeout_seconds: int = Field(default=900, ge=30)
    max_concurrent_scans: int = Field(default=2, ge=1)
    # Replay a recorded scan instead of running nmap (safe for public demos).
    demo_mode: bool = False

    # --- Abuse protection ----------------------------------------------------------------
    rate_limit_scans: int = 5  # scans per window per client
    rate_limit_window_seconds: int = 60
    trust_proxy_headers: bool = False  # honour X-Forwarded-For (only behind your own proxy)

    # --- CVE enrichment ------------------------------------------------------------------
    nvd_api_key: str | None = None
    nvd_enabled: bool = True
    max_cves_enriched: int = 30  # NVD is rate-limited; enrich the highest-scoring first
    kev_enabled: bool = True
    epss_enabled: bool = True  # FIRST.org EPSS API (free, no key)

    # --- AI explanations (Google Gemini) --------------------------------------------------
    gemini_api_key: str | None = None  # AI explanations are on when this is set
    gemini_model: str | None = None  # empty = gemini-3.6-flash
    # Tried in order when the main model is overloaded, slow or unavailable (comma-separated).
    gemini_fallback_models: str = "gemini-3.5-flash-lite"
    gemini_timeout_seconds: int = Field(default=30, ge=5, le=600)  # per model

    # --- Storage / server ----------------------------------------------------------------
    database_path: str = "data/najd-recon.db"
    cors_origins: str = "http://localhost:5173"

    @property
    def allowed_target_list(self) -> list[str]:
        return [t.strip() for t in self.allowed_targets.split(",") if t.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
