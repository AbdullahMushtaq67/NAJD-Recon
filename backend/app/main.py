"""NAJD Recon API entry point.

Run locally:  uvicorn app.main:app --reload
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.ai.explainer import CVEExplainer
from app.ai.gemini import build_client
from app.api.routes import router
from app.config import Settings, get_settings
from app.core.database import Database
from app.core.jobs import ScanManager
from app.core.ratelimit import RateLimiter
from app.cve.enricher import CVEEnricher
from app.cve.epss import EPSSClient
from app.cve.kev import KEVCatalog
from app.cve.nvd import NVDClient
from app.scanner.validator import Allowlist

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("najd_recon")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = Database(settings.database_path)
        await db.init()
        interrupted = await db.fail_unfinished()
        if interrupted:
            log.warning("Marked %d interrupted scans as failed", interrupted)

        data_dir = Path(settings.database_path).parent
        nvd = NVDClient(db, settings.nvd_api_key) if settings.nvd_enabled else None
        kev = KEVCatalog(str(data_dir / "kev.json"), enabled=settings.kev_enabled)
        epss = EPSSClient(enabled=settings.epss_enabled)
        enricher = CVEEnricher(nvd, kev, settings.max_cves_enriched, epss=epss)
        gemini = build_client(settings)

        app.state.settings = settings
        app.state.db = db
        app.state.allowlist = Allowlist(settings.allowed_target_list, settings.allow_any_target)
        app.state.enricher = enricher
        app.state.explainer = CVEExplainer(gemini, db) if gemini else None
        app.state.manager = ScanManager(settings, db, enricher)
        app.state.scan_limiter = RateLimiter(
            settings.rate_limit_scans, settings.rate_limit_window_seconds
        )
        app.state.ai_limiter = RateLimiter(20, 60)

        if settings.allow_any_target:
            log.warning("ALLOW_ANY_TARGET is on: only run this on a private network you control")
        log.info(
            "NAJD Recon %s ready (demo=%s, privileged=%s, ai=%s)",
            __version__, settings.demo_mode, settings.nmap_privileged,
            gemini.model if gemini else "off",
        )
        yield
        await app.state.manager.shutdown()

    app = FastAPI(
        title="NAJD Recon API",
        version=__version__,
        description="Nmap scanning with CVE enrichment (NVD, CISA KEV) and AI explanations.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    app.include_router(router)
    return app


app = create_app()
