"""HTTP API. Interactive docs are served at /docs (Swagger UI) by FastAPI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import sqlite3
import subprocess
import uuid
from dataclasses import asdict
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse

from app import __version__
from app.ai.explainer import ExplainerError
from app.core.ratelimit import client_key
from app.models import (
    CVE,
    Asset,
    AssetInput,
    ExplainRequest,
    Explanation,
    FindingRecord,
    FindingReviewInput,
    Notification,
    SavedView,
    SavedViewInput,
    ScanJob,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    WorkspaceSettings,
    severity_from_cvss,
)
from app.reports.pdf import build_scan_pdf
from app.scanner.commands import (
    PORT_PRESETS,
    TECHNIQUES,
    TIMING_TEMPLATES,
    CommandError,
    ScanOptions,
    build_command,
    explain_command,
)
from app.scanner.runner import nmap_available
from app.scanner.validator import TargetError, resolve_and_authorise

router = APIRouter(prefix="/api")

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
FINISHED = {ScanStatus.completed, ScanStatus.failed}


def _finding_id(target: str, host: str, port: int, protocol: str, cve_id: str) -> str:
    identity = "\0".join((target, host, str(port), protocol, cve_id))
    return hashlib.sha256(identity.encode()).hexdigest()


def _format_command(argv: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


async def _finding_records(request: Request) -> list[FindingRecord]:
    db = _state(request).db
    reviews = await db.list_finding_reviews()
    latest: dict[str, FindingRecord] = {}
    for job in await db.list_jobs():
        if job.status != ScanStatus.completed or not job.result:
            continue
        last_seen = job.finished_at or job.created_at
        for host in job.result.hosts:
            for port in host.ports:
                for cve in port.cves:
                    finding_id = _finding_id(
                        job.target, host.address, port.port, port.protocol, cve.id
                    )
                    review = reviews.get(finding_id, {})
                    record = FindingRecord(
                        finding_id=finding_id,
                        scan_id=job.id,
                        target=job.target,
                        host=host.address,
                        port=port.port,
                        protocol=port.protocol,
                        service=port.service,
                        product=port.product,
                        version=port.version,
                        last_seen=last_seen,
                        cve=cve,
                        **review,
                    )
                    current = latest.get(finding_id)
                    if current is None or record.last_seen > current.last_seen:
                        latest[finding_id] = record
    return sorted(
        latest.values(),
        key=lambda item: (
            item.status != "resolved",
            item.cve.in_kev,
            item.cve.epss or 0,
            item.cve.cvss or 0,
        ),
        reverse=True,
    )


def _state(request: Request):
    return request.app.state


async def _prepare(request: Request, body: ScanRequest) -> tuple[str, str, ScanOptions, list[str]]:
    """Validate the target and options; return (display, ip, options, argv)."""
    state = _state(request)
    settings = state.settings
    try:
        target = await resolve_and_authorise(body.target, state.allowlist)
        options = ScanOptions(
            technique=body.technique,
            timing=body.timing,
            port_preset=body.port_preset,
            custom_ports=body.custom_ports,
            service_detection=body.service_detection,
            cve_detection=body.cve_detection,
            os_detection=body.os_detection,
            skip_host_discovery=body.skip_host_discovery,
        )
        argv = build_command(
            target.ip,
            options,
            nmap_path=settings.nmap_path,
            privileged=settings.nmap_privileged,
            host_timeout_seconds=settings.scan_timeout_seconds,
        )
    except (TargetError, CommandError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return target.display, target.ip, options, argv


# --- meta ------------------------------------------------------------------------------


@router.get("/health")
async def health(request: Request) -> dict:
    s = _state(request).settings
    return {
        "status": "ok",
        "version": __version__,
        "nmap_available": s.demo_mode or nmap_available(s.nmap_path),
        "demo_mode": s.demo_mode,
    }


@router.get("/options")
async def options(request: Request) -> dict:
    """Everything the UI needs to render the scan form."""
    state = _state(request)
    privileged = state.settings.nmap_privileged
    return {
        "techniques": [
            {**asdict(t), "available": privileged or not t.requires_privileges}
            for t in TECHNIQUES.values()
        ],
        "timing_templates": [asdict(t) for t in TIMING_TEMPLATES.values()],
        "port_presets": [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in PORT_PRESETS.items()
        ],
        "privileged": privileged,
        "os_detection_available": privileged,
        "allowed_targets": state.allowlist.describe(),
        "ai_enabled": state.explainer is not None,
        "ai_provider": state.explainer.provider.name if state.explainer else None,
        "demo_mode": state.settings.demo_mode,
    }


# --- scans -----------------------------------------------------------------------------


@router.post("/scans/preview")
async def preview_scan(request: Request, body: ScanRequest) -> dict:
    """Show the exact nmap command a request would run, with every flag explained."""
    display, ip, _, argv = await _prepare(request, body)
    return {
        "target": display,
        "resolved_ip": ip,
        "argv": argv,
        "command": _format_command(argv),
        "explanation": explain_command(argv),
    }


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
async def create_scan(request: Request, body: ScanRequest) -> ScanJob:
    state = _state(request)
    if not body.authorized:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Confirm that you own this target or have permission to scan it.",
        )

    # Validate first so rejected requests don't use up the caller's quota.
    display, ip, options, argv = await _prepare(request, body)

    allowed, retry_after = state.scan_limiter.check(
        client_key(request, state.settings.trust_proxy_headers)
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many scans. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    return await state.manager.submit(display, ip, asdict(options), argv)


@router.get("/scans")
async def list_scans(request: Request, limit: int = Query(30, ge=1, le=100)) -> list[ScanSummary]:
    return await _state(request).db.list_scans(limit)


@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str) -> ScanJob:
    job = await _state(request).manager.get(scan_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return job


@router.get("/scans/{scan_id}/report.pdf")
async def download_scan_report(request: Request, scan_id: str) -> Response:
    """Download a complete PDF report for a completed assessment."""
    job = await _state(request).manager.get(scan_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    if job.status != ScanStatus.completed or job.result is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "The PDF report is available after a scan completes successfully.",
        )
    report_settings = await _state(request).db.get_workspace_settings()
    pdf = build_scan_pdf(job, report_settings)
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", job.id)[:64] or "assessment"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="najd-recon-{safe_id}-report.pdf"',
            "Cache-Control": "no-store",
        },
    )


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(request: Request, scan_id: str) -> None:
    state = _state(request)
    if state.manager.is_live(scan_id):
        job = await state.manager.get(scan_id)
        if job and job.status not in FINISHED:
            raise HTTPException(status.HTTP_409_CONFLICT, "Scan is still running")
    state.manager.forget(scan_id)
    if not await state.db.delete_scan(scan_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")


@router.get("/scans/{scan_id}/events")
async def scan_events(request: Request, scan_id: str) -> StreamingResponse:
    """Server-Sent Events stream of scan progress. Closes when the scan finishes."""
    manager = _state(request).manager
    if await manager.get(scan_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")

    async def stream():
        last_sent = None
        idle = 0.0
        while True:
            if await request.is_disconnected():
                return
            job = await manager.get(scan_id)
            if job is None:
                return
            snapshot = {
                "status": job.status.value,
                "progress": round(job.progress, 1),
                "current_task": job.current_task,
                "error": job.error,
            }
            if snapshot != last_sent:
                yield f"data: {json.dumps(snapshot)}\n\n"
                last_sent = snapshot
                idle = 0.0
            elif idle >= 15:
                yield ": keep-alive\n\n"
                idle = 0.0
            if job.status in FINISHED:
                return
            await asyncio.sleep(0.5)
            idle += 0.5

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --- shared assessment workspace ---------------------------------------------------------


@router.get("/assets")
async def list_assets(request: Request) -> list[Asset]:
    state = _state(request)
    assets = await state.db.list_assets()
    jobs = await state.db.list_jobs()
    for asset in assets:
        matching = [
            job
            for job in jobs
            if job.target.casefold() == asset.target.casefold()
            and job.status == ScanStatus.completed
        ]
        asset.scan_count = len(matching)
        asset.latest_scan_at = max(
            (job.finished_at or job.created_at for job in matching), default=None
        )
    return assets


@router.post("/assets", status_code=status.HTTP_201_CREATED)
async def create_asset(request: Request, body: AssetInput) -> Asset:
    now = datetime.now(UTC)
    data = body.model_dump()
    data["tags"] = [tag.strip() for tag in body.tags if tag.strip()]
    asset = Asset(
        id=uuid.uuid4().hex,
        **data,
        created_at=now,
        updated_at=now,
    )
    try:
        await _state(request).db.create_asset(asset)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An asset with this target already exists"
        ) from exc
    return asset


@router.put("/assets/{asset_id}")
async def update_asset(request: Request, asset_id: str, body: AssetInput) -> Asset:
    db = _state(request).db
    existing = await db.get_asset(asset_id)
    if existing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    data = body.model_dump()
    data["tags"] = [tag.strip() for tag in body.tags if tag.strip()]
    asset = Asset(
        id=asset_id,
        **data,
        created_at=existing.created_at,
        updated_at=datetime.now(UTC),
    )
    try:
        await db.update_asset(asset)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An asset with this target already exists"
        ) from exc
    return asset


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(request: Request, asset_id: str) -> None:
    if not await _state(request).db.delete_asset(asset_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")


@router.get("/findings")
async def list_findings(
    request: Request,
    query: str = Query("", max_length=200),
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|none|unknown)$"),
    finding_status: str | None = Query(
        None, alias="status", pattern="^(open|in_progress|accepted|resolved)$"
    ),
    kev_only: bool = False,
) -> list[FindingRecord]:
    records = await _finding_records(request)
    needle = query.casefold().strip()
    return [
        finding
        for finding in records
        if (
            not needle
            or needle
            in " ".join(
                (
                    finding.target,
                    finding.host,
                    finding.cve.id,
                    finding.service or "",
                    finding.product or "",
                    finding.version or "",
                    finding.cve.description or "",
                )
            ).casefold()
        )
        and (severity is None or finding.cve.severity.value == severity)
        and (finding_status is None or finding.status == finding_status)
        and (not kev_only or finding.cve.in_kev)
    ]


@router.put("/findings/{finding_id}")
async def update_finding(
    request: Request, finding_id: str, body: FindingReviewInput
) -> FindingRecord:
    findings = await _finding_records(request)
    finding = next((item for item in findings if item.finding_id == finding_id), None)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    await _state(request).db.save_finding_review(finding_id, body)
    return finding.model_copy(update=body.model_dump())


@router.get("/saved-views")
async def list_saved_views(request: Request) -> list[SavedView]:
    return await _state(request).db.list_saved_views()


@router.post("/saved-views", status_code=status.HTTP_201_CREATED)
async def create_saved_view(request: Request, body: SavedViewInput) -> SavedView:
    view = SavedView(
        id=uuid.uuid4().hex,
        name=body.name.strip(),
        filters=body.filters,
        created_at=datetime.now(UTC),
    )
    await _state(request).db.create_saved_view(view)
    return view


@router.delete("/saved-views/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_view(request: Request, view_id: str) -> None:
    if not await _state(request).db.delete_saved_view(view_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Saved view not found")


@router.get("/workspace-settings")
async def get_workspace_settings(request: Request) -> WorkspaceSettings:
    return await _state(request).db.get_workspace_settings()


@router.put("/workspace-settings")
async def update_workspace_settings(request: Request, body: WorkspaceSettings) -> WorkspaceSettings:
    await _state(request).db.save_workspace_settings(body)
    return body


@router.get("/notifications")
async def list_notifications(
    request: Request, limit: int = Query(50, ge=1, le=200)
) -> list[Notification]:
    return await _state(request).db.list_notifications(limit)


@router.post("/notifications/read-all")
async def mark_all_notifications_read(request: Request) -> dict[str, int]:
    count = await _state(request).db.mark_all_notifications_read()
    return {"updated": count}


@router.post("/notifications/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_notification_read(request: Request, notification_id: str) -> None:
    if not await _state(request).db.mark_notification_read(notification_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification not found")


# --- CVEs ------------------------------------------------------------------------------


def _check_cve_id(cve_id: str) -> str:
    cve_id = cve_id.upper()
    if not CVE_ID.match(cve_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid CVE id (e.g. CVE-2021-41773)")
    return cve_id


@router.get("/cves/{cve_id}")
async def get_cve(request: Request, cve_id: str) -> CVE:
    cve_id = _check_cve_id(cve_id)
    return await _state(request).enricher.enrich_cve(CVE(id=cve_id))


@router.post("/cves/{cve_id}/explain")
async def explain_cve(request: Request, cve_id: str, body: ExplainRequest) -> Explanation:
    state = _state(request)
    cve_id = _check_cve_id(cve_id)
    if state.explainer is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "AI explanations are off. Set GEMINI_API_KEY in .env (see README).",
        )

    allowed, retry_after = state.ai_limiter.check(
        client_key(request, state.settings.trust_proxy_headers)
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many AI requests. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    cve = await state.enricher.enrich_cve(
        CVE(
            id=cve_id,
            cvss=body.cvss,
            severity=severity_from_cvss(body.cvss),
            is_exploit=body.is_exploit,
        )
    )
    try:
        return await state.explainer.explain(cve, body.product, body.version, body.port)
    except ExplainerError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
