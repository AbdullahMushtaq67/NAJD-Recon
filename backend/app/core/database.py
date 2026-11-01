"""SQLite persistence: scan history plus caches for NVD data and AI explanations."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from app.models import (
    Asset,
    FindingReviewInput,
    Notification,
    SavedView,
    ScanJob,
    ScanStatus,
    ScanSummary,
    WorkspaceSettings,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);

CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id      TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    fetched_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_cache (
    cve_id      TEXT NOT NULL,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (cve_id, provider, model)
);

CREATE TABLE IF NOT EXISTS assets (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL UNIQUE,
    data        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_reviews (
    finding_id  TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_views (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    data        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    read_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications (created_at DESC);
"""


class Database:
    def __init__(self, path: str):
        self.path = path

    async def init(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(SCHEMA)
            await db.commit()

    # --- scans ---------------------------------------------------------------------------

    async def save_scan(self, job: ScanJob) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO scans (id, target, status, created_at, data) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET status = excluded.status, data = excluded.data",
                (job.id, job.target, job.status.value, job.created_at.isoformat(),
                 job.model_dump_json()),
            )
            await db.commit()

    async def get_scan(self, scan_id: str) -> ScanJob | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT data FROM scans WHERE id = ?", (scan_id,))
            row = await cursor.fetchone()
        return ScanJob.model_validate_json(row[0]) if row else None

    async def list_scans(self, limit: int = 50) -> list[ScanSummary]:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
        summaries = []
        for (data,) in rows:
            job = ScanJob.model_validate_json(data)
            ports = [p for h in job.result.hosts for p in h.ports] if job.result else []
            summaries.append(
                ScanSummary(
                    id=job.id,
                    target=job.target,
                    status=job.status,
                    created_at=job.created_at,
                    open_ports=sum(1 for p in ports if p.state == "open"),
                    cve_count=sum(len(p.cves) for p in ports),
                    severity_counts=job.severity_counts,
                )
            )
        return summaries

    async def fail_unfinished(self) -> int:
        """Mark scans left running by a previous process (crash/restart) as failed."""
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM scans WHERE status IN ('queued', 'running', 'enriching')"
            )
            rows = await cursor.fetchall()
        for (data,) in rows:
            job = ScanJob.model_validate_json(data)
            job.status = ScanStatus.failed
            job.error = "Interrupted by a server restart"
            await self.save_scan(job)
        return len(rows)

    async def delete_scan(self, scan_id: str) -> bool:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            await db.commit()
            return cursor.rowcount > 0

    async def list_jobs(self) -> list[ScanJob]:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT data FROM scans ORDER BY created_at DESC")
            rows = await cursor.fetchall()
        return [ScanJob.model_validate_json(row[0]) for row in rows]

    # --- workspace assets ----------------------------------------------------------------

    async def list_assets(self) -> list[Asset]:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT data FROM assets ORDER BY target COLLATE NOCASE")
            rows = await cursor.fetchall()
        return [Asset.model_validate_json(row[0]) for row in rows]

    async def get_asset(self, asset_id: str) -> Asset | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT data FROM assets WHERE id = ?", (asset_id,))
            row = await cursor.fetchone()
        return Asset.model_validate_json(row[0]) if row else None

    async def create_asset(self, asset: Asset) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO assets (id, target, data) VALUES (?, ?, ?)",
                (asset.id, asset.target, asset.model_dump_json()),
            )
            await db.commit()

    async def update_asset(self, asset: Asset) -> bool:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "UPDATE assets SET target = ?, data = ? WHERE id = ?",
                (asset.target, asset.model_dump_json(), asset.id),
            )
            await db.commit()
        return cursor.rowcount > 0

    async def delete_asset(self, asset_id: str) -> bool:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
            await db.commit()
        return cursor.rowcount > 0

    # --- finding workflow -----------------------------------------------------------------

    async def get_finding_review(self, finding_id: str) -> dict | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM finding_reviews WHERE finding_id = ?", (finding_id,)
            )
            row = await cursor.fetchone()
        return json.loads(row[0]) if row else None

    async def save_finding_review(
        self, finding_id: str, review: FindingReviewInput
    ) -> None:
        data = review.model_dump()
        now = datetime.now(UTC).isoformat()
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO finding_reviews (finding_id, data, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(finding_id) DO UPDATE SET data = excluded.data, "
                "updated_at = excluded.updated_at",
                (finding_id, json.dumps(data), now),
            )
            await db.commit()

    async def list_finding_reviews(self) -> dict[str, dict]:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT finding_id, data FROM finding_reviews")
            rows = await cursor.fetchall()
        return {row[0]: json.loads(row[1]) for row in rows}

    # --- saved finding views ---------------------------------------------------------------

    async def list_saved_views(self) -> list[SavedView]:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT data FROM saved_views ORDER BY created_at DESC")
            rows = await cursor.fetchall()
        return [SavedView.model_validate_json(row[0]) for row in rows]

    async def create_saved_view(self, view: SavedView) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO saved_views (id, name, data, created_at) VALUES (?, ?, ?, ?)",
                (view.id, view.name, view.model_dump_json(), view.created_at.isoformat()),
            )
            await db.commit()

    async def delete_saved_view(self, view_id: str) -> bool:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("DELETE FROM saved_views WHERE id = ?", (view_id,))
            await db.commit()
        return cursor.rowcount > 0

    # --- shared workspace settings ---------------------------------------------------------

    async def get_workspace_settings(self) -> WorkspaceSettings:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT data FROM workspace_settings WHERE id = 1")
            row = await cursor.fetchone()
        return WorkspaceSettings.model_validate_json(row[0]) if row else WorkspaceSettings()

    async def save_workspace_settings(self, settings: WorkspaceSettings) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO workspace_settings (id, data) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                (settings.model_dump_json(),),
            )
            await db.commit()

    # --- notifications ---------------------------------------------------------------------

    async def publish_scan_notifications(self, job: ScanJob) -> None:
        settings = await self.get_workspace_settings()
        now = datetime.now(UTC)
        if job.status == ScanStatus.failed:
            if settings.notify_scan_failure:
                notification = Notification(
                    id=f"failed-{job.id}",
                    kind="scan_failed",
                    title="Assessment failed",
                    message=f"{job.target}: {job.error or 'The assessment did not complete.'}",
                    severity="high",
                    scan_id=job.id,
                    target=job.target,
                    created_at=now,
                )
                async with aiosqlite.connect(self.path) as db:
                    await db.execute(
                        "INSERT OR IGNORE INTO notifications (id, kind, data, created_at, read_at) "
                        "VALUES (?, ?, ?, ?, NULL)",
                        (notification.id, notification.kind, notification.model_dump_json(),
                         notification.created_at.isoformat()),
                    )
                    await db.commit()
            return
        if job.status != ScanStatus.completed or job.result is None:
            return
        cves = job.result.all_cves()
        notifications: list[Notification] = []

        if settings.notify_new_scan:
            notifications.append(Notification(
                id=f"scan-{job.id}",
                kind="scan_completed",
                title="Assessment completed",
                message=f"{job.target}: {len(job.result.hosts)} host(s), "
                f"{sum(p.state == 'open' for h in job.result.hosts for p in h.ports)} "
                "open port(s).",
                severity="info",
                scan_id=job.id,
                target=job.target,
                created_at=now,
            ))
        if settings.notify_critical and job.severity_counts:
            urgent = job.severity_counts.critical + job.severity_counts.high
            if urgent:
                notifications.append(Notification(
                    id=f"risk-{job.id}",
                    kind="high_risk",
                    title="High-priority findings detected",
                    message=f"{job.target}: {job.severity_counts.critical} critical and "
                    f"{job.severity_counts.high} high-severity finding(s).",
                    severity="critical" if job.severity_counts.critical else "high",
                    scan_id=job.id,
                    target=job.target,
                    created_at=now,
                ))
        kev_count = sum(cve.in_kev for cve in cves)
        if settings.notify_critical and kev_count:
            notifications.append(Notification(
                id=f"kev-{job.id}",
                kind="kev_findings",
                title="Known-exploited vulnerability detected",
                message=f"{job.target}: {kev_count} finding(s) appear in CISA KEV.",
                severity="critical",
                scan_id=job.id,
                target=job.target,
                created_at=now,
            ))

        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM scans WHERE target = ? AND id != ? AND status = 'completed' "
                "ORDER BY created_at DESC LIMIT 1",
                (job.target, job.id),
            )
            row = await cursor.fetchone()
            if row:
                previous = ScanJob.model_validate_json(row[0])
                prior_ids = (
                    {cve.id for cve in previous.result.all_cves()}
                    if previous.result
                    else set()
                )
                added = sorted({cve.id for cve in cves} - prior_ids)
                if added:
                    notifications.append(Notification(
                        id=f"new-cves-{job.id}",
                        kind="new_findings",
                        title="New vulnerability findings",
                        message=f"{job.target}: {len(added)} new CVE(s): {', '.join(added[:5])}"
                        + ("…" if len(added) > 5 else ""),
                        severity="high",
                        scan_id=job.id,
                        target=job.target,
                        created_at=now,
                    ))
            for notification in notifications:
                await db.execute(
                    "INSERT OR IGNORE INTO notifications (id, kind, data, created_at, read_at) "
                    "VALUES (?, ?, ?, ?, NULL)",
                    (notification.id, notification.kind, notification.model_dump_json(),
                     notification.created_at.isoformat()),
                )
            if notifications:
                await db.commit()

    async def list_notifications(self, limit: int = 50) -> list[Notification]:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data, read_at FROM notifications ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            rows = await cursor.fetchall()
        notifications = []
        for data, read_at in rows:
            notification = Notification.model_validate_json(data)
            if read_at:
                notification.read_at = datetime.fromisoformat(read_at)
            notifications.append(notification)
        return notifications

    async def mark_notification_read(self, notification_id: str) -> bool:
        now = datetime.now(UTC).isoformat()
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "UPDATE notifications SET read_at = COALESCE(read_at, ?) WHERE id = ?",
                (now, notification_id),
            )
            await db.commit()
        return cursor.rowcount > 0

    async def mark_all_notifications_read(self) -> int:
        now = datetime.now(UTC).isoformat()
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "UPDATE notifications SET read_at = ? WHERE read_at IS NULL", (now,)
            )
            await db.commit()
        return cursor.rowcount

    # --- NVD cache -----------------------------------------------------------------------

    async def get_cve(self, cve_id: str, max_age_seconds: int) -> dict | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data, fetched_at FROM cve_cache WHERE cve_id = ?", (cve_id,)
            )
            row = await cursor.fetchone()
        if row and time.time() - row[1] < max_age_seconds:
            return json.loads(row[0])
        return None

    async def put_cve(self, cve_id: str, data: dict) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO cve_cache (cve_id, data, fetched_at) VALUES (?, ?, ?)",
                (cve_id, json.dumps(data), time.time()),
            )
            await db.commit()

    # --- AI cache ------------------------------------------------------------------------

    async def get_explanation(self, cve_id: str, provider: str, model: str) -> dict | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM ai_cache WHERE cve_id = ? AND provider = ? AND model = ?",
                (cve_id, provider, model),
            )
            row = await cursor.fetchone()
        return json.loads(row[0]) if row else None

    async def put_explanation(self, cve_id: str, provider: str, model: str, data: dict) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO ai_cache (cve_id, provider, model, data, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (cve_id, provider, model, json.dumps(data), time.time()),
            )
            await db.commit()
