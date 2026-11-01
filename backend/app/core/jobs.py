"""Background scan jobs.

A scan can take seconds or many minutes, so the API returns a job id immediately and the
work happens in an asyncio task:

    queued -> running (nmap) -> enriching (NVD/KEV) -> completed | failed

A semaphore caps how many nmap processes run at once. Live state is kept in memory for the
progress stream and written to SQLite at each status change.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from importlib import resources

from app.config import Settings
from app.core.database import Database
from app.cve.enricher import CVEEnricher, count_severities
from app.models import ScanJob, ScanStatus
from app.scanner.parser import ParseError, parse_nmap_xml
from app.scanner.runner import ScanError, run_nmap

log = logging.getLogger(__name__)

DEMO_FIXTURE = "lab_apache_vulners.xml"


class ScanManager:
    def __init__(self, settings: Settings, db: Database, enricher: CVEEnricher):
        self.settings = settings
        self.db = db
        self.enricher = enricher
        self._live: dict[str, ScanJob] = {}
        self._tasks: set[asyncio.Task] = set()
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_scans)

    async def submit(
        self, target: str, resolved_ip: str, options: dict, command: list[str]
    ) -> ScanJob:
        job = ScanJob(
            id=uuid.uuid4().hex,
            target=target,
            resolved_ip=resolved_ip,
            options=options,
            command=command,
            created_at=datetime.now(UTC),
        )
        self._live[job.id] = job
        await self.db.save_scan(job)
        task = asyncio.create_task(self._run(job))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job

    async def get(self, job_id: str) -> ScanJob | None:
        return self._live.get(job_id) or await self.db.get_scan(job_id)

    def forget(self, job_id: str) -> None:
        self._live.pop(job_id, None)

    def is_live(self, job_id: str) -> bool:
        return job_id in self._live

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    # ------------------------------------------------------------------------------------

    async def _run(self, job: ScanJob) -> None:
        try:
            async with self._semaphore:
                job.status = ScanStatus.running
                job.current_task = "Starting nmap"
                await self.db.save_scan(job)

                xml = await self._execute(job)
                result = parse_nmap_xml(xml)

                if result.all_cves() and not self.settings.demo_mode:
                    job.status = ScanStatus.enriching
                    job.current_task = "Looking up CVE details (EPSS, CISA KEV, NVD)"
                    job.progress = 0.0
                    await self.db.save_scan(job)

                    async def enrich_progress(done: int, total: int) -> None:
                        job.progress = round(done / total * 100, 1)
                        job.current_task = f"Enriching CVEs ({done}/{total})"

                    await self.enricher.enrich_result(result, enrich_progress)

                job.result = result
                job.severity_counts = count_severities(result)
                job.status = ScanStatus.completed
                job.progress = 100.0
                job.current_task = None
        except (ScanError, ParseError) as exc:
            job.status = ScanStatus.failed
            job.error = str(exc)
        except asyncio.CancelledError:
            job.status = ScanStatus.failed
            job.error = "Scan cancelled (server shutting down)"
            raise
        except Exception:  # noqa: BLE001 - last-resort guard so a job never hangs
            log.exception("Scan %s crashed", job.id)
            job.status = ScanStatus.failed
            job.error = "Unexpected server error during the scan"
        finally:
            job.finished_at = datetime.now(UTC)
            await self.db.save_scan(job)
            try:
                await self.db.publish_scan_notifications(job)
            except Exception:
                log.exception("Could not publish notifications for scan %s", job.id)
            # Keep finished jobs in memory briefly so open progress streams see the end.
            asyncio.get_running_loop().call_later(60, self._live.pop, job.id, None)

    async def _execute(self, job: ScanJob) -> str:
        async def on_progress(percent: float, task: str) -> None:
            job.progress = percent
            job.current_task = task

        if self.settings.demo_mode:
            return await self._demo_scan(job, on_progress)

        result = await run_nmap(
            job.command,
            timeout=self.settings.scan_timeout_seconds,
            on_progress=on_progress,
        )
        return result.xml

    async def _demo_scan(self, job: ScanJob, on_progress) -> str:
        """Replay a recorded lab scan so a public demo never sends real packets."""
        for percent, task in [
            (10, "Connect Scan"),
            (45, "Connect Scan"),
            (60, "Service scan"),
            (85, "NSE"),
            (100, "NSE"),
        ]:
            await on_progress(float(percent), f"{task} (demo replay)")
            await asyncio.sleep(0.6)
        xml = resources.files("app.demo").joinpath(DEMO_FIXTURE).read_text()
        return xml.replace("172.28.0.10", job.resolved_ip)
