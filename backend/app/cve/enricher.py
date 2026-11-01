"""Combine vulners results with EPSS (FIRST), the CISA KEV catalog and NVD details."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.cve.epss import EPSSClient
from app.cve.kev import KEVCatalog
from app.cve.nvd import NVDClient
from app.models import CVE, ScanResult, SeverityCounts, severity_from_cvss

ProgressCallback = Callable[[int, int], Awaitable[None]]


class CVEEnricher:
    def __init__(
        self,
        nvd: NVDClient | None,
        kev: KEVCatalog | None,
        max_enriched: int = 30,
        epss: EPSSClient | None = None,
    ):
        self.nvd = nvd
        self.kev = kev
        self.epss = epss
        self.max_enriched = max_enriched

    async def enrich_cve(self, cve: CVE, *, use_nvd: bool = True) -> CVE:
        """Enrich a single CVE (used by the CVE detail and explain endpoints)."""
        await self._apply_epss([cve])
        await self._apply_kev(cve)
        if use_nvd:
            await self._apply_nvd(cve)
        return cve

    async def enrich_result(
        self, result: ScanResult, on_progress: ProgressCallback | None = None
    ) -> None:
        """Enrich every CVE in a scan, in place.

        EPSS (one batched request) and KEV (a local catalog) are cheap, so every CVE gets
        them. NVD is rate-limited, so only the highest-priority CVEs are looked up there,
        which is why priority is computed after EPSS and KEV are known.
        """
        cves = result.all_cves()
        await self._apply_epss(cves)
        for cve in cves:
            await self._apply_kev(cve)

        ranked = sorted(cves, key=priority, reverse=True)
        nvd_ids = {c.id for c in ranked[: self.max_enriched]}
        for i, cve in enumerate(cves, start=1):
            if cve.id in nvd_ids:
                await self._apply_nvd(cve)
            if on_progress:
                await on_progress(i, len(cves))

        for host in result.hosts:
            for port in host.ports:
                port.cves.sort(key=priority, reverse=True)

    # ------------------------------------------------------------------------------------

    async def _apply_epss(self, cves: list[CVE]) -> None:
        # vulners.nse 2.x may already supply EPSS; only ask FIRST for the rest.
        missing = [c for c in cves if c.epss is None]
        if not self.epss or not missing:
            return
        scores = await self.epss.lookup([c.id for c in missing])
        for cve in missing:
            score = scores.get(cve.id)
            if score:
                cve.epss, cve.epss_percentile = score.epss, score.percentile

    async def _apply_kev(self, cve: CVE) -> None:
        cve.url = cve.url or f"https://nvd.nist.gov/vuln/detail/{cve.id}"
        if not self.kev:
            return
        kev = await self.kev.lookup(cve.id)
        if kev:
            cve.in_kev = True
            cve.kev_date_added = kev["date_added"]
            cve.kev_ransomware = kev["ransomware"]

    async def _apply_nvd(self, cve: CVE) -> None:
        if not self.nvd:
            return
        data = await self.nvd.get(cve.id)
        if not data:
            return
        cve.description = data["description"]
        cve.cvss_vector = data["cvss_vector"]
        cve.cvss_version = data["cvss_version"]
        cve.published = data["published"]
        cve.cwe = data["cwe"]
        cve.references = data["references"]
        if data["cvss"] is not None:
            cve.cvss = data["cvss"]
            cve.source = "nvd"
        cve.severity = severity_from_cvss(cve.cvss)


def priority(cve: CVE) -> tuple[bool, float, float]:
    """Risk-based order: confirmed exploitation (KEV) first, then the likelihood of
    exploitation (EPSS), then severity (CVSS). Without EPSS data this is KEV, then CVSS."""
    return (cve.in_kev, cve.epss if cve.epss is not None else -1.0, cve.cvss or 0.0)


def count_severities(result: ScanResult) -> SeverityCounts:
    counts = SeverityCounts()
    for cve in result.all_cves():
        key = cve.severity.value
        if key in ("critical", "high", "medium", "low"):
            setattr(counts, key, getattr(counts, key) + 1)
        else:
            counts.unknown += 1
    return counts
