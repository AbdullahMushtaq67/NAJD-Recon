"""Client for the NIST National Vulnerability Database (NVD) CVE API 2.0.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limits (rolling 30-second window): 5 requests without an API key, 50 with one.
Responses are cached in SQLite, so each CVE is fetched at most once a week.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from app.core.database import Database

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_SECONDS = 7 * 24 * 3600


class NVDClient:
    def __init__(self, db: Database, api_key: str | None = None, timeout: float = 15.0):
        self.db = db
        self.api_key = api_key
        self.timeout = timeout
        # Space requests evenly to stay inside the published limits.
        self._min_interval = 0.7 if api_key else 6.5
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def get(self, cve_id: str) -> dict | None:
        """Return normalised NVD data for a CVE, or None if unavailable."""
        cached = await self.db.get_cve(cve_id, CACHE_SECONDS)
        if cached is not None:
            return cached

        raw = await self._fetch(cve_id)
        if raw is None:
            return None
        data = normalise(raw)
        if data:
            await self.db.put_cve(cve_id, data)
        return data

    async def _fetch(self, cve_id: str) -> dict | None:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        async with self._lock:
            wait = self._min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
            except httpx.HTTPError as exc:
                log.warning("NVD request for %s failed: %s", cve_id, exc)
                return None
        if resp.status_code != 200:
            log.warning("NVD returned %s for %s", resp.status_code, cve_id)
            return None
        vulns = resp.json().get("vulnerabilities") or []
        return vulns[0].get("cve") if vulns else None


def normalise(cve: dict) -> dict:
    """Reduce an NVD CVE record to the fields NAJD Recon displays."""
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None
    )

    score = severity = vector = version = None
    metrics = cve.get("metrics", {})
    # Prefer CVSS v3.1 (most widely populated), then v4.0, v3.0 and finally v2.
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        vector = data.get("vectorString")
        version = data.get("version")
        break

    cwes = sorted({
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })

    return {
        "id": cve.get("id"),
        "description": description,
        "cvss": score,
        "nvd_severity": severity,
        "cvss_vector": vector,
        "cvss_version": version,
        "published": (cve.get("published") or "")[:10] or None,
        "cwe": cwes,
        "references": [r["url"] for r in cve.get("references", [])[:6] if r.get("url")],
    }
