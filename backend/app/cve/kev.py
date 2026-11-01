"""CISA Known Exploited Vulnerabilities (KEV) catalog.

A CVE in KEV has confirmed exploitation in the wild, which matters more for prioritising
fixes than CVSS alone. The catalog is a single JSON file, refreshed once a day and cached
on disk so restarts don't re-download it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
REFRESH_SECONDS = 24 * 3600


class KEVCatalog:
    def __init__(self, cache_file: str, enabled: bool = True):
        self.cache_file = Path(cache_file)
        self.enabled = enabled
        self._entries: dict[str, dict] = {}
        self._loaded_at = 0.0
        self._lock = asyncio.Lock()

    async def lookup(self, cve_id: str) -> dict | None:
        await self._ensure_loaded()
        return self._entries.get(cve_id)

    async def _ensure_loaded(self) -> None:
        if not self.enabled or time.time() - self._loaded_at < REFRESH_SECONDS:
            return
        async with self._lock:
            if time.time() - self._loaded_at < REFRESH_SECONDS:
                return
            data = self._read_cache()
            if data is None:
                data = await self._download()
            if data is not None:
                self._entries = {
                    v["cveID"]: {
                        "date_added": v.get("dateAdded"),
                        "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                        "required_action": v.get("requiredAction"),
                    }
                    for v in data.get("vulnerabilities", [])
                    if v.get("cveID")
                }
                log.info("Loaded %d KEV entries", len(self._entries))
            # Even on failure, wait before retrying so we don't hammer CISA.
            self._loaded_at = time.time()

    def _read_cache(self) -> dict | None:
        try:
            if time.time() - self.cache_file.stat().st_mtime < REFRESH_SECONDS:
                return json.loads(self.cache_file.read_text())
        except (OSError, json.JSONDecodeError):
            pass
        return None

    async def _download(self) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(KEV_URL)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            log.warning("Could not download CISA KEV catalog: %s", exc)
            return None
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(data))
        except OSError as exc:
            log.warning("Could not cache KEV catalog: %s", exc)
        return data
