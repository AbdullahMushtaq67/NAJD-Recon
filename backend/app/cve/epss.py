"""EPSS scores from FIRST.org: the probability a CVE is exploited in the next 30 days.

API docs: https://api.first.org/epss/  (free, no key)
Scores are recalculated daily, so lookups are cached in memory for 24 hours, including
"no score" answers, so a CVE without an EPSS entry isn't requested again and again.
"""

from __future__ import annotations

import logging
import time
from typing import NamedTuple

import httpx

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_SECONDS = 24 * 3600
MAX_PARAM_CHARS = 2000  # the API's limit on the comma-separated cve parameter
MAX_PER_REQUEST = 100


class EPSSScore(NamedTuple):
    epss: float  # probability of exploitation in the next 30 days, 0-1
    percentile: float | None  # share of all scored CVEs with a lower score, 0-1


class EPSSClient:
    def __init__(self, enabled: bool = True, timeout: float = 15.0):
        self.enabled = enabled
        self.timeout = timeout
        self._cache: dict[str, tuple[float, EPSSScore | None]] = {}

    async def lookup(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Return scores for the CVEs that have one. Unknown or failed lookups are omitted."""
        if not self.enabled or not cve_ids:
            return {}

        now = time.time()
        wanted = list(dict.fromkeys(cve_ids))  # de-duplicate, keep order
        missing = [c for c in wanted if not self._fresh(c, now)]

        for batch in batches(missing):
            fetched = await self._fetch(batch)
            if fetched is None:
                continue  # network error: don't cache, try again next time
            for cve_id in batch:
                self._cache[cve_id] = (now, fetched.get(cve_id))

        results: dict[str, EPSSScore] = {}
        for cve_id in wanted:
            entry = self._cache.get(cve_id)
            if entry and entry[1] is not None:
                results[cve_id] = entry[1]
        return results

    def _fresh(self, cve_id: str, now: float) -> bool:
        entry = self._cache.get(cve_id)
        return entry is not None and now - entry[0] < CACHE_SECONDS

    async def _fetch(self, batch: list[str]) -> dict[str, EPSSScore] | None:
        params = {"cve": ",".join(batch), "limit": str(len(batch))}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(EPSS_URL, params=params)
                resp.raise_for_status()
                payload = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("EPSS lookup failed: %s", exc)
            return None
        return parse_response(payload)


def parse_response(payload: dict) -> dict[str, EPSSScore]:
    """FIRST returns epss and percentile as decimal strings, e.g. "0.972240000"."""
    scores: dict[str, EPSSScore] = {}
    for item in payload.get("data") or []:
        try:
            cve_id = str(item["cve"]).upper()
            epss = float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
        try:
            percentile = float(item.get("percentile"))
        except (TypeError, ValueError):
            percentile = None
        if 0.0 <= epss <= 1.0:
            scores[cve_id] = EPSSScore(epss, percentile)
    return scores


def batches(cve_ids: list[str]) -> list[list[str]]:
    """Split ids so each request stays under the API's parameter length and page size."""
    out: list[list[str]] = []
    current: list[str] = []
    length = 0
    for cve_id in cve_ids:
        extra = len(cve_id) + (1 if current else 0)
        if current and (length + extra > MAX_PARAM_CHARS or len(current) >= MAX_PER_REQUEST):
            out.append(current)
            current, length, extra = [], 0, len(cve_id)
        current.append(cve_id)
        length += extra
    if current:
        out.append(current)
    return out
