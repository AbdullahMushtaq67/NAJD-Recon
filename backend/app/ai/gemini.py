"""Google Gemini client for CVE explanations (native generateContent REST API).

Get a key from Google AI Studio: https://aistudio.google.com/apikey

Reliability:
  * Model fallback: if the main model (GEMINI_MODEL) is overloaded, slow or unavailable, the
    request moves to the next model in GEMINI_FALLBACK_MODELS. Measured on a free-tier key:
    healthy answers take 2-4 s, while an overloaded model can hang for minutes.
  * Short per-model timeout (GEMINI_TIMEOUT_SECONDS, default 30 s) so a stuck model doesn't
    block the fallback.
  * One retry with backoff on the same model for temporary errors (429 / 5xx).
  * Low "thinking" level: a CVE summary doesn't need deep reasoning, and thinking time is the
    main cause of slow answers. If a model rejects the setting, it's resent without it.
  * Errors that would hit every model the same way (bad key, network down) fail immediately.
"""

from __future__ import annotations

import asyncio

import httpx

from app.config import Settings

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-3.6-flash"
DEFAULT_FALLBACKS = ("gemini-3.5-flash-lite",)
THINKING_LEVEL = "low"  # accepted by every current Gemini model

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
ATTEMPTS_PER_MODEL = 2  # one retry, then move on to the next model
MAX_RETRY_WAIT = 5.0  # seconds; caps a server's Retry-After


class GeminiError(RuntimeError):
    """A failure that no other model would fix (bad key, bad request, network down)."""


class ModelUnavailable(GeminiError):
    """This model can't answer right now (overloaded, slow, rate-limited, retired): try the next."""


class GeminiClient:
    name = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        fallbacks: tuple[str, ...] | list[str] = DEFAULT_FALLBACKS,
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.model = model  # the configured main model (also used as the cache key)
        self.models = [model] + [m for m in fallbacks if m and m != model]
        self.timeout = timeout

    async def complete(self, system: str, user: str) -> tuple[str, str]:
        """Return (answer text, model that answered), trying fallback models in order."""
        problems: list[str] = []
        for model in self.models:
            try:
                return await self._complete_with(model, system, user), model
            except ModelUnavailable as exc:
                problems.append(f"{model}: {exc}")
        raise GeminiError("No Gemini model could answer right now. " + " | ".join(problems))

    # ------------------------------------------------------------------------------------

    async def _complete_with(self, model: str, system: str, user: str) -> str:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                # JSON mode: the model returns a JSON document instead of prose.
                "responseMimeType": "application/json",
                "thinkingConfig": {"thinkingLevel": THINKING_LEVEL},
            },
        }
        resp = await self._post_with_retries(model, body)
        if resp.status_code == 400 and "thinking" in resp.text.lower():
            # This model doesn't accept the thinking setting: resend with its default.
            fallback = {**body, "generationConfig": {"responseMimeType": "application/json"}}
            resp = await self._post_with_retries(model, fallback)

        data = self._check(resp)
        candidates = data.get("candidates") or []
        if not candidates:
            reason = (data.get("promptFeedback") or {}).get("blockReason", "no candidates")
            raise GeminiError(f"gemini returned no answer ({reason})")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        # Skip any "thought" parts; only the answer text is wanted.
        return "".join(p.get("text", "") for p in parts if not p.get("thought"))

    async def _post_with_retries(self, model: str, body: dict) -> httpx.Response:
        url = f"{BASE_URL}/models/{model}:generateContent"
        for attempt in range(1, ATTEMPTS_PER_MODEL + 1):
            try:
                resp = await self._send(url, body)
            except httpx.TimeoutException as exc:
                raise ModelUnavailable(f"no answer within {self.timeout:.0f}s") from exc
            except httpx.HTTPError as exc:
                # Network-level failure: every model would fail the same way.
                raise GeminiError(
                    f"gemini request failed: {type(exc).__name__}: {exc or 'no details'}"
                ) from exc
            if resp.status_code not in RETRYABLE_STATUS or attempt == ATTEMPTS_PER_MODEL:
                return resp
            await asyncio.sleep(retry_delay(resp, attempt))
        return resp  # pragma: no cover - loop always returns

    async def _send(self, url: str, body: dict) -> httpx.Response:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # The key goes in a header, not a ?key= query parameter, so it never appears in
            # URLs or logs.
            return await client.post(url, json=body, headers={"x-goog-api-key": self.api_key})

    @staticmethod
    def _check(resp: httpx.Response) -> dict:
        code = resp.status_code
        if code == 503:
            raise ModelUnavailable("overloaded (HTTP 503)")
        if code == 429:
            raise ModelUnavailable("rate limit or quota reached (HTTP 429)")
        if code == 404:
            raise ModelUnavailable("model not available to this key (HTTP 404)")
        if code >= 500:
            raise ModelUnavailable(f"server error (HTTP {code})")
        if code >= 400:
            raise GeminiError(f"gemini returned HTTP {code}: {resp.text[:300]}")
        return resp.json()


def retry_delay(resp: httpx.Response, attempt: int) -> float:
    """Honour a numeric Retry-After header, else back off exponentially: 1s, 2s, 4s..."""
    try:
        wait = float(resp.headers.get("retry-after", ""))
    except ValueError:
        wait = 2.0 ** (attempt - 1)
    return max(0.0, min(wait, MAX_RETRY_WAIT))


def build_client(settings: Settings) -> GeminiClient | None:
    """AI explanations are on when GEMINI_API_KEY is set."""
    if not settings.gemini_api_key:
        return None
    fallbacks = [m.strip() for m in settings.gemini_fallback_models.split(",") if m.strip()]
    return GeminiClient(
        settings.gemini_api_key,
        settings.gemini_model or DEFAULT_MODEL,
        fallbacks=fallbacks,
        timeout=settings.gemini_timeout_seconds,
    )
