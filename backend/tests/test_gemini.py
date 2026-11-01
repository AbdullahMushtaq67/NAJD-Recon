import httpx
import pytest

from app.ai import gemini
from app.ai.gemini import GeminiClient, GeminiError, build_client
from app.config import Settings

ANSWER = {"candidates": [{"content": {"parts": [
    {"text": "thinking...", "thought": True},
    {"text": '{"a": '},
    {"text": "1}"},
]}}]}


@pytest.fixture
def no_sleep(monkeypatch):
    waits = []

    async def fake_sleep(seconds):
        waits.append(seconds)

    monkeypatch.setattr(gemini.asyncio, "sleep", fake_sleep)
    return waits


def scripted(client, monkeypatch, *responses):
    """Make the client's HTTP layer return (or raise) the given items in order."""
    queue = list(responses)
    sent = []

    async def fake_send(url, body):
        sent.append((url.split("/models/")[1].split(":")[0], body))
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(client, "_send", fake_send)
    return sent


def test_build_client_defaults_and_overrides():
    client = build_client(Settings(_env_file=None, gemini_api_key="k"))
    assert client.models == ["gemini-3.6-flash", "gemini-3.5-flash-lite"]
    assert client.timeout == 30
    custom = build_client(Settings(
        _env_file=None, gemini_api_key="k", gemini_model="gemini-3.5-flash",
        gemini_fallback_models="gemini-3.5-flash-lite, gemini-3.1-flash-lite",
        gemini_timeout_seconds=45,
    ))
    assert custom.models == ["gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"]
    assert custom.timeout == 45
    assert build_client(Settings(_env_file=None)) is None


async def test_request_shape_and_answer(monkeypatch):
    client = GeminiClient("secret", "gemini-3.6-flash")
    sent = scripted(client, monkeypatch, httpx.Response(200, json=ANSWER))
    assert await client.complete("sys", "user") == ('{"a": 1}', "gemini-3.6-flash")

    model, body = sent[0]
    assert model == "gemini-3.6-flash"
    config = body["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["thinkingConfig"] == {"thinkingLevel": "low"}


async def test_key_is_sent_in_header_not_url(monkeypatch):
    captured = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json, headers):
            captured.update(url=url, headers=headers)
            return httpx.Response(200, json=ANSWER)

    monkeypatch.setattr(gemini.httpx, "AsyncClient", FakeAsyncClient)
    await GeminiClient("secret", "m", timeout=20).complete("s", "u")
    assert captured["headers"] == {"x-goog-api-key": "secret"}
    assert "secret" not in captured["url"] and captured["timeout"] == 20


async def test_falls_back_to_next_model_on_timeout(monkeypatch, no_sleep):
    client = GeminiClient("k", "slow-model", fallbacks=["fast-model"])
    sent = scripted(client, monkeypatch, httpx.ReadTimeout(""), httpx.Response(200, json=ANSWER))
    text, used = await client.complete("s", "u")
    assert (text, used) == ('{"a": 1}', "fast-model")
    assert [m for m, _ in sent] == ["slow-model", "fast-model"]


async def test_falls_back_on_overload_after_one_retry(monkeypatch, no_sleep):
    client = GeminiClient("k", "busy", fallbacks=["lite"])
    sent = scripted(client, monkeypatch, httpx.Response(503), httpx.Response(503),
                    httpx.Response(200, json=ANSWER))
    assert (await client.complete("s", "u"))[1] == "lite"
    assert [m for m, _ in sent] == ["busy", "busy", "lite"]
    assert no_sleep == [1.0]


async def test_falls_back_when_model_retired(monkeypatch, no_sleep):
    client = GeminiClient("k", "old", fallbacks=["new"])
    scripted(client, monkeypatch, httpx.Response(404, text="no longer available"),
             httpx.Response(200, json=ANSWER))
    assert (await client.complete("s", "u"))[1] == "new"


async def test_all_models_failing_gives_clear_message(monkeypatch, no_sleep):
    client = GeminiClient("k", "a", fallbacks=["b"])
    scripted(client, monkeypatch, httpx.ReadTimeout(""), httpx.Response(503), httpx.Response(503))
    with pytest.raises(GeminiError, match="No Gemini model could answer") as info:
        await client.complete("s", "u")
    assert "a: no answer within 30s" in str(info.value) and "b: overloaded" in str(info.value)


async def test_bad_key_fails_fast_without_fallback(monkeypatch, no_sleep):
    client = GeminiClient("k", "a", fallbacks=["b"])
    sent = scripted(client, monkeypatch, httpx.Response(400, text="API key not valid"))
    with pytest.raises(GeminiError, match="API key not valid"):
        await client.complete("s", "u")
    assert len(sent) == 1


async def test_network_error_fails_fast(monkeypatch, no_sleep):
    client = GeminiClient("k", "a", fallbacks=["b"])
    sent = scripted(client, monkeypatch, httpx.ConnectError(""))
    with pytest.raises(GeminiError, match="ConnectError"):
        await client.complete("s", "u")
    assert len(sent) == 1


async def test_thinking_setting_rejected_is_resent_without_it(monkeypatch):
    client = GeminiClient("k", "older", fallbacks=[])
    sent = scripted(
        client, monkeypatch,
        httpx.Response(400, text="Unknown name 'thinkingLevel' in thinking_config"),
        httpx.Response(200, json=ANSWER),
    )
    assert (await client.complete("s", "u"))[0] == '{"a": 1}'
    assert "thinkingConfig" in sent[0][1]["generationConfig"]
    assert "thinkingConfig" not in sent[1][1]["generationConfig"]


async def test_blocked_prompt(monkeypatch):
    client = GeminiClient("k", "m", fallbacks=[])
    blocked = httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}})
    scripted(client, monkeypatch, blocked)
    with pytest.raises(GeminiError, match="SAFETY"):
        await client.complete("s", "u")
