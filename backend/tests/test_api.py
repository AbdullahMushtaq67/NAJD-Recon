import time

SCAN = {"target": "172.28.0.10", "authorized": True}


def wait_for(client, scan_id, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/scans/{scan_id}").json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.3)
    raise AssertionError("scan did not finish")


def test_health_and_options(client):
    assert client.get("/api/health").json()["status"] == "ok"
    opts = client.get("/api/options").json()
    assert {t["id"] for t in opts["techniques"]} == {"connect", "syn", "udp"}
    assert opts["ai_enabled"] is False
    syn = next(t for t in opts["techniques"] if t["id"] == "syn")
    assert syn["available"] is False  # not privileged in tests


def test_preview_returns_explained_command(client):
    body = client.post("/api/scans/preview", json=SCAN).json()
    assert body["argv"][-1] == "172.28.0.10"
    executable = body["argv"][0]
    quoted_executable = f'"{executable}"' if " " in executable else executable
    assert body["command"].startswith(f"{quoted_executable} -sT -T4")
    assert any(e["flag"] == "-sV" for e in body["explanation"])


def test_scan_requires_authorisation(client):
    r = client.post("/api/scans", json={**SCAN, "authorized": False})
    assert r.status_code == 400


def test_scan_rejects_disallowed_and_malicious_targets(client):
    for target in ["8.8.8.8", "127.0.0.1; id", "-oN x", "169.254.169.254"]:
        r = client.post("/api/scans", json={**SCAN, "target": target})
        assert r.status_code == 400, target


def test_full_demo_scan_flow(client):
    r = client.post("/api/scans", json=SCAN)
    assert r.status_code == 202
    scan_id = r.json()["id"]

    job = wait_for(client, scan_id)
    assert job["status"] == "completed", job["error"]
    port = job["result"]["hosts"][0]["ports"][0]
    assert port["product"] == "Apache httpd"
    assert len(port["cves"]) == 15
    assert job["severity_counts"]["critical"] >= 1

    history = client.get("/api/scans").json()
    assert history[0]["id"] == scan_id and history[0]["cve_count"] == 15

    # The SSE stream ends with the final state.
    with client.stream("GET", f"/api/scans/{scan_id}/events") as stream:
        events = [line for line in stream.iter_lines() if line.startswith("data:")]
    assert '"completed"' in events[-1]

    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_demo_scan_skips_network_enrichment(client, monkeypatch):
    async def unexpected_enrichment(*_args, **_kwargs):
        raise AssertionError("demo replay should not make external enrichment requests")

    monkeypatch.setattr(
        client.app.state.manager.enricher,
        "enrich_result",
        unexpected_enrichment,
    )
    response = client.post("/api/scans", json=SCAN)
    assert response.status_code == 202
    job = wait_for(client, response.json()["id"])
    assert job["status"] == "completed", job["error"]
    assert len(job["result"]["hosts"][0]["ports"][0]["cves"]) == 15


def test_rate_limit(client):
    codes = [client.post("/api/scans", json=SCAN).status_code for _ in range(4)]
    assert codes[:3] == [202, 202, 202] and codes[3] == 429


def test_explain_without_ai_configured(client):
    r = client.post("/api/cves/CVE-2021-41773/explain", json={})
    assert r.status_code == 503
    assert client.post("/api/cves/not-a-cve/explain", json={}).status_code == 400
