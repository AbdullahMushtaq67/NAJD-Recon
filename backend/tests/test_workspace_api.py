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


def test_shared_workspace_api_flow(client):
    asset_response = client.post(
        "/api/assets",
        json={
            "name": "Apache lab",
            "target": "172.28.0.10",
            "owner": "Security",
            "environment": "test",
            "criticality": "high",
            "tags": [" lab ", "", "web"],
            "notes": "Authorized practice target",
        },
    )
    assert asset_response.status_code == 201
    asset = asset_response.json()
    assert asset["tags"] == ["lab", "web"]
    assert client.post(
        "/api/assets",
        json={"name": "Duplicate", "target": "172.28.0.10"},
    ).status_code == 409

    scan_response = client.post("/api/scans", json=SCAN)
    assert scan_response.status_code == 202
    job = wait_for(client, scan_response.json()["id"])
    assert job["status"] == "completed"

    listed_asset = client.get("/api/assets").json()[0]
    assert listed_asset["scan_count"] == 1
    assert listed_asset["latest_scan_at"]

    findings = client.get("/api/findings").json()
    assert findings
    assert findings[0]["finding_id"]
    finding = findings[0]
    updated = client.put(
        f"/api/findings/{finding['finding_id']}",
        json={
            "status": "in_progress",
            "assignee": "analyst",
            "due_date": "2026-07-01",
            "note": "Verify vendor backport status",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"
    assert updated.json()["note"] == "Verify vendor backport status"
    assert client.get("/api/findings", params={"status": "in_progress"}).json()[0][
        "finding_id"
    ] == finding["finding_id"]

    saved = client.post(
        "/api/saved-views",
        json={"name": "Urgent", "filters": {"severity": "critical", "kev": True}},
    )
    assert saved.status_code == 201
    assert client.get("/api/saved-views").json()[0]["filters"]["kev"] is True
    assert client.delete(f"/api/saved-views/{saved.json()['id']}").status_code == 204
    assert client.delete("/api/saved-views/missing").status_code == 404

    settings = client.get("/api/workspace-settings").json()
    settings["workspace_name"] = "Security Operations"
    settings["report_contact"] = "security@example.test"
    assert client.put("/api/workspace-settings", json=settings).json()[
        "workspace_name"
    ] == "Security Operations"
    assert client.get("/api/workspace-settings").json()["report_contact"] == (
        "security@example.test"
    )

    notifications = client.get("/api/notifications").json()
    assert notifications
    notification_id = notifications[0]["id"]
    assert client.post(f"/api/notifications/{notification_id}/read").status_code == 204
    assert client.post("/api/notifications/missing/read").status_code == 404
    assert client.post("/api/notifications/read-all").json()["updated"] >= 1
    assert all(item["read_at"] for item in client.get("/api/notifications").json())

    assert client.delete(f"/api/assets/{asset['id']}").status_code == 204
    assert client.delete(f"/api/assets/{asset['id']}").status_code == 404
