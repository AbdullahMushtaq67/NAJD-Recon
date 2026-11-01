import time

from reportlab.pdfgen.canvas import Canvas


def _wait_for_scan(client, scan_id, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/scans/{scan_id}").json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.3)
    raise AssertionError("scan did not finish")


def test_pdf_report_requires_existing_completed_scan(client, monkeypatch):
    cover_text = []
    original_draw_string = Canvas.drawString

    def record_draw_string(canvas, x, y, text, *args, **kwargs):
        cover_text.append(str(text))
        return original_draw_string(canvas, x, y, text, *args, **kwargs)

    monkeypatch.setattr(Canvas, "drawString", record_draw_string)

    missing = client.get("/api/scans/not-a-scan/report.pdf")
    assert missing.status_code == 404

    created = client.post(
        "/api/scans",
        json={"target": "172.28.0.10", "authorized": True},
    )
    assert created.status_code == 202
    scan_id = created.json()["id"]
    job = _wait_for_scan(client, scan_id)
    assert job["status"] == "completed", job["error"]

    updated_settings = client.put(
        "/api/workspace-settings",
        json={
            "report_subtitle": "Internal security review",
            "report_contact": "Security Assessment Team",
            "report_footer": "Internal distribution only",
        },
    )
    assert updated_settings.status_code == 200

    response = client.get(f"/api/scans/{scan_id}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"].endswith(f'najd-recon-{scan_id}-report.pdf"')
    assert response.headers["cache-control"] == "no-store"
    assert response.content.startswith(b"%PDF-")
    assert b"/Subtype /Image" in response.content
    assert b"/BaseFont /Times-Roman" in response.content
    assert b"/BaseFont /Times-Bold" in response.content
    assert len(response.content) > 5000
    assert "Security Assessment" in cover_text
    assert "Report" in cover_text
    assert not any("<br" in text for text in cover_text)
    assert "A measured record of observed network exposure." not in cover_text
