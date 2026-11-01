from app.cve.enricher import CVEEnricher, count_severities
from app.cve.nvd import normalise
from app.models import Severity
from app.scanner.parser import parse_nmap_xml

# Trimmed NVD CVE API 2.0 record (shape from https://nvd.nist.gov/developers/vulnerabilities)
NVD_RECORD = {
    "id": "CVE-2021-41773",
    "published": "2021-10-05T09:15:07.593",
    "descriptions": [
        {"lang": "en", "value": "A flaw was found in a change made to path normalization..."},
        {"lang": "es", "value": "Se encontró un fallo..."},
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                },
            }
        ],
        "cvssMetricV2": [
            {"cvssData": {"version": "2.0", "baseScore": 4.3}, "baseSeverity": "MEDIUM"}
        ],
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
    "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}],
}


class FakeNVD:
    async def get(self, cve_id):
        return normalise({**NVD_RECORD, "id": cve_id}) if cve_id == "CVE-2021-41773" else None


class FakeKEV:
    async def lookup(self, cve_id):
        if cve_id == "CVE-2021-41773":
            return {"date_added": "2021-11-03", "ransomware": True, "required_action": "Patch"}
        return None


def test_normalise_prefers_cvss_v31():
    data = normalise(NVD_RECORD)
    assert data["cvss"] == 9.8 and data["cvss_version"] == "3.1"
    assert data["description"].startswith("A flaw")
    assert data["cwe"] == ["CWE-22"]
    assert data["published"] == "2021-10-05"


async def test_enrich_result_merges_nvd_and_kev(lab_xml):
    result = parse_nmap_xml(lab_xml)
    await CVEEnricher(FakeNVD(), FakeKEV()).enrich_result(result)
    cves = result.hosts[0].ports[0].cves

    top = cves[0]  # KEV entries are sorted first
    assert top.id == "CVE-2021-41773"
    assert top.in_kev and top.kev_ransomware
    assert top.cvss == 9.8 and top.source == "nvd" and top.severity == Severity.critical
    assert all(c.url for c in cves)

    counts = count_severities(result)
    assert counts.critical + counts.high == 15


def test_priority_orders_kev_then_epss_then_cvss():
    from app.cve.enricher import priority
    from app.models import CVE

    cves = [
        CVE(id="CVE-2000-0001", cvss=9.8),
        CVE(id="CVE-2000-0002", cvss=7.5, epss=0.9),
        CVE(id="CVE-2000-0003", cvss=5.0, in_kev=True),
        CVE(id="CVE-2000-0004", cvss=9.8, epss=0.01),
    ]
    ordered = [c.id[-1] for c in sorted(cves, key=priority, reverse=True)]
    assert ordered == ["3", "2", "4", "1"]


def test_epss_parse_and_batching():
    from app.cve.epss import MAX_PARAM_CHARS, batches, parse_response

    payload = {"data": [
        {"cve": "CVE-2021-40438", "epss": "0.972240000", "percentile": "1.000000000"},
        {"cve": "CVE-2019-16759", "epss": "not-a-number", "percentile": "0.9"},
    ]}
    scores = parse_response(payload)
    assert set(scores) == {"CVE-2021-40438"}
    assert scores["CVE-2021-40438"].epss == 0.97224
    assert scores["CVE-2021-40438"].percentile == 1.0

    ids = [f"CVE-2024-{n:05d}" for n in range(250)]
    chunks = batches(ids)
    assert sum(len(c) for c in chunks) == 250
    assert all(len(",".join(c)) <= MAX_PARAM_CHARS and len(c) <= 100 for c in chunks)


async def test_epss_client_caches_and_skips_failures(monkeypatch):
    from app.cve.epss import EPSSClient, EPSSScore

    client = EPSSClient()
    calls = []

    async def fake_fetch(batch):
        calls.append(list(batch))
        return {"CVE-2021-41773": EPSSScore(0.94, 0.999)}

    monkeypatch.setattr(client, "_fetch", fake_fetch)
    first = await client.lookup(["CVE-2021-41773", "CVE-2000-0001"])
    second = await client.lookup(["CVE-2021-41773", "CVE-2000-0001"])
    assert first == second == {"CVE-2021-41773": EPSSScore(0.94, 0.999)}
    assert len(calls) == 1  # both the hit and the miss were cached


async def test_enrich_result_adds_epss_and_ranks_by_it(lab_xml):
    from app.cve.epss import EPSSScore

    class FakeEPSS:
        async def lookup(self, ids):
            return {"CVE-2021-44224": EPSSScore(0.5, 0.98)}

    result = parse_nmap_xml(lab_xml)
    await CVEEnricher(None, None, epss=FakeEPSS()).enrich_result(result)
    cves = result.hosts[0].ports[0].cves
    assert cves[0].id == "CVE-2021-44224"  # an 8.2 with EPSS 50% outranks unscored 9.8s
    assert cves[0].epss == 0.5 and cves[0].epss_percentile == 0.98
