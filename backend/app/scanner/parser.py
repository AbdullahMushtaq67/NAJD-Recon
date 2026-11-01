"""Parse nmap's XML output (-oX) into NAJD Recon's data model.

XML is parsed with `defusedxml`, which rejects entity-expansion ("billion laughs") and
external-entity (XXE) payloads. nmap output is trusted, but service banners and NSE
script output inside it come from the scanned host, which is not.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from xml.etree.ElementTree import Element  # nosec B405

from defusedxml import ElementTree as SafeET

from app.models import (
    CVE,
    Host,
    NetworkAddress,
    NmapScript,
    OSMatch,
    Port,
    PortStateCount,
    ScanResult,
    TraceHop,
    severity_from_cvss,
)

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


class ParseError(ValueError):
    pass


def parse_nmap_xml(xml_text: str) -> ScanResult:
    try:
        root = SafeET.fromstring(xml_text)
    except SafeET.ParseError as exc:
        raise ParseError(f"Could not parse nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ParseError("Not an nmap XML document")

    started = root.get("start")
    finished = root.find("runstats/finished")
    host_stats = root.find("runstats/hosts")

    return ScanResult(
        nmap_version=root.get("version"),
        command=root.get("args"),
        started_at=datetime.fromtimestamp(int(started), tz=UTC) if started else None,
        elapsed_seconds=_float(finished.get("elapsed")) if finished is not None else None,
        summary=finished.get("summary") if finished is not None else None,
        hosts_up=_int(host_stats.get("up")) if host_stats is not None else None,
        hosts_down=_int(host_stats.get("down")) if host_stats is not None else None,
        hosts_total=_int(host_stats.get("total")) if host_stats is not None else None,
        hosts=[_parse_host(h) for h in root.findall("host")],
    )


def _parse_host(host_el: Element) -> Host:
    address = ""
    for addr in host_el.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            address = addr.get("addr", "")
            break

    status_el = host_el.find("status")
    uptime_el = host_el.find("uptime")
    distance_el = host_el.find("distance")
    return Host(
        address=address,
        hostnames=[h.get("name", "") for h in host_el.findall("hostnames/hostname")],
        status=status_el.get("state", "unknown") if status_el is not None else "unknown",
        status_reason=_attr(status_el, "reason"),
        status_reason_ttl=_int(_attr(status_el, "reason_ttl")),
        addresses=[
            NetworkAddress(
                address=addr.get("addr", ""),
                kind=addr.get("addrtype", "unknown"),
                vendor=addr.get("vendor"),
            )
            for addr in host_el.findall("address")
            if addr.get("addr")
        ],
        os_matches=[
            OSMatch(name=m.get("name", ""), accuracy=int(m.get("accuracy", "0")))
            for m in host_el.findall("os/osmatch")[:3]
        ],
        uptime_seconds=_int(_attr(uptime_el, "seconds")),
        uptime_last_boot=_attr(uptime_el, "lastboot"),
        distance_hops=_int(_attr(distance_el, "value")),
        extra_port_states=[
            PortStateCount(
                state=state.get("state", "unknown"),
                count=int(state.get("count", "0")),
                reasons=[
                    f"{reason.get('reason', 'unknown')}: {reason.get('count', '0')}"
                    for reason in state.findall("extrareasons")
                ],
            )
            for state in host_el.findall("ports/extraports")
        ],
        scripts=_parse_scripts(host_el.findall("hostscript/script")),
        trace_hops=[
            TraceHop(
                ttl=int(hop.get("ttl", "0")),
                address=_attr(hop, "ipaddr"),
                hostname=_attr(hop, "host"),
                rtt=_attr(hop, "rtt"),
            )
            for hop in host_el.findall("trace/hop")
        ],
        ports=[_parse_port(p) for p in host_el.findall("ports/port")],
    )


def _parse_port(port_el: Element) -> Port:
    state_el = port_el.find("state")
    service_el = port_el.find("service")

    cves: list[CVE] = []
    for script in port_el.findall("script"):
        if script.get("id") == "vulners":
            cves.extend(parse_vulners_script(script))

    return Port(
        port=int(port_el.get("portid", "0")),
        protocol=port_el.get("protocol", "tcp"),
        state=state_el.get("state", "unknown") if state_el is not None else "unknown",
        reason=state_el.get("reason") if state_el is not None else None,
        reason_ttl=_int(_attr(state_el, "reason_ttl")),
        service=_attr(service_el, "name"),
        product=_attr(service_el, "product"),
        version=_attr(service_el, "version"),
        extrainfo=_attr(service_el, "extrainfo"),
        service_tunnel=_attr(service_el, "tunnel"),
        service_method=_attr(service_el, "method"),
        service_confidence=_int(_attr(service_el, "conf")),
        cpes=[c.text for c in port_el.findall("service/cpe") if c.text],
        scripts=_parse_scripts(port_el.findall("script")),
        cves=_dedupe_sorted(cves),
    )


def _parse_scripts(elements: list[Element]) -> list[NmapScript]:
    return [
        NmapScript(id=script.get("id", "unknown"), output=script.get("output", ""))
        for script in elements
    ]


def parse_vulners_script(script_el: Element) -> list[CVE]:
    """Read the structured output of the `vulners` NSE script.

    Layout:
        <script id="vulners">
          <table key="cpe:/a:apache:http_server:2.4.49">
            <table>
              <elem key="id">CVE-2021-42013</elem>
              <elem key="cvss">9.8</elem>
              <elem key="type">cve</elem>
              <elem key="is_exploit">false</elem>
            </table>
            ...
    vulners also lists exploit-db, packetstorm, etc. entries; only CVEs are kept.
    The keys above are stable across vulners.nse 1.x and 2.x. With an API key, 2.x adds
    exploit_known, kev, epss and epss_percentile, which are read when present.
    """
    cves: list[CVE] = []
    for cpe_table in script_el.findall("table"):
        for entry in cpe_table.findall("table"):
            fields = {e.get("key"): (e.text or "").strip() for e in entry.findall("elem")}
            vuln_id = fields.get("id", "").upper()
            if fields.get("type", "").lower() != "cve" or not _CVE_ID.match(vuln_id):
                continue
            score = _float(fields.get("cvss"))
            cves.append(
                CVE(
                    id=vuln_id,
                    cvss=score,
                    severity=severity_from_cvss(score),
                    # 1.x marks CVEs with is_exploit. 2.x sets is_exploit only on exploit
                    # documents and marks a CVE that has one with exploit_known instead.
                    is_exploit=_true(fields.get("is_exploit"))
                    or _true(fields.get("exploit_known")),
                    in_kev=_true(fields.get("kev")),  # 2.x, with an API key
                    epss=_probability(fields.get("epss")),
                    epss_percentile=_probability(fields.get("epss_percentile")),
                    url=f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
                )
            )
    return cves


def _dedupe_sorted(cves: list[CVE]) -> list[CVE]:
    unique: dict[str, CVE] = {}
    for cve in cves:
        existing = unique.get(cve.id)
        if existing is None or (cve.cvss or 0) > (existing.cvss or 0):
            unique[cve.id] = cve
    return sorted(unique.values(), key=lambda c: (c.cvss or 0), reverse=True)


def _attr(el: Element | None, name: str) -> str | None:
    if el is None:
        return None
    value = el.get(name)
    return value or None


def _true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def _probability(value: str | None) -> float | None:
    number = _float(value)
    return number if number is not None and 0.0 <= number <= 1.0 else None


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except ValueError:
        return None


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
