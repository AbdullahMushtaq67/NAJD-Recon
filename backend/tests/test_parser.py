import pytest
from defusedxml import EntitiesForbidden

from app.models import Severity
from app.scanner.parser import ParseError, parse_nmap_xml


def test_parses_lab_scan(lab_xml):
    result = parse_nmap_xml(lab_xml)
    assert result.nmap_version == "7.94SVN"
    assert result.elapsed_seconds == pytest.approx(9.12)
    host = result.hosts[0]
    assert host.address == "172.28.0.10"
    assert host.hostnames == ["lab-apache"]
    assert host.status == "up"

    port = host.ports[0]
    assert (port.port, port.protocol, port.state) == (80, "tcp", "open")
    assert port.product == "Apache httpd" and port.version == "2.4.49"
    assert port.cpes == ["cpe:/a:apache:http_server:2.4.49"]


def test_vulners_keeps_only_cves_sorted_by_score(lab_xml):
    cves = parse_nmap_xml(lab_xml).hosts[0].ports[0].cves
    ids = [c.id for c in cves]
    assert all(i.startswith("CVE-") for i in ids)  # PACKETSTORM / EDB entries dropped
    assert len(ids) == len(set(ids)) == 15
    scores = [c.cvss for c in cves]
    assert scores == sorted(scores, reverse=True)

    traversal = next(c for c in cves if c.id == "CVE-2021-41773")
    assert traversal.cvss == 7.5
    assert traversal.severity == Severity.high
    assert traversal.is_exploit is True


def test_rejects_non_nmap_xml():
    with pytest.raises(ParseError):
        parse_nmap_xml("<html></html>")
    with pytest.raises(ParseError):
        parse_nmap_xml("not xml")


def test_rejects_entity_expansion_attack():
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><nmaprun>&lol2;</nmaprun>'
    )
    with pytest.raises(EntitiesForbidden):
        parse_nmap_xml(bomb)


def test_handles_host_with_no_ports():
    xml = (
        '<?xml version="1.0"?><nmaprun version="7.94"><host><status state="up"/>'
        '<address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'
    )
    result = parse_nmap_xml(xml)
    assert result.hosts[0].ports == []


def test_preserves_nmap_host_port_and_script_observations():
    xml = """<?xml version="1.0"?>
    <nmaprun version="7.99">
      <host>
        <status state="up" reason="syn-ack" reason_ttl="128"/>
        <address addr="192.0.2.10" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example Vendor"/>
        <hostnames><hostname name="example.local" type="PTR"/></hostnames>
        <uptime seconds="3600" lastboot="Sat Nov  1 15:00:00 2026"/>
        <distance value="2"/>
        <ports>
          <extraports state="closed" count="5">
            <extrareasons reason="conn-refused" count="5"/>
          </extraports>
          <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack" reason_ttl="128"/>
            <service name="https" tunnel="ssl" method="probed" conf="10">
              <cpe>cpe:/a:example:server</cpe>
            </service>
            <script id="ssl-cert" output="certificate summary"/>
          </port>
        </ports>
        <hostscript><script id="smb-os-discovery" output="host summary"/></hostscript>
        <trace><hop ttl="1" ipaddr="192.0.2.1" host="router.local" rtt="1.25"/></trace>
      </host>
      <runstats>
        <hosts up="1" down="0" total="1"/>
        <finished elapsed="1.5" summary="one host up"/>
      </runstats>
    </nmaprun>"""
    result = parse_nmap_xml(xml)
    host = result.hosts[0]
    port = host.ports[0]

    assert (result.hosts_up, result.hosts_down, result.hosts_total) == (1, 0, 1)
    assert host.addresses[1].vendor == "Example Vendor"
    assert (host.status_reason, host.status_reason_ttl) == ("syn-ack", 128)
    assert (host.uptime_seconds, host.distance_hops) == (3600, 2)
    assert host.extra_port_states[0].reasons == ["conn-refused: 5"]
    assert host.scripts[0].output == "host summary"
    assert host.trace_hops[0].hostname == "router.local"
    assert (port.service_tunnel, port.service_method, port.service_confidence) == (
        "ssl",
        "probed",
        10,
    )
    assert port.scripts[0].output == "certificate summary"


VULNERS_2X = """<?xml version="1.0"?>
<nmaprun version="7.95"><host><status state="up"/><address addr="172.28.0.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.49">
<cpe>cpe:/a:apache:http_server:2.4.49</cpe></service>
<script id="vulners" output="...">
<elem key="schema">2.0</elem>
<elem key="mode">keyed</elem>
<table key="cpe:/a:apache:http_server:2.4.49">
  <table>
    <elem key="id">CVE-2021-41773</elem><elem key="type">cve</elem>
    <elem key="severity">HIGH</elem><elem key="cvss">7.5</elem>
    <elem key="is_exploit">false</elem><elem key="exploit_known">true</elem>
    <elem key="kev">true</elem><elem key="epss">0.94412</elem>
    <elem key="epss_percentile">0.99981</elem>
  </table>
  <table>
    <elem key="id">CVE-2022-22720</elem><elem key="type">cve</elem>
    <elem key="cvss">9.8</elem><elem key="is_exploit">false</elem>
  </table>
  <table>
    <elem key="id">AE004D91-C8AA-5DE3-8E14-481192A124DD</elem>
    <elem key="type">githubexploit</elem><elem key="cvss">10.0</elem>
    <elem key="is_exploit">true</elem><elem key="kev">true</elem>
  </table>
</table>
</script></port></ports></host></nmaprun>"""


def test_parses_vulners_2x_with_api_key_fields():
    cves = parse_nmap_xml(VULNERS_2X).hosts[0].ports[0].cves
    assert [c.id for c in cves] == ["CVE-2022-22720", "CVE-2021-41773"]  # exploit doc dropped

    traversal = cves[1]
    assert traversal.is_exploit is True  # from exploit_known
    assert traversal.in_kev is True
    assert traversal.epss == pytest.approx(0.94412)
    assert traversal.epss_percentile == pytest.approx(0.99981)

    plain = cves[0]
    assert plain.is_exploit is False and plain.epss is None
