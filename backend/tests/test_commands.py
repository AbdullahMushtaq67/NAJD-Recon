import pytest

from app.scanner.commands import (
    CommandError,
    ScanOptions,
    build_command,
    explain_command,
    normalise_ports,
)


def test_default_command_is_safe_and_complete():
    argv = build_command("127.0.0.1", ScanOptions())
    assert argv[0] == "nmap"
    assert argv[-1] == "127.0.0.1"
    assert argv[argv.index("-oX"): argv.index("-oX") + 2] == ["-oX", "-"]
    assert "-sT" in argv and "-T4" in argv and "-sV" in argv
    assert "--unprivileged" in argv
    assert argv[argv.index("--script") + 1] == "vulners"
    assert argv[argv.index("--script-args") + 1] == "vulners.catalog=none"


def test_cve_detection_implies_version_detection():
    argv = build_command("127.0.0.1", ScanOptions(service_detection=False, cve_detection=True))
    assert "-sV" in argv


def test_no_detection_flags_when_disabled():
    argv = build_command("127.0.0.1", ScanOptions(service_detection=False, cve_detection=False))
    assert "-sV" not in argv and "--script" not in argv


@pytest.mark.parametrize("technique", ["syn", "udp"])
def test_raw_socket_scans_require_privileges(technique):
    with pytest.raises(CommandError, match="privileges"):
        build_command("127.0.0.1", ScanOptions(technique=technique))
    argv = build_command("127.0.0.1", ScanOptions(technique=technique), privileged=True)
    assert "--privileged" in argv


def test_os_detection_requires_privileges():
    with pytest.raises(CommandError):
        build_command("127.0.0.1", ScanOptions(os_detection=True))


def test_unknown_technique_and_timing_rejected():
    with pytest.raises(CommandError):
        build_command("127.0.0.1", ScanOptions(technique="-sS --script=exploit"))
    with pytest.raises(CommandError):
        build_command("127.0.0.1", ScanOptions(timing=9))


def test_udp_all_ports_rejected():
    with pytest.raises(CommandError, match="hours"):
        build_command("127.0.0.1", ScanOptions(technique="udp", port_preset="all"),
                      privileged=True)


@pytest.mark.parametrize(
    "spec, expected",
    [("22", "22"), (" 22, 80 ,443 ", "22,80,443"), ("8000-8100", "8000-8100"), ("5-5", "5")],
)
def test_normalise_ports_valid(spec, expected):
    assert normalise_ports(spec) == expected


@pytest.mark.parametrize(
    "spec",
    ["", "0", "65536", "80-22", "abc", "T:80", "80;rm -rf /", "22 --script x", "1-2-3",
     ",".join(str(p) for p in range(1, 60))],
)
def test_normalise_ports_invalid(spec):
    with pytest.raises(CommandError):
        normalise_ports(spec)


def test_custom_ports_in_command():
    argv = build_command("127.0.0.1", ScanOptions(port_preset="custom", custom_ports="22,80"))
    assert argv[argv.index("-p") + 1] == "22,80"


def test_explain_command_covers_every_flag():
    argv = build_command("127.0.0.1", ScanOptions())
    flags = [e["flag"] for e in explain_command(argv)]
    assert "-T4" in flags and "-sV" in flags and "--script vulners" in flags
    assert "127.0.0.1" in flags
