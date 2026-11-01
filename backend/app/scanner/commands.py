"""Every Nmap command NAJD Recon can run is defined in this file.

Nothing outside this module decides which flags reach nmap. User input never becomes a
flag directly: it selects an entry from one of the allowlists below, and only validated
values (an IP address, a normalised port list) are inserted as arguments. The argv list is
executed without a shell, so shell metacharacters have no special meaning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

# --------------------------------------------------------------------------------------
# Scan techniques (how nmap probes each port)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanTechnique:
    id: str
    name: str
    flag: str
    description: str
    requires_privileges: bool


TECHNIQUES: dict[str, ScanTechnique] = {
    "connect": ScanTechnique(
        id="connect",
        name="TCP Connect",
        flag="-sT",
        description=(
            "Completes the full TCP three-way handshake using the OS socket API. "
            "Works without raw-socket privileges, but is slower and more likely to be logged."
        ),
        requires_privileges=False,
    ),
    "syn": ScanTechnique(
        id="syn",
        name="TCP SYN (stealth)",
        flag="-sS",
        description=(
            "Sends a SYN and reads the reply (SYN/ACK = open, RST = closed) without finishing "
            "the handshake. Fast and nmap's default when privileged. Needs raw sockets."
        ),
        requires_privileges=True,
    ),
    "udp": ScanTechnique(
        id="udp",
        name="UDP",
        flag="-sU",
        description=(
            "Probes UDP services such as DNS (53), SNMP (161) and NTP (123). Slow, because "
            "closed ports are only revealed by rate-limited ICMP replies. Needs raw sockets."
        ),
        requires_privileges=True,
    ),
}

# --------------------------------------------------------------------------------------
# Timing templates (-T0 .. -T5)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TimingTemplate:
    level: int
    name: str
    description: str


TIMING_TEMPLATES: dict[int, TimingTemplate] = {
    0: TimingTemplate(0, "Paranoid", "IDS evasion: waits 5 minutes between probes. Very slow."),
    1: TimingTemplate(1, "Sneaky", "IDS evasion: waits 15 seconds between probes. Slow."),
    2: TimingTemplate(2, "Polite", "Slows down to use less bandwidth and target resources."),
    3: TimingTemplate(3, "Normal", "Nmap's default balance of speed and reliability."),
    4: TimingTemplate(4, "Aggressive", "Assumes a fast, reliable network. Good for labs."),
    5: TimingTemplate(5, "Insane", "Sacrifices accuracy for speed; may miss open ports."),
}

# --------------------------------------------------------------------------------------
# Port selection
# --------------------------------------------------------------------------------------

PortPreset = Literal["top100", "top1000", "all", "custom"]

PORT_PRESETS: dict[str, dict] = {
    "top100": {
        "name": "Top 100 ports",
        "args": ["--top-ports", "100"],
        "description": "The 100 most common ports, from nmap's frequency database.",
    },
    "top1000": {
        "name": "Top 1000 ports",
        "args": ["--top-ports", "1000"],
        "description": "Nmap's default port set.",
    },
    "all": {
        "name": "All 65,535 ports",
        "args": ["-p-"],
        "description": "Every TCP port. Thorough but slow.",
    },
    "custom": {
        "name": "Custom",
        "args": None,  # built from the validated user list
        "description": "Your own list, e.g. 22,80,443,8000-8100",
    },
}

MAX_CUSTOM_PORT_TOKENS = 50
_PORT_TOKEN = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


class CommandError(ValueError):
    """Raised when scan options cannot be turned into a safe nmap command."""


def normalise_ports(spec: str) -> str:
    """Validate a custom port list and return it in canonical form.

    Accepts comma-separated ports and ranges ("22, 80,443,8000-8100").
    Rejects anything else, including nmap syntax like "T:" / "U:" prefixes or names.
    """
    tokens = [t.strip() for t in spec.split(",") if t.strip()]
    if not tokens:
        raise CommandError("Enter at least one port, e.g. 22,80,443")
    if len(tokens) > MAX_CUSTOM_PORT_TOKENS:
        raise CommandError(f"Use at most {MAX_CUSTOM_PORT_TOKENS} ports or ranges")

    cleaned: list[str] = []
    for token in tokens:
        match = _PORT_TOKEN.match(token)
        if not match:
            raise CommandError(f"Invalid port or range: {token!r}")
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else start
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise CommandError(f"Ports must be between 1 and 65535: {token!r}")
        if start > end:
            raise CommandError(f"Range start is greater than end: {token!r}")
        cleaned.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(cleaned)


# --------------------------------------------------------------------------------------
# Building the command
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanOptions:
    technique: str = "connect"
    timing: int = 4
    port_preset: str = "top100"
    custom_ports: str | None = None
    service_detection: bool = True
    cve_detection: bool = True
    os_detection: bool = False
    skip_host_discovery: bool = True


def build_command(
    target_ip: str,
    options: ScanOptions,
    *,
    nmap_path: str = "nmap",
    privileged: bool = False,
    host_timeout_seconds: int = 900,
) -> list[str]:
    """Translate validated scan options into an nmap argv list.

    `target_ip` must already have passed `validator.resolve_and_authorise`, which returns a
    literal IP address. Hostnames are never passed to nmap, which closes the gap between
    the allowlist check and nmap's own DNS lookup (DNS rebinding).
    """
    technique = TECHNIQUES.get(options.technique)
    if technique is None:
        raise CommandError(f"Unknown scan type: {options.technique!r}")
    if technique.requires_privileges and not privileged:
        raise CommandError(
            f"{technique.name} scans need raw-socket privileges. "
            "Use TCP Connect, or run the backend with NMAP_PRIVILEGED=true (see README)."
        )
    if options.os_detection and not privileged:
        raise CommandError("OS detection needs raw-socket privileges (NMAP_PRIVILEGED=true).")

    if options.timing not in TIMING_TEMPLATES:
        raise CommandError("Timing must be between T0 and T5")

    preset = PORT_PRESETS.get(options.port_preset)
    if preset is None:
        raise CommandError(f"Unknown port preset: {options.port_preset!r}")
    if options.port_preset == "custom":
        port_args = ["-p", normalise_ports(options.custom_ports or "")]
    else:
        port_args = list(preset["args"])

    if technique.id == "udp" and options.port_preset == "all":
        raise CommandError("A UDP scan of all 65,535 ports can take many hours. Pick fewer ports.")

    argv: list[str] = [nmap_path, technique.flag, f"-T{options.timing}", *port_args]

    # CVE detection relies on product/version data, so it implies -sV.
    if options.service_detection or options.cve_detection:
        argv.append("-sV")
    if options.cve_detection:
        # vulners 2.x also fingerprints web servers by requesting ~940 paths per HTTP port.
        # That is intrusive and slow, so it is off; only -sV's CPEs are looked up.
        argv += ["--script", "vulners", "--script-args", "vulners.catalog=none"]
    if options.os_detection:
        argv.append("-O")
    if options.skip_host_discovery:
        argv.append("-Pn")

    argv += [
        "--privileged" if privileged else "--unprivileged",
        "--reason",
        "--host-timeout",
        f"{host_timeout_seconds}s",
        "--stats-every",
        "2s",
        "-oX",
        "-",
        target_ip,
    ]
    return argv


# --------------------------------------------------------------------------------------
# Human-readable explanations (shown in the UI's command preview)
# --------------------------------------------------------------------------------------

FLAG_HELP: dict[str, str] = {
    "-sT": TECHNIQUES["connect"].description,
    "-sS": TECHNIQUES["syn"].description,
    "-sU": TECHNIQUES["udp"].description,
    "--top-ports": "Scan the N most frequently open ports from nmap-services.",
    "-p-": "Scan all ports from 1 to 65535.",
    "-p": "Scan only the listed ports and ranges.",
    "-sV": "Service/version detection: probe open ports to identify the software and version.",
    "--script": "Run an NSE script. 'vulners' maps detected versions (CPEs) to known CVEs.",
    "--script-args": (
        "Arguments for NSE scripts. 'vulners.catalog=none' turns off the script's web-path "
        "sweep (about 940 requests per HTTP port), so only versions found by -sV are looked up."
    ),
    "-O": "OS fingerprinting from TCP/IP stack behaviour.",
    "-Pn": "Skip host discovery and treat the host as up (many hosts block ping).",
    "--privileged": "Tell nmap it has raw-socket capability even though it isn't root.",
    "--unprivileged": "Tell nmap to avoid raw sockets and use the OS socket API only.",
    "--reason": "Record why each port got its state (e.g. syn-ack, conn-refused).",
    "--host-timeout": "Give up on the host after this long.",
    "--stats-every": "Emit progress updates at this interval (used for the progress bar).",
    "-oX": "Write machine-readable XML ('-' = stdout), which the backend parses.",
}


def explain_command(argv: list[str]) -> list[dict[str, str]]:
    """Pair each flag (and its value, if any) with an explanation for the UI."""
    explained: list[dict[str, str]] = []
    i = 1  # skip the binary
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("-T") and len(arg) == 3:
            level = int(arg[2])
            t = TIMING_TEMPLATES[level]
            explained.append({"flag": arg, "help": f"Timing template {t.name}: {t.description}"})
            i += 1
            continue
        if arg in FLAG_HELP:
            takes_value = arg in {"--top-ports", "-p", "--script", "--script-args",
                                  "--host-timeout", "--stats-every", "-oX"}
            if takes_value and i + 1 < len(argv):
                explained.append({"flag": f"{arg} {argv[i + 1]}", "help": FLAG_HELP[arg]})
                i += 2
                continue
            explained.append({"flag": arg, "help": FLAG_HELP[arg]})
        elif not arg.startswith("-"):
            explained.append({"flag": arg, "help": "Target (resolved IP address)."})
        i += 1
    return explained
