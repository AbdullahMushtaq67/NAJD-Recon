"""Target validation: decide whether a user-supplied target may be scanned.

Defences implemented here:
  * Only a single host is accepted (no CIDR ranges, no lists, no nmap options).
  * Hostnames must be syntactically valid DNS names; anything else is rejected before DNS.
  * The hostname is resolved ONCE, and every resolved address must pass the allowlist.
    The resolved IP (not the hostname) is what nmap receives, so a DNS record cannot
    change between the check and the scan (DNS rebinding / TOCTOU).
  * Some ranges are always blocked, e.g. cloud metadata endpoints (169.254.169.254),
    multicast and "this network", even when ALLOW_ANY_TARGET is enabled.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

ALWAYS_BLOCKED: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),  # "this network"
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, incl. cloud metadata
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved + broadcast
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
    ipaddress.ip_network("::/128"),  # unspecified
)

# RFC 1123 hostname: labels of letters, digits and hyphens, not starting/ending with '-'.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class TargetError(ValueError):
    """Raised when a target is malformed or not authorised for scanning."""


@dataclass(frozen=True)
class AuthorisedTarget:
    display: str  # what the user typed (normalised)
    ip: str  # the literal IP that nmap will scan


def parse_target(raw: str) -> str | IPAddress:
    """Return an IP address object, or a validated hostname string."""
    target = (raw or "").strip()
    if not target:
        raise TargetError("Enter an IP address or hostname")
    if target.startswith("-"):
        raise TargetError("Targets cannot start with '-'")  # option injection
    if "/" in target:
        raise TargetError("Scan a single host; CIDR ranges are not supported")
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        pass
    if not _HOSTNAME.match(target) or target.replace(".", "").isdigit():
        raise TargetError(f"Not a valid IP address or hostname: {target!r}")
    return target.rstrip(".").lower()


class Allowlist:
    def __init__(self, entries: list[str], allow_any: bool = False):
        self.allow_any = allow_any
        self.networks: list[IPNetwork] = []
        self.hostnames: set[str] = set()
        for entry in entries:
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self.hostnames.add(entry.lower().rstrip("."))

    def permits(self, hostname: str | None, ip: IPAddress) -> bool:
        if any(ip in net for net in ALWAYS_BLOCKED):
            return False
        if self.allow_any:
            return True
        if hostname and hostname in self.hostnames:
            return True
        return any(ip.version == net.version and ip in net for net in self.networks)

    def describe(self) -> list[str]:
        if self.allow_any:
            return ["any (ALLOW_ANY_TARGET=true)"]
        # Show single-host networks as plain addresses (127.0.0.1, not 127.0.0.1/32).
        nets = [
            str(n.network_address) if n.num_addresses == 1 else str(n) for n in self.networks
        ]
        return sorted(self.hostnames) + nets


async def _resolve(hostname: str) -> list[IPAddress]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"Could not resolve {hostname!r}") from exc
    addresses: list[IPAddress] = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in addresses:
            addresses.append(addr)
    return addresses


async def resolve_and_authorise(raw: str, allowlist: Allowlist) -> AuthorisedTarget:
    """Validate, resolve and allowlist-check a target. Returns the IP nmap should scan."""
    parsed = parse_target(raw)

    if isinstance(parsed, str):
        addresses = await _resolve(parsed)
        if not addresses:
            raise TargetError(f"{parsed!r} did not resolve to any address")
        # Every address must be allowed; otherwise a hostname could point at both an
        # allowed and a forbidden IP.
        for addr in addresses:
            if not allowlist.permits(parsed, addr):
                raise TargetError(_not_allowed_message(parsed, allowlist))
        # Prefer IPv4: it is what most lab setups and scanme.nmap.org use.
        chosen = next((a for a in addresses if a.version == 4), addresses[0])
        return AuthorisedTarget(display=parsed, ip=str(chosen))

    if not allowlist.permits(None, parsed):
        raise TargetError(_not_allowed_message(str(parsed), allowlist))
    return AuthorisedTarget(display=str(parsed), ip=str(parsed))


def _not_allowed_message(target: str, allowlist: Allowlist) -> str:
    return (
        f"{target} is not on this server's allowlist. Only scan systems you own or have "
        f"written permission to test. Allowed: {', '.join(allowlist.describe())}"
    )
