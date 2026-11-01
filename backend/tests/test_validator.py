import pytest

from app.scanner.validator import Allowlist, TargetError, parse_target, resolve_and_authorise

ALLOW = Allowlist(["127.0.0.1", "172.28.0.0/24", "localhost"])


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "-oN /etc/passwd",  # option injection
        "--script=evil",
        "127.0.0.1; rm -rf /",  # shell injection
        "127.0.0.1 && id",
        "$(whoami).example.com",
        "`id`",
        "10.0.0.0/8",  # ranges not allowed
        "a" * 300,
        "exa mple.com",
        "999.1.1.1",
        "-example.com",
    ],
)
def test_malformed_targets_rejected(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


@pytest.mark.parametrize("raw", ["127.0.0.1", "::1", "scanme.nmap.org", "Lab-Apache"])
def test_well_formed_targets_parse(raw):
    parse_target(raw)


async def test_allowlisted_ip():
    target = await resolve_and_authorise("172.28.0.10", ALLOW)
    assert target.ip == "172.28.0.10"


async def test_ip_outside_allowlist_rejected():
    with pytest.raises(TargetError, match="allowlist"):
        await resolve_and_authorise("8.8.8.8", ALLOW)


async def test_hostname_is_resolved_to_ip():
    target = await resolve_and_authorise("localhost", ALLOW)
    assert target.display == "localhost"
    assert target.ip in ("127.0.0.1", "::1")


async def test_metadata_endpoint_always_blocked_even_with_allow_any():
    open_list = Allowlist([], allow_any=True)
    with pytest.raises(TargetError):
        await resolve_and_authorise("169.254.169.254", open_list)
    assert (await resolve_and_authorise("8.8.8.8", open_list)).ip == "8.8.8.8"


async def test_hostname_resolving_outside_allowlist_rejected(monkeypatch):
    import ipaddress

    from app.scanner import validator

    async def fake_resolve(_):
        # e.g. an attacker's DNS record pointing at an internal service
        return [ipaddress.ip_address("172.28.0.5"), ipaddress.ip_address("10.1.2.3")]

    monkeypatch.setattr(validator, "_resolve", fake_resolve)
    with pytest.raises(TargetError):
        await resolve_and_authorise("rebind.example.com", Allowlist(["172.28.0.0/24"]))
