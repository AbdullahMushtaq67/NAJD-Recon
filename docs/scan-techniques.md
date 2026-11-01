# Nmap concepts used in NAJD Recon

This page explains the choices behind each option in the scan form. The flag definitions
live in [`backend/app/scanner/commands.py`](../backend/app/scanner/commands.py).

## Port states

| State | Meaning |
|---|---|
| `open` | An application is accepting connections on the port. |
| `closed` | The host answered, but nothing is listening (TCP RST). |
| `filtered` | No answer, or an ICMP "unreachable". A firewall is probably dropping probes. |
| `open\|filtered` | Common in UDP scans: no reply, which could mean open or dropped. |

With `--reason`, NAJD Recon shows *why* nmap chose each state (`syn-ack`, `conn-refused`,
`no-response`, …).

## Scan techniques

**TCP Connect (`-sT`).** Calls the OS `connect()` and completes the three-way handshake:
`SYN → SYN/ACK → ACK`. It needs no special privileges, but every connection is a full session
that the target may log.

**TCP SYN (`-sS`).** Sends a raw `SYN`. A `SYN/ACK` reply means open, so nmap answers with
`RST` instead of finishing the handshake. A `RST` reply means closed, and silence means
filtered. It's faster and quieter than a connect scan, but crafting raw packets needs the
`CAP_NET_RAW` capability. The Docker image grants that capability to the nmap binary alone
(`setcap cap_net_raw+eip`) and runs everything as a non-root user.

**UDP (`-sU`).** UDP has no handshake. An open port often doesn't reply at all, and a closed
port replies with ICMP "port unreachable", which most kernels rate-limit to about one per
second. That's why UDP scans are slow, and why NAJD Recon refuses a UDP scan of all 65,535 ports.

## Timing templates

`-T0` to `-T5` adjust probe parallelism, timeouts and delays together. `T0` and `T1` evade
intrusion detection by waiting minutes or seconds between probes. `T3` is the default.
`T4` suits reliable networks like the lab, and `T5` trades accuracy for speed.

## From banner to CVE

1. `-sV` sends probes from `nmap-service-probes` and matches the responses, for example
   `Apache httpd 2.4.49`.
2. Nmap records a **CPE** (Common Platform Enumeration) name:
   `cpe:/a:apache:http_server:2.4.49`.
3. The `vulners` NSE script sends the CPE to the Vulners database and gets back CVEs with
   CVSS scores and exploit availability.
4. NAJD Recon adds details from **NVD** (description, CVSS vector, CWE) and flags CVEs listed
   in **CISA KEV** (confirmed exploitation in the wild).

### Limits of version-based detection

- **False positives.** Linux distributions often backport security fixes without changing
  the upstream version. Debian's Apache can say `2.4.49` and still be patched.
- **False negatives.** Hidden or customised banners give `-sV` nothing to match.
- **Configuration matters.** CVE-2021-41773 is only exploitable when `/` isn't protected by
  `Require all denied`. The version tells you the risk exists, not that it can be exploited.

A version match is a lead to verify, not a confirmed vulnerability. Authenticated scanning
or checking the vendor's patch level confirms it.

## CVSS vs KEV vs EPSS

- **CVSS** measures how bad a flaw *could* be (0–10).
- **CISA KEV** lists flaws that attackers are *actually exploiting*.
- **EPSS** estimates the *probability* of exploitation in the next 30 days. NAJD Recon fetches it
  from FIRST.org, which publishes it.

NAJD Recon's default "Priority" order is KEV first, then EPSS, then CVSS, because a 7.5 that is
being exploited usually matters more than an unexploited 9.8. EPSS ≥ 10% counts as "likely
exploited": that's roughly the top few percent of all CVEs.
