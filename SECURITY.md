# Security Policy

## Responsible use

NAJD Recon is for scanning systems you own or have **written permission** to test. Unauthorised
port scanning may break the law where you live and your hosting provider's terms of service.
The default allowlist only permits the bundled lab, localhost and `scanme.nmap.org`, which
Nmap's authors provide for testing. Please don't scan it more than a few times a day.

**Never deploy a public instance with `ALLOW_ANY_TARGET=true`.** For a public demo, use
`DEMO_MODE=true`. It replays a recorded scan and sends no packets.

## Reporting a vulnerability

If you find a security issue in NAJD Recon itself (for example a way around the target
allowlist, or command/option injection), please **don't open a public issue**. Report it
privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Include:

- a description of the issue and its impact
- steps to reproduce
- the commit or version you tested

You should get a reply within a few days.

## Built-in protections

See the **Security design** section of the [README](README.md#security-design).
