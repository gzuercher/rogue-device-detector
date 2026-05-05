# Security Policy

## Reporting a Vulnerability

If you discover a security issue in this project, please report it privately
rather than opening a public GitHub issue.

- **Preferred:** Use GitHub's [Security Advisory](https://github.com/gzuercher/rogue-device-detector/security/advisories/new) form (private, encrypted in transit).
- **Alternative:** Email the maintainer at the address listed in `git log`.

Please include:
- A short description of the issue and its impact.
- Reproduction steps or a minimal test case.
- Affected version(s) (output of `.\rogue-device-detector.ps1 -Version`).

You will receive an acknowledgement within a few days. After triage, a fix
will be released in the next patch version, and the advisory will be
disclosed publicly along with the release.

## Supported Versions

Only the latest minor version receives fixes. Older `1.x.y` releases are
not patched — update via the existing bootstrap snippet (see README).

| Version | Supported |
|---------|-----------|
| 1.5.x   | ✅ current |
| 1.4.x   | ❌ |
| < 1.4   | ❌ |

## Threat Model

This tool is intended for **defensive monitoring on networks the operator
already controls**. It performs ICMP ping sweep, ARP table read, reverse DNS,
NetBIOS probes, and TCP connect scans on a small set of well-known ports.

Out of scope:
- Use against networks without authorization. The tool will scan whatever
  subnet is configured; the operator is responsible for ensuring lawful use.
- Active exploitation, credential brute-forcing, packet injection. The
  scanner only opens TCP connections and reads HTTP banners; it does not
  attempt to authenticate or escalate.

The trust boundary for the deployment pipeline is documented in
[ARCHITECTURE.md](ARCHITECTURE.md#deployment-pipeline). Code-signing for the
bootstrap chain is tracked in [ROADMAP.md](ROADMAP.md).
