# Documentation

Documentation is grouped by audience. Pick the section that matches what you are about to do.

## For engineers — deploy and operate

Operators, MSP techs, and IT admins running RDD against a network.

- **[Deployment](deployment.md)** — requirements, quick start, unattended install via RMM, scheduling, migrating state between hosts.
- **[Usage](usage.md)** — every CLI parameter, the scan workflow, daily examples (approving devices, allowing ports, bulk-approving rogues).
- **[Configuration](configuration.md)** — every key in `config.json`: SMTP, AXFR pre-fill, risk-alert threshold, audit log rotation.
- **[Alerts](alerts.md)** — what an alert email contains, exit codes for RMM integration, the optional summary report.
- **[Diagnostics](diagnostics.md)** — `-Verbose` / `-Debug` recipes, `tools/Test-Axfr.ps1`, what to attach to a bug report.
- **[Troubleshooting](troubleshooting.md)** — common gotchas: empty ARP table, SMTP errors, false positives, OUI download failures.

See **[samples/](samples/)** for a rendered example of an alert email built from synthetic data.

## For security reviewers

Anyone evaluating RDD for production use.

- **[Security model](security.md)** — what RDD reads and writes, where credentials live, file-permission recommendations, the `configured: false` safety gate.
- **[SECURITY.md](../SECURITY.md)** (repo root) — vulnerability reporting policy.

## For developers — architecture and contribution

Anyone reading or extending the script.

- **[Architecture](architecture.md)** — data flow diagram, state-file schema (current is v5), detection rules, hostname-resolution cascade, the security-port table.
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** (repo root) — dev environment, running tests, coding conventions.
- **[ROADMAP.md](../ROADMAP.md)** (repo root) — directional plans.
