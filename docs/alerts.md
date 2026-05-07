# Alerts

What RDD sends to the inbox and what each section means.

A rendered example is in **[samples/](samples/)** — open `sample-report.html` in a browser, or look at `sample-report.png` for a flat preview. Built from synthetic fixtures so you can read it before deploying.

## Alert email (default)

The default alert (`summaryReport: false`) is an HTML email sent only when the scan finds something to report — at least one rogue, risk finding, or absent device.

The body contains:

- **Header** with scanner host, timestamp, and subnet.
- **Summary** with colored badges per category (rogue / risk / absent / hostname-changes).
- **Rogue Devices** table — MAC, IP, hostname, vendor, OS, first-seen, details. One copy-paste-ready `-ApproveDevice` command listed below the table for each rogue. If a rogue's hostname is similar to a baseline device, an alias-match candidate row appears with a ready `-AliasOf` snippet.
- **Risk Findings on Known Devices** table — MAC, IP, hostname, level badge, reasons, open ports. One `-AllowPort <port> -On '<mac>'` template per device below the table.
- **Absent Devices** table — MAC, label, last-seen timestamp.

### Hostname column source tags

Each hostname is annotated with a small grey `[src]` subscript so the operator can judge name confidence at a glance:

| Tag | Source | Trust level |
|---|---|---|
| `[axfr]` | DNS zone transfer pre-fill | High — canonical, server-asserted |
| `[dns]` | Reverse DNS PTR | High — canonical |
| `[mdns]` | Multicast DNS reverse-PTR | Medium — device-self-asserted (`.local` stripped) |
| `[llmnr]` | LLMNR reverse-PTR | Medium — Windows-asserted |
| `[nbns]` | NetBIOS name query | Medium — legacy Windows |
| `[upnp]` | UPnP `friendlyName` from SSDP | Medium — device-self-asserted, often a service name |
| `[label]` | Operator-set `-Label` | Operator-curated — only used when the resolver cascade returned nothing |

### Risk-level badges

Risk-level badges use a consistent color scale: CRITICAL = red, HIGH = orange, MEDIUM = amber, LOW = yellow. The level on a device comes from the highest-risk open port (see the port table in [architecture.md](architecture.md#security-ports-monitored)).

## Summary report

Set `"summaryReport": true` for a plain-text comprehensive report after every scan (not just on findings). Includes everything above plus identity changes and a baseline-size line. Useful for weekly health check-ins where the absence of an email would itself be a signal.

## Exit codes (RMM integration)

The script returns a bitmask exit code for use with any RMM or Intune:

| Code | Meaning |
|------|---------|
| `0` | Clean — no issues found |
| `1` | Rogue (unknown) devices detected |
| `2` | Devices with risk findings at or above `config.alertRiskLevel` (default `HIGH`) |
| `4` | Devices absent for longer than `absentDays` |

Codes combine: e.g. `3` = rogue devices **and** risk findings, `5` = rogue **and** absent.

In your RMM, create a condition on the script's exit code to auto-create tickets.
