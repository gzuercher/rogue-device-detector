# ARCHITECTURE.md

Technical design and decisions for the rogue-device-detector.

## Goal

Detect unknown (rogue) devices on a network. Standalone PowerShell script, no external dependencies, no vendor lock-in. Can be deployed and scheduled via any RMM, MDM, or Windows Task Scheduler.

## Data Flow

```
Scheduled execution (any scheduler, recommended: weekly)
  └─ PowerShell Script
       ├─ 1. Load config (config.json + parameter overrides)
       ├─ 2. Determine subnet (auto-detect from NIC or config override)
       ├─ 3. Ping sweep → populate ARP cache (async, ~500ms for /24)
       ├─ 4. Read ARP table → list of MACs + IPs (broadcast/network addr filtered)
       ├─ 5. Resolve hostnames (async reverse DNS, 2s timeout, concurrent)
       ├─ 6. Lookup MAC vendor (OUI database, offline)
       ├─ 7. Enrichment (if enabled):
       │       ├─ UPnP/SSDP broadcast → IoT device identification
       │       ├─ TCP port scan (10 security ports, async, per device)
       │       ├─ HTTP/HTTPS banner grab (title + Server header)
       │       └─ Risk evaluation → NONE / LOW / MEDIUM / HIGH / CRITICAL
       ├─ 8. Load state file → known MACs
       ├─ 9. Compare: found vs known
       ├─ 10a. Learning Mode ON  → merge new devices into state, no alerts
       │         └─ Print simulated alert to console for new devices
       └─ 10b. Learning Mode OFF → delta (new MACs only):
                 ├─ Send alert email via SMTP (with enrichment data)
                 ├─ Log RISK_FOUND for known devices with HIGH/CRITICAL risk
                 └─ Write audit log entries
```

## State File

Local JSON file. Path configurable. Can be moved to another device to migrate state.

```json
{
  "lastScan": "2025-03-14T08:00:00Z",
  "knownDevices": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "ip": "192.168.1.42",
      "hostname": "LAPTOP-XYZ",
      "vendor": "Apple Inc.",
      "firstSeen": "2025-03-01T10:00:00Z",
      "lastSeen": "2025-03-14T08:00:00Z"
    }
  ]
}
```

Note: enrichment data (ports, banner, risk) is not persisted in the state file – it is re-evaluated on every scan.

## Audit Log

Append-only CSV file (`rdd-audit.csv` by default). Never overwritten, only extended.

Columns: `Timestamp, Event, Scanner, MAC, IP, Hostname, Vendor, OpenPorts, Risk, Details`

Events logged (minimal noise principle):

| Event | When |
|---|---|
| `SCAN_START` | Every scan run |
| `SCAN_DONE` | Every scan run (summary: found/rogue/risks counts) |
| `DEVICE_NEW` | Learning mode: new device added to baseline |
| `DEVICE_ROGUE` | Normal scan: unknown device detected |
| `RISK_FOUND` | Normal scan: known device with HIGH or CRITICAL risk |

A quiet network produces exactly 2 log lines per week.

## Configuration

Config file: `config.json` (same directory as script by default).
All path values must include the full filename. Backslashes must be escaped as `\\`.

```json
{
  "subnet": "",
  "statePath": "C:\\temp\\state.json",
  "ouiPath": "C:\\temp\\oui.csv",
  "logPath": "C:\\temp\\rdd-audit.csv",
  "enrichment": true,
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "user": "user@example.com",
    "password": "secret",
    "from": "rdd@example.com",
    "to": "alerts@example.com"
  }
}
```

| Field | Default | Description |
|---|---|---|
| `subnet` | auto-detect | Subnet to scan, e.g. `192.168.1.0/24`. Empty = detect from NIC. |
| `statePath` | `state.json` in script dir | Full path to known-device state file. |
| `ouiPath` | `oui.csv` in script dir | Full path to OUI vendor cache file. |
| `logPath` | `rdd-audit.csv` in script dir | Full path to audit log CSV file. |
| `enrichment` | `true` | Set to `false` to skip port scan / banner / UPnP (faster). |
| `smtp.host` | – | SMTP server hostname |
| `smtp.port` | `587` | SMTP port (STARTTLS) |
| `smtp.user` | – | SMTP username |
| `smtp.password` | – | SMTP password |
| `smtp.from` | – | Sender address |
| `smtp.to` | – | Alert recipient address |

## Features

### Included

- **Ping sweep + ARP scan** – Pure PowerShell, no external tools, async concurrent
- **Auto-subnet detection** – Reads own NIC config; overridable via config or parameter
- **Hostname resolution** – Async concurrent reverse DNS (2s timeout per host)
- **MAC vendor lookup** – IEEE OUI database, downloaded on first run, cached 30 days
- **Port scan** – 10 security-relevant TCP ports per device, async, ~500ms per host
- **HTTP/HTTPS banner grab** – Page title + Server header for device identification
- **UPnP discovery** – Single SSDP broadcast, identifies IoT/smart devices
- **Risk evaluation** – NONE / LOW / MEDIUM / HIGH / CRITICAL based on open ports
- **Learning mode** – Baseline creation: merges found devices into state, no alerts; simulates alert output on console for new devices
- **SMTP alert** – Enriched with ports, risk, banner, UPnP info; Azure ACS compatible
- **Portable state file** – JSON, path configurable, easy to migrate between hosts
- **Audit log** – Append-only CSV, minimal noise, suitable for compliance/forensics

### Security Ports Monitored

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | HIGH |
| 22 | SSH | LOW |
| 23 | Telnet | CRITICAL |
| 25 | SMTP | MEDIUM |
| 80 | HTTP | LOW |
| 443 | HTTPS | NONE |
| 445 | SMB | HIGH |
| 3389 | RDP | HIGH |
| 8080 | HTTP-alt | LOW |
| 8443 | HTTPS-alt | NONE |

### Explicitly Out of Scope

- Real-time / continuous monitoring
- Disappeared / offline device detection
- Vulnerability scanning
- Web UI or dashboard
- Cloud backend or external API dependencies

## Scheduling

Recommended: once per week (e.g. Monday 02:00).

Works with any scheduler:
- Windows Task Scheduler
- NinjaOne / ConnectWise / any RMM as a scheduled script
- Intune (PowerShell script deployment)
- cron (via WSL or on Linux/macOS with pwsh)

## First-Time Setup

1. Copy script + `config.json` to target device
2. Fill in `config.json` (SMTP, paths, optional subnet override)
3. Run once with `-LearningMode` to establish baseline
4. Review console output and `state.json` – remove any entries that should not be trusted
5. Schedule weekly run without `-LearningMode`

## Security Notes

- `config.json` contains SMTP credentials – restrict file permissions (`icacls config.json /inheritance:r /grant:r "SYSTEM:F"`)
- State file and audit log contain MAC addresses and hostnames – no credentials
- Script runs without elevated privileges (ARP read + ping + TCP connect do not require admin)
- OUI database download uses system proxy and browser User-Agent to pass corporate firewalls
