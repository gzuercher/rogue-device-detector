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
       ├─ 3. Ping sweep → populate ARP cache
       ├─ 4. Read ARP table → list of MACs + IPs
       ├─ 5. Resolve hostnames (reverse DNS + NetBIOS fallback)
       ├─ 6. Lookup MAC vendor (OUI, offline)
       ├─ 7. Load state file → known MACs
       ├─ 8. Compare: found vs known
       ├─ 9a. Learning Mode ON  → write all found devices to state file, no alerts
       └─ 9b. Learning Mode OFF → delta (new MACs only):
                └─ Send alert email via SMTP
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

## Configuration

Config file: `config.json` (same directory as script by default).
All values can be overridden via script parameters.

```json
{
  "subnet": "",
  "statePath": "",
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
| `statePath` | script dir | Path to state JSON file. |
| `smtp.host` | – | SMTP server hostname |
| `smtp.port` | `587` | SMTP port |
| `smtp.user` | – | SMTP username |
| `smtp.password` | – | SMTP password |
| `smtp.from` | – | Sender address |
| `smtp.to` | – | Alert recipient address |

## Features

### Included

- **Ping sweep + ARP scan** – Pure PowerShell, no external tools
- **Auto-subnet detection** – Reads own NIC config; config/parameter overrides if needed
- **Hostname resolution** – Reverse DNS first, NetBIOS fallback
- **MAC vendor lookup** – Offline OUI database (IEEE), bundled with script
- **Learning mode** – First run baseline: all found devices written to state, no alerts
- **SMTP alert** – Configurable, Azure ACS compatible (STARTTLS on port 587)
- **Portable state file** – JSON, path configurable, easy to migrate

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
2. Fill in `config.json` (SMTP, optional subnet override)
3. Run once with `-LearningMode` to establish baseline
4. Review state file, remove any devices that should not be known
5. Schedule weekly run without `-LearningMode`

## Security Notes

- `config.json` contains SMTP credentials – restrict file permissions (`icacls`)
- State file contains MAC addresses and hostnames – no credentials
- Script runs without elevated privileges (ARP read + ping do not require admin)
