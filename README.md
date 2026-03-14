# rogue-device-detector

Standalone PowerShell script that detects rogue/unauthorized devices on a network. No external dependencies, no cloud backend, no vendor lock-in.

## How it works

1. Performs a ping sweep across the configured subnet
2. Reads the ARP cache to collect MAC addresses and IPs
3. Resolves hostnames via reverse DNS
4. Looks up MAC vendors using the IEEE OUI database (downloaded and cached locally)
5. Compares found devices against a known-device baseline (`state.json`)
6. Sends an SMTP alert for any unknown device

## Requirements

- Windows, PowerShell 5.1 or later
- Network access to the target subnet from the scanning host
- SMTP server for alerts (optional but recommended)

## Setup

1. Copy `config.example.json` to `config.json` and fill in your SMTP settings
2. Run once in learning mode to create the baseline:
   ```powershell
   .\rogue-device-detector.ps1 -LearningMode
   ```
3. Review `state.json` – remove any entries that should not be trusted
4. Schedule for weekly execution (see below)

## Usage

```powershell
# Establish or update baseline (no alerts sent)
.\rogue-device-detector.ps1 -LearningMode

# Regular scan
.\rogue-device-detector.ps1

# Use a specific config file
.\rogue-device-detector.ps1 -Config "C:\Scripts\rdd\config.json"

# Override subnet
.\rogue-device-detector.ps1 -Subnet "10.0.1.0/24"
```

## Configuration

Copy `config.example.json` to `config.json` and adjust:

| Field | Default | Description |
|---|---|---|
| `subnet` | auto-detect | CIDR subnet to scan, e.g. `192.168.1.0/24` |
| `statePath` | `state.json` in script dir | Path to the known-device state file |
| `ouiPath` | `oui.csv` in script dir | Path to the OUI vendor cache |
| `smtp.host` | – | SMTP server hostname |
| `smtp.port` | `587` | SMTP port (STARTTLS) |
| `smtp.user` | – | SMTP username |
| `smtp.password` | – | SMTP password |
| `smtp.from` | – | Sender email address |
| `smtp.to` | – | Alert recipient email address |

`config.json` is excluded from git (contains credentials). `state.json` and `oui.csv` are also excluded.

## Scheduling

Recommended: weekly, e.g. Monday at 02:00.

**Windows Task Scheduler:**
```
Action: powershell.exe
Arguments: -NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\rdd\rogue-device-detector.ps1"
```

**NinjaOne / any RMM:** deploy as a scheduled script task with the same arguments.

## When a rogue device is detected

An email alert is sent with MAC, IP, hostname, and vendor for each unknown device.

- **Authorized device** (e.g. new laptop, printer): re-run with `-LearningMode` to add it to the baseline
- **Unauthorized device**: investigate and remove from the network

## State file

`state.json` stores all known devices. It is the sole source of truth – there is no external database. The file can be moved to another host by copying it alongside the script.

## OUI database

The IEEE OUI vendor database is downloaded automatically on first run and refreshed every 30 days. If the download fails, vendor names show as `Unknown` but the scan continues normally.
