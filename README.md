# rogue-device-detector

Standalone PowerShell script that detects rogue/unauthorized devices on a network. No external dependencies, no cloud backend, no vendor lock-in.

## How it works

1. Performs a ping sweep across the configured subnet
2. Reads the ARP cache to collect MAC addresses and IPs
3. Resolves hostnames via reverse DNS
4. Looks up MAC vendors using the IEEE OUI database (downloaded and cached locally)
5. Fingerprints the OS via ICMP TTL (Windows / Linux / macOS / network device)
6. Compares found devices against a known-device baseline (`state.json`)
7. Detects identity changes (hostname changed since last scan)
8. Detects absent devices (not seen for a configurable number of days)
9. Sends alerts and/or a network health summary report via SMTP

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
| `statePath` | `state.json` in script dir | Full path to the known-device state file, e.g. `C:\\temp\\state.json` |
| `ouiPath` | `oui.csv` in script dir | Full path to the OUI vendor cache file, e.g. `C:\\temp\\oui.csv` |
| `logPath` | `rdd-audit.csv` in script dir | Full path to the audit log CSV file, e.g. `C:\\temp\\rdd-audit.csv` |
| `enrichment` | `true` | Set to `false` to skip port scan / banner / UPnP (faster scan) |
| `absentDays` | `21` | Days without a sighting before a device is flagged as absent |
| `summaryReport` | `false` | Send a full network health report after every scan (not just rogue alerts) |
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

An email alert is sent with MAC, IP, hostname, vendor, and OS guess for each unknown device.

- **Authorized device** (e.g. new laptop, printer): re-run with `-LearningMode` to add it to the baseline
- **Unauthorized device**: investigate and remove from the network

## Exit codes (RMM integration)

The script returns a bitmask exit code for use with NinjaOne, Intune, or other RMM tools:

| Code | Meaning |
|------|---------|
| `0`  | Clean – no issues found |
| `1`  | Rogue (unknown) devices detected |
| `2`  | Known devices with HIGH/CRITICAL risk ports |
| `4`  | Devices absent for longer than `absentDays` |

Codes combine: e.g. `3` = rogue devices **and** risk findings, `5` = rogue **and** absent.

In NinjaOne, create a condition on the script's exit code to auto-create tickets.

## Summary report

Set `"summaryReport": true` in `config.json` to receive a comprehensive network health email after every scan. The report includes:

- Device count overview (scanned, baseline, rogue, absent, risks)
- Rogue device details with approve commands
- Absent devices (not seen for `absentDays`+ days)
- Risk findings on known devices
- Identity changes (hostname changed since last scan)
- OS breakdown (Windows / Linux / macOS / network devices)

When `summaryReport` is `false` (default), only rogue device alerts are sent.

## State file

`state.json` stores all known devices. It is the sole source of truth – there is no external database. The file can be moved to another host by copying it alongside the script.

## OUI database

The IEEE OUI vendor database is downloaded automatically on first run and refreshed every 30 days. If the download fails, vendor names show as `Unknown` but the scan continues normally.

## Troubleshooting

**No devices found / ARP table empty**
- The scanning host must be on the same Layer-2 network as the target subnet. Scanning across routers or VLANs does not work (routers don't forward broadcast traffic).
- Windows Firewall may block outbound ICMP (ping). Verify with `ping 192.168.1.1` from the scanning host.
- Run `arp -a` manually to check if the ARP cache is populated.

**OUI database download fails**
- The script downloads from `https://standards-oui.ieee.org/oui/oui.csv`. Verify the host can reach this URL.
- If a proxy is required, configure the system proxy – the script uses the default system proxy settings.
- The scan continues without vendor names. Once connectivity is restored, delete the cached `oui.csv` to force a fresh download.

**SMTP alerts not sending**
- Check `config.json` for correct `smtp.host`, `smtp.port`, `smtp.user`, and `smtp.password`.
- Port 587 (STARTTLS) is the default. Some providers require port 465 (implicit TLS), which is not supported by `Send-MailMessage`.
- Verify the scanning host can reach the SMTP server: `Test-NetConnection -ComputerName smtp.example.com -Port 587`.
- Azure Communication Services SMTP requires the full connection string as username.

**Scan takes too long**
- Large subnets (e.g. /16 = 65k hosts) will be slow. Narrow the subnet or disable enrichment: set `"enrichment": false` in `config.json`.
- Port scan and banner grab add time per device. Enrichment is most useful for smaller subnets (/24).

**False positives (known devices reported as rogue)**
- Devices with changing MAC addresses (e.g. MAC randomization on phones) will appear as new devices each time. Approve the new MAC or disable MAC randomization on the device.
- DHCP lease changes don't cause false positives – the baseline tracks MAC addresses, not IPs.

**Permission errors on state/log files**
- The script needs write access to `state.json`, `rdd-audit.csv`, and `oui.csv`. When running as a scheduled task, ensure the task's user account has write access to these paths.
- Avoid placing files in `C:\Program Files` or other protected directories.
