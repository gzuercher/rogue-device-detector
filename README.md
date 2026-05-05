# Rogue Device Detector (RDD)

[![Releases](https://img.shields.io/github/v/release/gzuercher/rogue-device-detector)](https://github.com/gzuercher/rogue-device-detector/releases) [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![CI](https://github.com/gzuercher/rogue-device-detector/actions/workflows/test.yml/badge.svg)](https://github.com/gzuercher/rogue-device-detector/actions/workflows/test.yml)

A standalone PowerShell script that detects unauthorized devices on your network. Built for MSPs and IT admins who need visibility into what's connected — without agents, cloud services, or vendor lock-in.

See [release notes](https://github.com/gzuercher/rogue-device-detector/releases) for changes between versions, [SECURITY.md](SECURITY.md) for vulnerability reporting, and [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup.

**What it does:** Scans your network, builds a baseline of known devices, and alerts you when something new shows up. It also monitors known devices for risky open ports and flags devices that disappear.

**What it doesn't do:** Real-time monitoring, vulnerability scanning, or anything that requires a cloud backend. It's a single script with a JSON config file.

## Quick Start

```powershell
# 1. Copy the example config and fill in your SMTP settings
Copy-Item config.example.json config.json
notepad config.json

# 2. Run in learning mode to build the baseline (no alerts sent)
.\rogue-device-detector.ps1 -LearningMode

# 3. Review the baseline; -RemoveDevice can be used to drop entries
.\rogue-device-detector.ps1 -ListDevices

# 4. Schedule regular scans (see Scheduling section below)
```

For unattended deployment via an RMM (NinjaOne / ConnectWise / Intune /
generic), see **[Unattended Install (RMM)](#unattended-install-rmm)** below.

## Unattended Install (RMM)

Store the snippet below once as a PowerShell script in your RMM. It downloads
the updater from the latest GitHub release, verifies its SHA-256, and runs it.
Idempotent — safe to schedule. Updater bumps require zero RMM maintenance.

```powershell
$base    = 'https://github.com/gzuercher/rogue-device-detector/releases/latest/download'
$tmp     = Join-Path $env:TEMP "rdd-bootstrap-$([guid]::NewGuid()).ps1"
$tmpHash = "$tmp.sha256"
try {
    Invoke-WebRequest "$base/Update-RogueDeviceDetector.ps1"        -OutFile $tmp     -UseBasicParsing -ErrorAction Stop
    Invoke-WebRequest "$base/Update-RogueDeviceDetector.ps1.sha256" -OutFile $tmpHash -UseBasicParsing -ErrorAction Stop
    $exp = (Get-Content $tmpHash -Raw).Trim().Split()[0].ToLower()
    $act = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
    if ($act -ne $exp) { throw "Updater hash mismatch: expected $exp, got $act" }
    & $tmp
    exit $LASTEXITCODE
} finally {
    Remove-Item $tmp,$tmpHash -Force -ErrorAction SilentlyContinue
}
```

The updater installs to `C:\Scripts\RDD\` and writes a default
`config.json` with `"configured": false` as a safety gate. The main script
refuses to run a normal scan until you review the file (smtp settings in
particular) and flip the flag to `true`. `-LearningMode` and the device-
management modes (`-ListDevices`, `-ApproveDevice`, etc.) work without the
flag, so you can seed the baseline before going live.

Re-running the same snippet on an existing host updates the script in place
to the latest release. The existing `config.json`, `state.json`, and audit
log are left untouched.

## Requirements

- Windows with PowerShell 5.1 or later (pre-installed on Windows 10/11/Server 2016+)
- Network access to the target subnet from the scanning host (same Layer-2 segment)
- SMTP server for email alerts (optional but recommended)

## How It Works

1. Sends ICMP pings across the subnet to populate the ARP cache
2. Reads the ARP table to collect MAC addresses and IPs
3. Resolves hostnames via reverse DNS (with NetBIOS fallback)
4. Looks up MAC vendors from the IEEE OUI database (cached locally)
5. Fingerprints the OS via ICMP TTL (Windows / Linux / macOS / network device)
6. Optionally scans 10 security-relevant TCP ports and grabs HTTP banners
7. Compares found devices against the baseline (`state.json`)
8. Sends alerts for rogue devices, risky ports, identity changes, and absent devices

## Parameters

### Scanning

| Parameter | Type | Description |
|-----------|------|-------------|
| `-LearningMode` | Switch | Adds all found devices to the baseline without sending alerts. Use for initial setup or after adding known devices to the network. |
| `-Config "path"` | String | Path to `config.json`. Defaults to `config.json` in the script directory. |
| `-Subnet "cidr"` | String | CIDR subnet to scan (e.g. `192.168.1.0/24`). Overrides config file. Auto-detected from NIC if omitted. |

### Device Management

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ApproveDevice "MAC"` | String | Add a device to the baseline by MAC address. Combine with `-Label` for a human-readable name. |
| `-Label "name"` | String | Human-readable name for the device (only with `-ApproveDevice`). |
| `-RemoveDevice "MAC"` | String | Remove a device from the baseline. |
| `-ListDevices` | Switch | Show all approved devices and exit. No scan is performed. |
| `-ApproveAllRogues` | Switch | Run a full scan and add every detected rogue to the baseline at once. Risk findings are NOT auto-allowed — risky open ports on the approved devices will be reported as RISK on the next scan. Use after acknowledging a batch of expected new devices. |

### Diagnostics

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Version` | Switch | Print the script version and exit. |
| `-TestSmtp` | Switch | Send a single test email using the configured SMTP settings, then exit. No scan, no state mutation. Use to validate config during initial setup. |
| `-DryRun` | Switch | (Combine with default scan mode.) Run a full scan but skip `state.json`, audit log, and email side effects. Useful for testing config changes without consequences. |
| `-?` / `Get-Help .\rogue-device-detector.ps1 -Full` | — | Built-in PowerShell help. Shows full parameter docs and usage examples. |

### Port Allowlist

Known devices with open ports trigger risk warnings by default. If a port is intentional (e.g. RDP on a terminal server), you can allow it per device to suppress the warning:

| Parameter | Type | Description |
|-----------|------|-------------|
| `-AllowPort 3389,22` | Int[] | Allow one or more ports on a device. Must be used with `-On`. |
| `-BlockPort 3389` | Int[] | Revoke a port allowance. Must be used with `-On`. |
| `-On "MAC"` | String | Target device MAC for `-AllowPort` or `-BlockPort`. |

## Usage Examples

```powershell
# --- Scanning ---

# Regular scan (typically run via scheduler)
.\rogue-device-detector.ps1

# Learning mode — baseline creation, no alerts
.\rogue-device-detector.ps1 -LearningMode

# Scan a specific subnet
.\rogue-device-detector.ps1 -Subnet "10.0.1.0/24"

# Use a config file from a different location
.\rogue-device-detector.ps1 -Config "C:\Scripts\rdd\config.json"


# --- Device Management ---

# Approve a device that appeared in an alert (copy-paste from the email)
.\rogue-device-detector.ps1 -ApproveDevice "AA:BB:CC:DD:EE:FF" -Label "Reception printer"

# Remove a device that left the network
.\rogue-device-detector.ps1 -RemoveDevice "AA:BB:CC:DD:EE:FF"

# List all approved devices with their allowed ports
.\rogue-device-detector.ps1 -ListDevices

# Bulk-approve every currently-rogue device after a known network change
.\rogue-device-detector.ps1 -ApproveAllRogues


# --- Port Allowlist ---

# Allow RDP and SSH on a known server (suppresses risk warnings for these ports)
.\rogue-device-detector.ps1 -AllowPort 3389,22 -On "AA:BB:CC:DD:EE:FF"

# Revoke a port allowance (port will trigger warnings again)
.\rogue-device-detector.ps1 -BlockPort 3389 -On "AA:BB:CC:DD:EE:FF"
```

## Configuration

Copy `config.example.json` to `config.json` and adjust. The config file is excluded from git (contains SMTP credentials).

```json
{
  "subnet": "",
  "statePath": "C:\\temp\\state.json",
  "ouiPath": "C:\\temp\\oui.csv",
  "logPath": "C:\\temp\\rdd-audit.csv",
  "enrichment": true,
  "absentDays": 21,
  "summaryReport": false,
  "configured": true,
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "user": "alerts@example.com",
    "password": "your-smtp-password",
    "from": "rdd@example.com",
    "to": "helpdesk@example.com",
    "useSsl": true
  }
}
```

| Field | Default | Description |
|---|---|---|
| `subnet` | auto-detect | CIDR subnet to scan, e.g. `192.168.1.0/24`. Empty = detect from NIC. |
| `statePath` | `state.json` in script dir | Full path to the known-device state file. |
| `ouiPath` | `oui.csv` in script dir | Full path to the OUI vendor cache file. |
| `logPath` | `rdd-audit.csv` in script dir | Full path to the audit log CSV file. |
| `enrichment` | `true` | Set to `false` to skip port scan / banner / UPnP (faster scan). |
| `absentDays` | `21` | Days without a sighting before a device is flagged as absent. |
| `summaryReport` | `false` | Send a full network health report after every scan (not just rogue alerts). |
| `configured` | `true` | Safety gate. The unattended installer writes `false`; normal scan mode refuses to run until you flip it to `true` after reviewing this file. `-LearningMode` and admin modes (`-ListDevices`, `-ApproveDevice`, …) bypass the gate. |
| `smtp.host` | – | SMTP server hostname. |
| `smtp.port` | `587` | SMTP port. |
| `smtp.user` | – | SMTP username. Optional; alerts skip silently if blank. |
| `smtp.password` | – | SMTP password. |
| `smtp.from` | – | Sender email address. |
| `smtp.to` | – | Alert recipient email address. |
| `smtp.useSsl` | port-derived | `true` enables TLS (587/465). When omitted, defaults to `false` for port 25 (typical local relay) and `true` otherwise. Explicit value always wins. |

All path values must include the full filename. Backslashes must be escaped as `\\` in JSON.

`state.json`, `oui.csv`, and `rdd-audit.csv` are also excluded from git.

### Audit log rotation

`rdd-audit.csv` is rotated automatically when its size exceeds 10 MB. The
active file is renamed to `<base>.YYYY-MM-DD-HHmmss.csv` and a fresh CSV
with the same header is started. Rotated files stay on disk for the
operator to archive or prune.

### Migrating state to another host

`state.json` is a portable JSON file with a versioned schema. Copy it to
the new host's configured `statePath` and the schema migrator brings older
versions up to current on first read. No re-baselining required if the
network is unchanged.

## Alerts

The default alert (`summaryReport: false`) is an HTML email sent only when
the scan finds something to report — at least one rogue, risk finding, or
absent device. The current scan's `rdd-audit.csv` is attached.

The body has:

- **Header** with scanner host, timestamp, and subnet.
- **Summary** with colored badges per category (rogue / risk / absent / hostname-changes).
- **Rogue Devices** table — MAC, IP, hostname, vendor, OS, open ports, risk level. One copy-paste-ready `-ApproveDevice` command listed below the table for each rogue.
- **Risk Findings on Known Devices** table — MAC, IP, hostname, level badge, reasons, open ports. One `-AllowPort <port> -On '<mac>'` template per device below the table.
- **Absent Devices** table — MAC, label, last-seen timestamp.

Risk-level badges use a consistent color scale: CRITICAL = red, HIGH = orange, MEDIUM = amber, LOW = yellow.

### Summary Report

Set `"summaryReport": true` for a plain-text comprehensive report after every
scan (not just on findings). Includes everything above plus identity changes
and a baseline-size line. Useful for weekly health check-ins where the
absence of an email would itself be a signal.

## Exit Codes (RMM Integration)

The script returns a bitmask exit code for use with any RMM or Intune:

| Code | Meaning |
|------|---------|
| `0`  | Clean — no issues found |
| `1`  | Rogue (unknown) devices detected |
| `2`  | Known devices with HIGH/CRITICAL risk ports |
| `4`  | Devices absent for longer than `absentDays` |

Codes combine: e.g. `3` = rogue devices **and** risk findings, `5` = rogue **and** absent.

In your RMM, create a condition on the script's exit code to auto-create tickets.

## Scheduling

Recommended: once per week (e.g. Monday at 02:00).

**Windows Task Scheduler:**
```
Action:    powershell.exe
Arguments: -NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\rdd\rogue-device-detector.ps1"
```

**Any RMM:** Deploy as a scheduled script task with the same arguments.

**Intune:** Deploy as a PowerShell script via Endpoint Manager.

**cron (via WSL or Linux/macOS with pwsh):**
```
0 2 * * 1 pwsh -NonInteractive -File /path/to/rogue-device-detector.ps1
```

## Typical Workflow

1. **Deploy:** Copy script + `config.json` to the target host
2. **Baseline:** Run with `-LearningMode` to establish the known-device baseline
3. **Review:** Use `-ListDevices` to verify; use `-RemoveDevice` to remove anything suspicious
4. **Schedule:** Set up a weekly scan without `-LearningMode`
5. **React to alerts:**
   - **Authorized device** (e.g. new laptop, printer): approve with `-ApproveDevice`
   - **Expected open port** (e.g. RDP on a server): allow with `-AllowPort ... -On ...`
   - **Unauthorized device**: investigate and remove from the network
6. **Re-baseline:** Run `-LearningMode` again after deliberate network changes

## Troubleshooting

**No devices found / ARP table empty**
- The scanning host must be on the same Layer-2 network as the target subnet. Scanning across routers or VLANs does not work (routers don't forward broadcast traffic).
- Windows Firewall may block outbound ICMP (ping). Verify with `ping 192.168.1.1`.
- Run `arp -a` manually to check if the ARP cache is populated.

**OUI database download fails**
- The script downloads from `https://standards-oui.ieee.org/oui/oui.csv`. Verify the host can reach this URL.
- If a proxy is required, the script uses the default system proxy settings.
- The scan continues without vendor names. Delete the cached `oui.csv` to force a fresh download.

**SMTP alerts not sending**
- Check `config.json` for correct `smtp.host`, `smtp.port`, `smtp.from`, and `smtp.to`. Alerts skip silently if any of those three are blank.
- TLS error like *"Das Remotezertifikat ist laut Validierungsverfahren ungültig"*: set `smtp.useSsl: false` for plain SMTP (typical for port 25 local relays). When omitted, `useSsl` is auto-derived from the port (false for 25, true otherwise) — explicit values always win.
- Port 587 (STARTTLS) is the typical authenticated submission port. Port 465 (implicit TLS) is not supported by `Send-MailMessage`.
- Verify connectivity: `Test-NetConnection -ComputerName smtp.example.com -Port 587`.
- Azure Communication Services SMTP requires the full connection string as username.

**Scan takes too long**
- Large subnets (e.g. /16 = 65k hosts) will be slow. Narrow the subnet or set `"enrichment": false`.
- Port scan and banner grab add time per device. Enrichment is most useful for /24 subnets.

**False positives (known devices reported as rogue)**
- Devices with MAC randomization (e.g. phones) appear as new devices each time. Approve the new MAC or disable MAC randomization on the device.
- DHCP lease changes don't cause false positives — the baseline tracks MAC addresses, not IPs.

**Permission errors on state/log files**
- The script needs write access to `state.json`, `rdd-audit.csv`, and `oui.csv`.
- When running as a scheduled task, ensure the task's user account has write access.
- Avoid placing files in `C:\Program Files` or other protected directories.

## Security Notes

- `config.json` contains SMTP credentials — restrict file permissions: `icacls config.json /inheritance:r /grant:r "SYSTEM:F" "BUILTIN\Administrators:F"`
- State file and audit log contain MAC addresses and hostnames — no credentials
- The script runs without elevated privileges (ARP read + ping + TCP connect do not require admin)
- OUI database download uses the system proxy and a browser User-Agent
