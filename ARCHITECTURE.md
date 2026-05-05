# ARCHITECTURE.md

Technical design and decisions for the rogue-device-detector. This document is for developers and contributors.

## Goal

Detect unknown (rogue) devices on a network. Standalone PowerShell script, no external dependencies, no vendor lock-in. Can be deployed and scheduled via any RMM, MDM, or Windows Task Scheduler.

## Data Flow

```
Scheduled execution (any scheduler, recommended: weekly)
  └─ PowerShell Script
       ├─ 1. Load config (config.json + parameter overrides)
       ├─ 1b. Validate output paths (statePath, logPath, ouiPath) for writability
       ├─ 1c. Safety gate: refuse normal-scan path if config.configured == false
       ├─ 2. Determine subnet (auto-detect from NIC or config override)
       ├─ 2b. Acquire scan lock (exclusive lock file prevents concurrent scans)
       ├─ 3. Ping sweep → populate ARP cache (async, ~500ms for /24)
       ├─ 4. Read ARP table → list of MACs + IPs (broadcast/network addr filtered)
       ├─ 5. Resolve hostnames (concurrent DNS via Task.WaitAll + NetBIOS fallback)
       ├─ 6. Lookup MAC vendor (OUI database, offline)
       ├─ 7. OS fingerprint via TTL (Windows / Linux/macOS / Network device)
       ├─ 8. Enrichment (if enabled):
       │       ├─ UPnP/SSDP broadcast → IoT device identification
       │       ├─ TCP port scan (10 security ports, async, per device)
       │       ├─ HTTP/HTTPS banner grab (title + Server header)
       │       └─ Risk evaluation → NONE / LOW / MEDIUM / HIGH / CRITICAL
       ├─ 9. Load state file → known MACs
       ├─ 10. Compare: found vs known
       │        ├─ Detect identity changes (hostname changed since last scan)
       │        └─ Detect absent devices (not seen for N days)
       ├─ 10b. Filter allowed ports from risk data (per-device port allowlist)
       ├─ 11a. Learning Mode ON  → merge new devices into state, no alerts
       │         └─ Print simulated alert to console for new devices
       └─ 11b. Learning Mode OFF → delta (new MACs only):
                ├─ Send alert email or summary report via SMTP
                ├─ Log RISK_FOUND for known devices with HIGH/CRITICAL risk
                ├─ Log DEVICE_ABSENT / DEVICE_CHANGED events
                ├─ Write audit log entries
                └─ Exit with bitmask code for RMM integration
```

## State File

Local JSON file (`state.json`). Path configurable. Can be moved to another device to migrate state. Includes a `schemaVersion` field for automatic migration of older state files.

### Schema Version 3 (current)

```json
{
  "schemaVersion": 3,
  "lastScan": "2026-03-23T08:00:00Z",
  "knownDevices": [
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "ip": "192.168.1.42",
      "hostname": "FILESERVER",
      "vendor": "Dell Inc.",
      "osGuess": "Windows",
      "label": "File server",
      "firstSeen": "2026-03-01T10:00:00Z",
      "lastSeen": "2026-03-23T08:00:00Z",
      "approvedBy": "DOMAIN\\admin",
      "approvedAt": "2026-03-01T10:00:00Z",
      "allowedPorts": [
        { "port": 3389, "allowedBy": "DOMAIN\\admin", "allowedAt": "2026-03-23T10:00:00Z" },
        { "port": 22, "allowedBy": "DOMAIN\\admin", "allowedAt": "2026-03-23T10:00:00Z" }
      ]
    }
  ]
}
```

**Schema history:**
- v1: No `schemaVersion` field
- v2: Added `schemaVersion`, `osGuess`, auto-migration on load
- v3: Added `allowedPorts` per device. Backward compatible — devices without `allowedPorts` are treated as having an empty list.

Enrichment data (ports, banner, risk) is not persisted — it is re-evaluated on every scan. The `osGuess` field is persisted so absent device reports can include the OS.

## Port Allowlist

Per-device list of allowed TCP ports stored in `state.json`. Suppresses risk warnings for intentional services (e.g. RDP on a terminal server).

**Design decision:** The allowlist is applied *after* enrichment and *after* baseline matching, not during port scanning. `Get-DeviceRisk` calculates risk on all open ports. `Get-FilteredRisk` then strips allowed ports and recalculates the effective risk level. This keeps the scan pipeline clean and the filtering explicit.

A device with all risky ports allowed has effective risk level `NONE`. New unexpected ports on the same device still trigger warnings.

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
| `RISK_FOUND` | Normal scan: known device with HIGH or CRITICAL risk (after allowlist filtering) |
| `DEVICE_CHANGED` | Hostname changed since last scan (identity change) |
| `DEVICE_ABSENT` | Device not seen for longer than `absentDays` |
| `DEVICE_APPROVED` | Device manually approved via `-ApproveDevice` |
| `DEVICE_REMOVED` | Device manually removed via `-RemoveDevice` |
| `PORT_ALLOWED` | Port(s) added to a device's allowlist via `-AllowPort` |
| `PORT_BLOCKED` | Port(s) removed from a device's allowlist via `-BlockPort` |

A quiet network produces exactly 2 log lines per week.

## Parameter Sets

Mutually exclusive parameter sets enforce valid CLI combinations:

| Set Name | Parameters | Description |
|----------|-----------|-------------|
| `Scan` (default) | `-Config`, `-Subnet`, `-LearningMode` | Normal scan operation |
| `ApproveDevice` | `-ApproveDevice`, `-Label` | Add device to baseline |
| `RemoveDevice` | `-RemoveDevice` | Remove device from baseline |
| `AllowPort` | `-AllowPort`, `-On` (mandatory) | Allow port(s) on a device |
| `BlockPort` | `-BlockPort`, `-On` (mandatory) | Revoke port allowance |
| `ListDevices` | `-ListDevices` | Show approved devices |
| `ApproveAllRogues` | `-ApproveAllRogues`, `-Config`, `-Subnet` | Scan, then bulk-add every detected rogue to baseline. Risk findings are not auto-allowed |

## Security Ports Monitored

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

## Features

### Included

- **Ping sweep + ARP scan** — Pure PowerShell, no external tools, async concurrent
- **Auto-subnet detection** — Reads own NIC config; overridable via config or parameter
- **Hostname resolution** — Async concurrent reverse DNS with `Task.WaitAll` (2s timeout per host), NetBIOS (UDP 137) fallback for unresolved hosts
- **MAC vendor lookup** — IEEE OUI database, downloaded on first run, cached 30 days
- **Port scan** — 10 security-relevant TCP ports per device, async, ~500ms per host
- **HTTP/HTTPS banner grab** — Page title + Server header for device identification
- **UPnP discovery** — Single SSDP broadcast, identifies IoT/smart devices
- **Risk evaluation** — NONE / LOW / MEDIUM / HIGH / CRITICAL based on open ports
- **Per-device port allowlist** — Suppress risk warnings for intentional services
- **OS fingerprinting** — TTL-based guess: Windows, Linux/macOS, Network device
- **Identity change detection** — Alerts when a known device's hostname changes
- **Absent device detection** — Flags devices not seen for configurable number of days
- **Learning mode** — Baseline creation: merges found devices into state, no alerts
- **HTML SMTP alert** — Inline-styled email with per-section tables (Rogue / Risk / Absent), color-coded risk badges, copy-paste-safe action commands, and the audit CSV attached. Sent only when something is to report. Azure ACS compatible
- **Safety gate** — `config.configured` defaults to `false` in installer-generated configs; the main script refuses normal scans until an operator reviews the config and flips the flag. `-LearningMode` and admin modes bypass the gate
- **Summary report** — Optional comprehensive network health email with OS breakdown
- **RMM exit codes** — Bitmask exit code (0=clean, 1=rogue, 2=risk, 4=absent) for any RMM/Intune
- **Portable state file** — JSON, path configurable, versioned schema with auto-migration
- **Path validation** — All output paths validated for writability before scan starts
- **Concurrent scan guard** — Exclusive lock file prevents two scans from corrupting `state.json`
- **Subnet validation** — /31 and /32 subnets are rejected (no scannable host addresses)
- **Audit log** — Append-only CSV, minimal noise, suitable for compliance/forensics

### Explicitly Out of Scope

- Real-time / continuous monitoring
- Vulnerability scanning
- Web UI or dashboard
- Cloud backend or external API dependencies

## Deployment Pipeline

Three-layer install/update model designed for unattended RMM rollouts:

```
RMM (NinjaOne / ConnectWise / Intune / etc.)
  └─ ~10-line bootstrap snippet (copy-paste once into the RMM)
       ├─ Downloads Update-RogueDeviceDetector.ps1 from the latest GitHub Release
       ├─ Verifies SHA-256 against the published .sha256 sidecar
       └─ Executes the updater
            ├─ On a fresh host:
            │    ├─ Creates C:\Scripts\RDD\ and C:\Scripts\RDD\var\
            │    ├─ Downloads + verifies + installs rogue-device-detector.ps1
            │    ├─ Generates a default config.json with "configured": false
            │    │    └─ SMTP host auto-detected from default gateway, port 25, no auth
            │    └─ Prints next-steps reminder
            └─ On an existing host:
                 ├─ Compares installed $SCRIPT_VERSION to latest release
                 ├─ Updates the script in place if newer (creates .backup first)
                 └─ Leaves config.json, state.json, audit log untouched
```

**Idempotency.** Re-running the bootstrap is always safe. An existing
`config.json` is never overwritten by the updater; the safety gate enforces
that operators consciously transition from default to live state.

**Trust boundary.** The bootstrap's SHA-256 check protects against transit
corruption. Repo-compromise mitigation (code-signing the updater) is tracked
in `ROADMAP.md`.

## Code Quality

### PSScriptAnalyzer

Standard PSScriptAnalyzer rules plus a custom rule:

- **`Measure-UnsafeCountAccess`** (`rules/Measure-UnsafeCountAccess.psm1`): Detects `.Count` access on variables not provably backed by an array or typed collection. Under `Set-StrictMode -Version Latest`, `.Count` on a single object or `$null` throws `PropertyNotFoundException`. The rule uses AST analysis to find unprotected accesses and suggests wrapping in `@()`.

Custom rules are loaded via `-CustomRulePath ./rules/` in both CI and the local lint hook.

### Tests

Pester 5 tests in `tests/`. Run with:

```powershell
Invoke-Pester ./tests/ -Output Detailed
```

## Security Notes

- `config.json` contains SMTP credentials — restrict file permissions
- State file and audit log contain MAC addresses and hostnames — no credentials
- Script runs without elevated privileges (ARP read + ping + TCP connect do not require admin)
- OUI database download uses system proxy and browser User-Agent to pass corporate firewalls
