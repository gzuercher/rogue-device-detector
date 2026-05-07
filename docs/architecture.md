# Architecture

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
       ├─ 5. Resolve hostnames (cascade: AXFR pre-fill → DNS → mDNS → LLMNR → NetBIOS)
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
                ├─ Log RISK_FOUND for devices at or above config.alertRiskLevel
                │     (default HIGH; "NONE" disables the entire risk section)
                ├─ Log DEVICE_ABSENT / DEVICE_CHANGED events
                ├─ Write audit log entries
                └─ Exit with bitmask code for RMM integration
```

## Hostname Resolution

A layered cascade. Each stage runs only against IPs still unresolved by the previous one. Every device's `hostnameSource` field records which stage answered (`axfr` / `dns` / `mdns` / `llmnr` / `nbns` / `upnp`); this is rendered as a small `[src]` subscript in the alert and console output.

1. **AXFR (DNS zone transfer)** — opt-in, default-on. One TCP/53 query per scan to a configured (or auto-discovered) DNS server for the forward zone (`config.dnsZoneTransfer.{enabled, server, zone}`). On success, the entire zone's A records are pre-loaded as an IP→hostname map; every matching IP is fully resolved before any network probing happens. On failure (REFUSED rcode, unreachable, malformed) one WARN line is logged and the cascade continues — designed so that an unauthorised attempt costs nothing more than a few hundred milliseconds. Auto-discovery uses `$env:USERDNSDOMAIN` plus the active interface's first DNS server / DnsSuffix when `server`/`zone` are empty.
2. **DNS reverse-PTR** — `[System.Net.Dns]::GetHostEntryAsync` fired in parallel for all remaining IPs, joined via `Task.WhenAny` with a 2 s per-host timeout.
3. **mDNS** — single multicast burst into `224.0.0.251:5353` (RFC 6762, QU bit set), 3 s passive listen window, responder-IP filter. O(1) regardless of subnet size. Returns `.local` names from Apple/Linux/IoT.
4. **LLMNR** — same pattern against `224.0.0.252:5355` (RFC 4795, no QU bit). Covers modern Windows hosts that no longer have NetBIOS over TCP/IP enabled.
5. **NetBIOS** — UDP/137 unicast per host, sequential. Legacy Windows / SMB devices.
6. **UPnP `friendlyName`** (in the enrichment phase, not the hostname pass) — fallback for devices that only advertise themselves over SSDP. Final entry in the chain.

Trailing `.local` is stripped from every result via `Format-DisplayHostname` so the column shows `fileserver` rather than `fileserver.local`.

## Detection Rules

Four independent detection categories. A single device can land in more than one (a rogue device can also have risk findings; a known device can be both at risk and absent on a future scan).

### Rogue

A device is rogue when its **MAC address** matches neither a primary `mac` nor any entry in any device's `aliases` list. Match is MAC-only and case-insensitive — IP, hostname, vendor, and OS are ignored for the rogue/known decision (they appear in the alert as context).

- Recurring rogue MACs are tracked in `state.seenRogues` so the alert can show how long the device has been seen, not just "today".
- Approving a MAC (`-ApproveDevice` / `-ApproveAllRogues`) removes it from `seenRogues`.
- For each rogue, the alert shows up to 3 baseline candidates with similar hostnames (normalised, case-insensitive, ranked by common-prefix length) plus a copy-paste `-AliasOf` snippet — the typical case being a notebook's second NIC showing up under a different MAC.

### Risk

Computed from open TCP ports against the hardcoded port table (see [Security Ports Monitored](#security-ports-monitored)). Independent of rogue/known status.

1. `Get-DeviceRisk` walks the device's open ports and records every port whose definition has a non-`NONE` risk.
2. The device's effective level is the **maximum** across all matching ports (`NONE < LOW < MEDIUM < HIGH < CRITICAL`).
3. `Get-FilteredRisk` then strips ports listed in the device's `allowedPorts` and recomputes the level from the remaining ports.
4. The device is reported in the Risk-Findings table only if its effective level is **at or above** `config.alertRiskLevel` (default `HIGH`; `NONE` disables the entire risk section).

A rogue device's risk findings are evaluated identically — rogue and risk are two lenses on the same device, not mutually exclusive.

### Identity Change

A known MAC whose hostname differs from the previously stored hostname triggers a `DEVICE_CHANGED` event. To avoid noise from transient DNS failures, the change is **suppressed** when the previously stored hostname looks like an IPv4 address (i.e. DNS was failing before and recovered now). See `Test-IdentityChange` in the script.

### Absent

A known device is flagged absent when `now - lastSeen > config.absentDays` (default `21`). Absent devices stay in the baseline; they are reported in the Absent table until they reappear or are removed via `-RemoveDevice`.

## State File

Local JSON file (`state.json`). Path configurable. Can be moved to another device to migrate state. Includes a `schemaVersion` field for automatic migration of older state files.

### Schema Version 5 (current)

```json
{
  "schemaVersion": 5,
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
      ],
      "aliases": ["AA:BB:CC:DD:EE:F0"]
    }
  ],
  "seenRogues": [
    { "mac": "11:22:33:44:55:66", "firstSeen": "2026-03-20T08:00:00Z", "lastSeen": "2026-03-23T08:00:00Z" }
  ]
}
```

`seenRogues` tracks unapproved-but-recurring MACs across scans so the alert email can show "first seen N days ago" instead of always "today". Entries are removed when the MAC is approved (via `-ApproveDevice` or `-ApproveAllRogues`).

`aliases` lets one logical device own multiple MACs (e.g. a notebook's wired and WiFi adapters). The `mac` field is the primary identity; aliases are additional MACs that resolve to the same baseline entry. Lookup goes through `Find-KnownDevice`, which checks the primary first and then walks each device's alias list.

**Schema history:**
- v1: No `schemaVersion` field
- v2: Added `schemaVersion`, `osGuess`, auto-migration on load
- v3: Added `allowedPorts` per device. Backward compatible — devices without `allowedPorts` are treated as having an empty list.
- v4: Added top-level `seenRogues`. Backward compatible — missing field is initialised to an empty list on load.
- v5: Added `aliases` per device. Backward compatible — missing field is initialised to an empty list on load.

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
| `RISK_FOUND` | Normal scan: device at or above `config.alertRiskLevel` (default `HIGH`; `NONE` disables) after allowlist filtering. Both rogue and known devices land here when they cross the threshold |
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
