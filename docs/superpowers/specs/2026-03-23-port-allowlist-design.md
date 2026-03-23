# Port Allowlist & Parameter Rename

## Problem

Risk warnings (open ports like RDP, SSH, Telnet, HTTP) are reported on every scan, even for known/approved devices where the ports are intentional. There is no way to acknowledge that a specific port on a specific device is expected. This creates alert fatigue in environments with legitimate services.

Additionally, the current parameter names (`-Approve`, `-Remove`, `-List`) are not self-explanatory.

## Solution

1. Per-device port allowlist stored in state.json
2. Rename parameters to be self-documenting
3. Copy-paste commands in alerts for port approval (same UX pattern as device approval)

## Parameter Changes (Breaking)

No backward-compatible aliases. Old parameter names are removed entirely.

| Old | New | Type | Description |
|-----|-----|------|-------------|
| `-Approve "MAC"` | `-ApproveDevice "MAC"` | `[string]` | Add device to baseline |
| `-Remove "MAC"` | `-RemoveDevice "MAC"` | `[string]` | Remove device from baseline |
| `-List` | `-ListDevices` | `[switch]` | Show all approved devices |
| `-Label "Name"` | `-Label "Name"` | `[string]` | Unchanged, used with `-ApproveDevice` |
| — | `-AllowPort 3389,22` | `[int[]]` | Allow port(s) on a device |
| — | `-BlockPort 3389` | `[int[]]` | Revoke port allowance |
| — | `-On "MAC"` | `[string]` | Target device for `-AllowPort` / `-BlockPort` |

### Parameter Sets

Mutually exclusive parameter sets enforce valid combinations:

| Set Name | Parameters | Description |
|----------|-----------|-------------|
| `Scan` (default) | `-Config`, `-Subnet`, `-LearningMode` | Normal scan operation |
| `ApproveDevice` | `-ApproveDevice`, `-Label` | Add device to baseline |
| `RemoveDevice` | `-RemoveDevice` | Remove device from baseline |
| `AllowPort` | `-AllowPort`, `-On` (mandatory) | Allow port(s) on a device |
| `BlockPort` | `-BlockPort`, `-On` (mandatory) | Revoke port allowance |
| `ListDevices` | `-ListDevices` | Show approved devices |

`-On` is mandatory when `-AllowPort` or `-BlockPort` is used, enforced via parameter set.

### Usage Examples

```powershell
# Approve a device (renamed from -Approve)
.\rogue-device-detector.ps1 -ApproveDevice "AA:BB:CC:DD:EE:FF" -Label "File server"

# Allow specific ports on a known device
.\rogue-device-detector.ps1 -AllowPort 3389,22 -On "AA:BB:CC:DD:EE:FF"

# Revoke a port allowance
.\rogue-device-detector.ps1 -BlockPort 3389 -On "AA:BB:CC:DD:EE:FF"

# Remove a device entirely
.\rogue-device-detector.ps1 -RemoveDevice "AA:BB:CC:DD:EE:FF"

# List all approved devices with their allowed ports
.\rogue-device-detector.ps1 -ListDevices
```

## State File Changes

### Schema version

Bump `$STATE_SCHEMA_VERSION` from `2` to `3`. Older script versions loading a v3 state file will ignore the `allowedPorts` field (no crash, just no port filtering). Newer script versions loading a v2 state file will treat missing `allowedPorts` as empty list.

### Current device object (v2)

```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "ip": "192.168.8.21",
  "hostname": "fileserver.local",
  "vendor": "Dell Inc.",
  "label": "File server",
  "firstSeen": "2026-03-20T...",
  "lastSeen": "2026-03-23T...",
  "approvedBy": "DOMAIN\\admin",
  "approvedAt": "2026-03-20T..."
}
```

### New device object (v3, added field)

```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "ip": "192.168.8.21",
  "hostname": "fileserver.local",
  "vendor": "Dell Inc.",
  "label": "File server",
  "firstSeen": "2026-03-20T...",
  "lastSeen": "2026-03-23T...",
  "approvedBy": "DOMAIN\\admin",
  "approvedAt": "2026-03-20T...",
  "allowedPorts": [
    { "port": 3389, "allowedBy": "DOMAIN\\admin", "allowedAt": "2026-03-23T..." },
    { "port": 22, "allowedBy": "DOMAIN\\admin", "allowedAt": "2026-03-23T..." }
  ]
}
```

Backward compatible: devices without `allowedPorts` are treated as having an empty list.

## Scan Logic Changes

### Data flow: when allowedPorts are applied

The port allowlist is applied **after** enrichment and **after** baseline matching — not during `Invoke-DeviceEnrichment`. The flow:

1. `Invoke-DeviceEnrichment` runs as before (port scan, risk calculation on ALL open ports)
2. Normal scan loop matches found devices to baseline (`$state.knownDevices`)
3. For known devices: retrieve `allowedPorts` from baseline entry
4. **New step**: filter risk — remove allowed ports from `riskReasons`, recalculate `riskLevel`
5. Risk check loop (currently ~line 1527) only sees non-allowed risks

This means `Get-DeviceRisk` stays unchanged. Instead, a new function `Get-FilteredRisk` (or inline logic) strips allowed ports from the risk result after baseline matching.

### Risk level scope

The port allowlist applies to **all risk levels** (LOW, MEDIUM, HIGH, CRITICAL). Although only HIGH+ currently triggers log/email alerts, the summary report shows all risk levels. Allowed ports are filtered consistently across all levels.

### Risk check (currently ~line 1527)

For each known device with open ports:

1. Check each open port against the device's `allowedPorts` list
2. Port is in `allowedPorts` → **skip** (no warning)
3. Port is NOT in `allowedPorts` → **warn** as before
4. New unexpected port appears → **warn** (this is the key value: allowed ports are explicit, anything new gets flagged)

### Risk level recalculation

After filtering allowed ports, recalculate effective risk level from remaining non-allowed ports only. A device with all risky ports allowed has effective risk level `NONE`.

## Alert Output

Alert commands use `$PSCommandPath` for the full script path (consistent with existing behavior).

### Risk warnings (log + email)

```
RISK [HIGH]: 192.168.8.21 fileserver.local - Remote Desktop exposed (port 3389)
  -> If expected: & "C:\path\to\rogue-device-detector.ps1" -AllowPort 3389 -On "AA:BB:CC:DD:EE:FF"
```

Multiple ports on the same device get individual lines with individual commands for selective approval.

### Rogue device alerts (updated parameter name)

```
ROGUE: AA:BB:CC:DD:EE:FF  192.168.8.215  [Unknown]
  -> Approve: & "C:\path\to\rogue-device-detector.ps1" -ApproveDevice "AA:BB:CC:DD:EE:FF" -Label "<description>"
```

## `-ListDevices` Output

Terse format — shows port numbers only. Per-port audit details (`allowedBy`, `allowedAt`) are in the audit log.

```
Approved devices baseline - C:\path\to\state.json
Last scan : 2026-03-23T08:41:46Z
Devices   : 12
--------------------------------------------------------------------------------
  AA:BB:CC:DD:EE:FF  IP: 192.168.8.21    | fileserver.local | Dell Inc. | Allowed ports: 3389, 22
  BB:CC:DD:EE:FF:00  IP: 192.168.8.26    | getafix.local    | HP Inc.
```

## Audit Log Events

| Event | When | Details |
|-------|------|---------|
| `PORT_ALLOWED` | `-AllowPort` executed | `mac=AA:BB:CC:DD:EE:FF ports=3389,22 allowedBy=DOMAIN\admin` |
| `PORT_BLOCKED` | `-BlockPort` executed | `mac=AA:BB:CC:DD:EE:FF ports=3389 blockedBy=DOMAIN\admin` |
| `DEVICE_APPROVED` | `-ApproveDevice` executed | Unchanged (parameter name updated in details) |
| `DEVICE_REMOVED` | `-RemoveDevice` executed | Unchanged (parameter name updated in details) |
| `RISK_FOUND` | Scan finds non-allowed risky port | Unchanged |

## New Functions

| Function | Purpose |
|----------|---------|
| `Invoke-AllowPort` | Adds port(s) to a device's `allowedPorts` list in state |
| `Invoke-BlockPort` | Removes port(s) from a device's `allowedPorts` list in state |

## Modified Functions

| Function | Change |
|----------|--------|
| `Invoke-ApproveDevice` | Rename references from `-Approve` to `-ApproveDevice` |
| `Invoke-RemoveDevice` | Rename references from `-Remove` to `-RemoveDevice` |
| `Show-Baseline` | Rename to align with `-ListDevices`, show allowed ports |
| `Send-RogueAlert` | Update copy-paste command to use `-ApproveDevice`, add port allow commands for risky rogues |
| `Send-SummaryReport` | Add copy-paste commands for port allowance, update `-ApproveDevice` |
| Main scan loop | After baseline matching, filter allowed ports from risk data before risk check loop |

## Edge Cases

- `-AllowPort` on a device not in baseline → error with message to `-ApproveDevice` first
- `-AllowPort` for a port already allowed → idempotent, update `allowedAt` timestamp
- `-BlockPort` for a port not in the list → warning, no-op
- `-RemoveDevice` for a device with allowed ports → removes everything (device + ports)
- `-AllowPort` without `-On` → PowerShell parameter set error (enforced by parameter sets)
- State file from older version (v2) without `allowedPorts` → treated as empty list, no migration needed
