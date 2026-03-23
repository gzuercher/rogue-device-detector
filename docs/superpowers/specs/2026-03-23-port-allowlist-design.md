# Port Allowlist & Parameter Rename

## Problem

Risk warnings (open ports like RDP, SSH, Telnet, HTTP) are reported on every scan, even for known/approved devices where the ports are intentional. There is no way to acknowledge that a specific port on a specific device is expected. This creates alert fatigue in environments with legitimate services.

Additionally, the current parameter names (`-Approve`, `-Remove`, `-List`) are not self-explanatory.

## Solution

1. Per-device port allowlist stored in state.json
2. Rename parameters to be self-documenting
3. Copy-paste commands in alerts for port approval (same UX pattern as device approval)

## Parameter Changes (Breaking)

| Old | New | Type | Description |
|-----|-----|------|-------------|
| `-Approve "MAC"` | `-ApproveDevice "MAC"` | `[string]` | Add device to baseline |
| `-Remove "MAC"` | `-RemoveDevice "MAC"` | `[string]` | Remove device from baseline |
| `-List` | `-ListDevices` | `[switch]` | Show all approved devices |
| `-Label "Name"` | `-Label "Name"` | `[string]` | Unchanged, used with `-ApproveDevice` |
| — | `-AllowPort 3389,22` | `[int[]]` | Allow port(s) on a device |
| — | `-BlockPort 3389` | `[int[]]` | Revoke port allowance |
| — | `-On "MAC"` | `[string]` | Target device for `-AllowPort` / `-BlockPort` |

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

### Current device object

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

### New device object (added field)

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

### Risk check (currently ~line 1527)

For each known device with open ports:

1. Check each open port against the device's `allowedPorts` list
2. Port is in `allowedPorts` → **skip** (no warning)
3. Port is NOT in `allowedPorts` → **warn** as before
4. New unexpected port appears → **warn** (this is the key value: allowed ports are explicit, anything new gets flagged)

### Risk level calculation

Risk level is recalculated based on **non-allowed ports only**. A device with all risky ports allowed has effective risk level `NONE`.

## Alert Output

### Risk warnings (log + email)

```
RISK [HIGH]: 192.168.8.21 fileserver.local - Remote Desktop exposed (port 3389)
  -> If expected: & "rogue-device-detector.ps1" -AllowPort 3389 -On "AA:BB:CC:DD:EE:FF"
```

Multiple ports on the same device get individual lines with individual commands for selective approval.

### Rogue device alerts (updated parameter name)

```
ROGUE: AA:BB:CC:DD:EE:FF  192.168.8.215  [Unknown]
  -> Approve: & "rogue-device-detector.ps1" -ApproveDevice "AA:BB:CC:DD:EE:FF" -Label "<description>"
```

## `-ListDevices` Output

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
| `Get-DeviceRisk` | Accept `allowedPorts` parameter, exclude allowed ports from risk calculation |
| `Send-RogueAlert` | Update copy-paste command to use `-ApproveDevice` |
| `Send-SummaryReport` | Add copy-paste commands for port allowance, update `-ApproveDevice` |

## Edge Cases

- `-AllowPort` on a device not in baseline → error with message to `-ApproveDevice` first
- `-AllowPort` for a port already allowed → idempotent, update `allowedAt` timestamp
- `-BlockPort` for a port not in the list → warning, no-op
- `-RemoveDevice` for a device with allowed ports → removes everything (device + ports)
- State file from older version without `allowedPorts` → treated as empty list, no migration needed
