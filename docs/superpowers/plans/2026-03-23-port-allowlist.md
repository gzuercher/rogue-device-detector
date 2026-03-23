# Port Allowlist & Parameter Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-device port allowlist to suppress known risk warnings, rename CLI parameters for clarity, and bump state schema to v3.

**Architecture:** Extend existing baseline management with `allowedPorts` per device. Port filtering happens after enrichment and baseline matching. New parameter sets enforce valid CLI combinations. All changes in a single file (`rogue-device-detector.ps1`) plus tests.

**Tech Stack:** PowerShell, Pester 5

**Spec:** `docs/superpowers/specs/2026-03-23-port-allowlist-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `rogue-device-detector.ps1` | Modify | All production changes (params, functions, scan logic, alerts) |
| `tests/rogue-device-detector.Tests.ps1` | Modify | Add tests for new functions and param renames |

---

### Task 1: Rename parameters and update parameter sets

**Files:**
- Modify: `rogue-device-detector.ps1` (lines 62-70, param block)
- Modify: `rogue-device-detector.ps1` (lines 1342-1366, management commands section)
- Modify: `tests/rogue-device-detector.Tests.ps1` (update existing tests referencing old param names)

- [ ] **Step 1: Write failing tests for new parameter names**

Add to `tests/rogue-device-detector.Tests.ps1`:

```powershell
Describe 'Parameter Rename' {

    It 'has -ApproveDevice parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Contain 'ApproveDevice'
    }

    It 'has -RemoveDevice parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Contain 'RemoveDevice'
    }

    It 'has -ListDevices parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Contain 'ListDevices'
    }

    It 'has -AllowPort parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Contain 'AllowPort'
    }

    It 'has -BlockPort parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Contain 'BlockPort'
    }

    It 'has -On parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Contain 'On'
    }

    It 'does NOT have old -Approve parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Not -Contain 'Approve'
    }

    It 'does NOT have old -Remove parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Not -Contain 'Remove'
    }

    It 'does NOT have old -List parameter' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters.Keys | Should -Not -Contain 'List'
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Update param block**

Replace the current param block (lines 62-70) with:

```powershell
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(ParameterSetName = 'Scan')]
    [string]$Config = '',

    [Parameter(ParameterSetName = 'Scan')]
    [string]$Subnet = '',

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$LearningMode,

    [Parameter(Mandatory, ParameterSetName = 'ApproveDevice')]
    [string]$ApproveDevice = '',

    [Parameter(ParameterSetName = 'ApproveDevice')]
    [string]$Label = '',

    [Parameter(Mandatory, ParameterSetName = 'RemoveDevice')]
    [string]$RemoveDevice = '',

    [Parameter(ParameterSetName = 'ListDevices')]
    [switch]$ListDevices,

    [Parameter(Mandatory, ParameterSetName = 'AllowPort')]
    [int[]]$AllowPort,

    [Parameter(Mandatory, ParameterSetName = 'BlockPort')]
    [int[]]$BlockPort,

    [Parameter(Mandatory, ParameterSetName = 'AllowPort')]
    [Parameter(Mandatory, ParameterSetName = 'BlockPort')]
    [string]$On
)
```

- [ ] **Step 4: Update management commands section (lines ~1342-1366)**

Replace references to old parameter names:
- `$List` → `$ListDevices`
- `$Approve` → `$ApproveDevice`
- `$Remove` → `$RemoveDevice`

Also update audit log details strings and the comment-based help at the top of the script.

- [ ] **Step 5: Update existing tests that reference old parameter names**

Search tests for `Invoke-ApproveDevice`, `Invoke-RemoveDevice` — these function names stay the same, only the script parameters change. Update any test that invokes the script with old params.

- [ ] **Step 6: Run tests, verify new param tests pass**

- [ ] **Step 7: Commit**

```bash
git commit -m "refactor: rename CLI parameters for clarity (breaking change)

-Approve -> -ApproveDevice, -Remove -> -RemoveDevice, -List -> -ListDevices.
Adds -AllowPort, -BlockPort, -On parameters with parameter sets.
No backward-compatible aliases."
```

---

### Task 2: Add Invoke-AllowPort and Invoke-BlockPort functions

**Files:**
- Modify: `rogue-device-detector.ps1` (add after Invoke-RemoveDevice, ~line 1031)
- Modify: `tests/rogue-device-detector.Tests.ps1`

- [ ] **Step 1: Write failing tests**

```powershell
Describe 'Invoke-AllowPort' {

    BeforeEach {
        $script:state = [PSCustomObject]@{
            schemaVersion = 3
            knownDevices  = @(
                [PSCustomObject]@{
                    mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.10'
                    hostname = 'server'; vendor = 'Dell'; label = 'File server'
                    firstSeen = '2026-01-01T00:00:00Z'; lastSeen = '2026-03-23T00:00:00Z'
                    approvedBy = 'DOMAIN\admin'; approvedAt = '2026-01-01T00:00:00Z'
                    allowedPorts = @()
                }
            )
            lastScan = '2026-03-23T00:00:00Z'
        }
    }

    It 'adds a single port to allowedPorts' {
        Invoke-AllowPort -Ports @(3389) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T10:00:00Z'
        $device = $script:state.knownDevices[0]
        $device.allowedPorts | Should -HaveCount 1
        $device.allowedPorts[0].port | Should -Be 3389
    }

    It 'adds multiple ports at once' {
        Invoke-AllowPort -Ports @(3389, 22) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T10:00:00Z'
        $device = $script:state.knownDevices[0]
        $device.allowedPorts | Should -HaveCount 2
    }

    It 'is idempotent — re-allowing updates timestamp' {
        Invoke-AllowPort -Ports @(3389) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T10:00:00Z'
        Invoke-AllowPort -Ports @(3389) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T12:00:00Z'
        $device = $script:state.knownDevices[0]
        $device.allowedPorts | Should -HaveCount 1
        $device.allowedPorts[0].allowedAt | Should -Be '2026-03-23T12:00:00Z'
    }

    It 'throws if device not in baseline' {
        { Invoke-AllowPort -Ports @(3389) -Mac '11:22:33:44:55:66' -State $script:state -Now '2026-03-23T10:00:00Z' } |
            Should -Throw '*not found in baseline*'
    }

    It 'records allowedBy with current user' {
        Invoke-AllowPort -Ports @(22) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T10:00:00Z'
        $device = $script:state.knownDevices[0]
        $device.allowedPorts[0].allowedBy | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-BlockPort' {

    BeforeEach {
        $script:state = [PSCustomObject]@{
            schemaVersion = 3
            knownDevices  = @(
                [PSCustomObject]@{
                    mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.10'
                    hostname = 'server'; vendor = 'Dell'; label = ''
                    firstSeen = '2026-01-01T00:00:00Z'; lastSeen = '2026-03-23T00:00:00Z'
                    approvedBy = ''; approvedAt = ''
                    allowedPorts = @(
                        [PSCustomObject]@{ port = 3389; allowedBy = 'DOMAIN\admin'; allowedAt = '2026-03-23T00:00:00Z' },
                        [PSCustomObject]@{ port = 22;   allowedBy = 'DOMAIN\admin'; allowedAt = '2026-03-23T00:00:00Z' }
                    )
                }
            )
            lastScan = '2026-03-23T00:00:00Z'
        }
    }

    It 'removes an allowed port' {
        Invoke-BlockPort -Ports @(3389) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state
        $device = $script:state.knownDevices[0]
        $device.allowedPorts | Should -HaveCount 1
        $device.allowedPorts[0].port | Should -Be 22
    }

    It 'removes multiple ports at once' {
        Invoke-BlockPort -Ports @(3389, 22) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state
        $device = $script:state.knownDevices[0]
        $device.allowedPorts | Should -HaveCount 0
    }

    It 'is a no-op for ports not in the list (no error)' {
        Invoke-BlockPort -Ports @(80) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state
        $device = $script:state.knownDevices[0]
        $device.allowedPorts | Should -HaveCount 2
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement Invoke-AllowPort**

Add after `Invoke-RemoveDevice` in `rogue-device-detector.ps1`:

```powershell
function Invoke-AllowPort {
    <#
    .SYNOPSIS
        Adds port(s) to a device's allowedPorts list in the baseline.
    .PARAMETER Ports  Port numbers to allow.
    .PARAMETER Mac    MAC address of the target device.
    .PARAMETER State  State object loaded from state.json.
    .PARAMETER Now    ISO timestamp string.
    #>
    param(
        [Parameter(Mandatory)][int[]]$Ports,
        [Parameter(Mandatory)][string]$Mac,
        [Parameter(Mandatory)][PSCustomObject]$State,
        [Parameter(Mandatory)][string]$Now
    )

    $mac = ($Mac -replace '[^0-9A-Fa-f]', '') -replace '(.{2})(?!$)', '$1:'
    $mac = $mac.ToUpper()

    $device = @($State.knownDevices) | Where-Object { $_.mac -eq $mac } | Select-Object -First 1
    if (-not $device) {
        throw "Device $mac not found in baseline. Use -ApproveDevice first."
    }

    # Initialize allowedPorts if missing (v2 state file)
    if (-not $device.PSObject.Properties['allowedPorts'] -or $null -eq $device.allowedPorts) {
        $device | Add-Member -NotePropertyName 'allowedPorts' -NotePropertyValue @() -Force
    }

    foreach ($port in $Ports) {
        $existing = @($device.allowedPorts) | Where-Object { $_.port -eq $port } | Select-Object -First 1
        if ($existing) {
            $existing.allowedAt = $Now
            $existing.allowedBy = "$env:USERDOMAIN\$env:USERNAME"
            Write-RddLog "Updated port $port allowance on $mac."
        } else {
            $device.allowedPorts = @($device.allowedPorts) + @([PSCustomObject]@{
                port      = $port
                allowedBy = "$env:USERDOMAIN\$env:USERNAME"
                allowedAt = $Now
            })
            Write-RddLog "Allowed port $port on $mac."
        }
    }
}

function Invoke-BlockPort {
    <#
    .SYNOPSIS
        Removes port(s) from a device's allowedPorts list in the baseline.
    .PARAMETER Ports  Port numbers to revoke.
    .PARAMETER Mac    MAC address of the target device.
    .PARAMETER State  State object loaded from state.json.
    #>
    param(
        [Parameter(Mandatory)][int[]]$Ports,
        [Parameter(Mandatory)][string]$Mac,
        [Parameter(Mandatory)][PSCustomObject]$State
    )

    $mac = ($Mac -replace '[^0-9A-Fa-f]', '') -replace '(.{2})(?!$)', '$1:'
    $mac = $mac.ToUpper()

    $device = @($State.knownDevices) | Where-Object { $_.mac -eq $mac } | Select-Object -First 1
    if (-not $device) {
        Write-RddLog "Device $mac not found in baseline." -Level WARN
        return
    }

    if (-not $device.PSObject.Properties['allowedPorts'] -or $null -eq $device.allowedPorts) {
        Write-RddLog "Device $mac has no allowed ports." -Level WARN
        return
    }

    $before = @($device.allowedPorts).Count
    $device.allowedPorts = @($device.allowedPorts | Where-Object { $_.port -notin $Ports })
    $after = @($device.allowedPorts).Count
    $removed = $before - $after

    if ($removed -gt 0) {
        Write-RddLog "Blocked $removed port(s) on $mac: $($Ports -join ', ')"
    } else {
        Write-RddLog "Port(s) $($Ports -join ', ') not in allowed list for $mac." -Level WARN
    }
}
```

- [ ] **Step 4: Wire up management commands for -AllowPort and -BlockPort**

Add after the existing `$RemoveDevice` block in the management commands section:

```powershell
if ($AllowPort) {
    $state = Get-State -StatePath $cfg.statePath
    $now   = (Get-Date).ToUniversalTime().ToString('o')
    Invoke-AllowPort -Ports $AllowPort -Mac $On -State $state -Now $now
    Save-State -State $state -StatePath $cfg.statePath
    Write-AuditLog -LogPath $cfg.logPath -EventName 'PORT_ALLOWED' `
        -Details "mac=$On ports=$($AllowPort -join ',') allowedBy=$env:USERDOMAIN\$env:USERNAME"
    exit 0
}

if ($BlockPort) {
    $state = Get-State -StatePath $cfg.statePath
    Invoke-BlockPort -Ports $BlockPort -Mac $On -State $state
    Save-State -State $state -StatePath $cfg.statePath
    Write-AuditLog -LogPath $cfg.logPath -EventName 'PORT_BLOCKED' `
        -Details "mac=$On ports=$($BlockPort -join ',') blockedBy=$env:USERDOMAIN\$env:USERNAME"
    exit 0
}
```

- [ ] **Step 5: Run tests, verify all pass**

- [ ] **Step 6: Commit**

```bash
git commit -m "feat: add Invoke-AllowPort and Invoke-BlockPort functions

Per-device port allowlist management. Ports are stored in allowedPorts
array on each device in state.json. Includes CLI wiring and audit logging."
```

---

### Task 3: Bump schema version and add allowedPorts to device creation

**Files:**
- Modify: `rogue-device-detector.ps1` (line 80: schema version, device object creation in learning mode and Invoke-ApproveDevice)
- Modify: `tests/rogue-device-detector.Tests.ps1`

- [ ] **Step 1: Write failing test**

```powershell
Describe 'State Schema v3' {

    It 'uses schema version 3' {
        $STATE_SCHEMA_VERSION | Should -Be 3
    }

    It 'new devices from Invoke-ApproveDevice include allowedPorts field' {
        $state = [PSCustomObject]@{ schemaVersion = 3; knownDevices = @(); lastScan = '' }
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:FF' -State $state -Now '2026-03-23T00:00:00Z'
        $device = $state.knownDevices[0]
        $device.PSObject.Properties.Name | Should -Contain 'allowedPorts'
        $device.allowedPorts | Should -HaveCount 0
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Bump schema version**

Change line 80 from `$STATE_SCHEMA_VERSION = 2` to `$STATE_SCHEMA_VERSION = 3`.

- [ ] **Step 4: Add allowedPorts to new device creation**

In `Invoke-ApproveDevice`, add `allowedPorts = @()` to the new device object (line ~989).
In the learning mode loop, add `allowedPorts = @()` to the device object (search for `firstSeen  = $now` in the learning mode block).

- [ ] **Step 5: Run tests, verify pass**

- [ ] **Step 6: Commit**

```bash
git commit -m "feat: bump state schema to v3, add allowedPorts to device objects

New devices now include an empty allowedPorts array. Older v2 state files
are handled gracefully (missing field treated as empty list)."
```

---

### Task 4: Filter allowed ports from risk warnings in scan logic

**Files:**
- Modify: `rogue-device-detector.ps1` (risk check loop ~line 1527, and report construction ~line 1561)
- Modify: `tests/rogue-device-detector.Tests.ps1`

- [ ] **Step 1: Write failing tests**

```powershell
Describe 'Allowed port filtering in scan' {

    It 'excludes allowed ports from riskReasons' {
        # Simulate a device with port 3389 open and allowed
        $device = [PSCustomObject]@{
            mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.10'; hostname = 'server'
            openPorts = @(3389, 445); riskLevel = 'HIGH'
            riskReasons = @('Remote Desktop exposed (port 3389)', 'File sharing exposed (ransomware vector) (port 445)')
        }
        $allowedPorts = @([PSCustomObject]@{ port = 3389; allowedBy = 'admin'; allowedAt = '2026-03-23T00:00:00Z' })

        $filtered = Get-FilteredRisk -Device $device -AllowedPorts $allowedPorts
        $filtered.Reasons | Should -HaveCount 1
        $filtered.Reasons[0] | Should -BeLike '*445*'
    }

    It 'returns NONE risk level when all risky ports are allowed' {
        $device = [PSCustomObject]@{
            mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.10'; hostname = 'server'
            openPorts = @(3389); riskLevel = 'HIGH'
            riskReasons = @('Remote Desktop exposed (port 3389)')
        }
        $allowedPorts = @([PSCustomObject]@{ port = 3389; allowedBy = 'admin'; allowedAt = '2026-03-23T00:00:00Z' })

        $filtered = Get-FilteredRisk -Device $device -AllowedPorts $allowedPorts
        $filtered.Level | Should -Be 'NONE'
        $filtered.Reasons | Should -HaveCount 0
    }

    It 'passes through all risks when no ports are allowed' {
        $device = [PSCustomObject]@{
            mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.10'; hostname = 'server'
            openPorts = @(3389, 22); riskLevel = 'HIGH'
            riskReasons = @('Remote Desktop exposed (port 3389)', 'Remote access (SSH) (port 22)')
        }

        $filtered = Get-FilteredRisk -Device $device -AllowedPorts @()
        $filtered.Reasons | Should -HaveCount 2
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement Get-FilteredRisk function**

Add after `Get-DeviceRisk`:

```powershell
function Get-FilteredRisk {
    <#
    .SYNOPSIS
        Recalculates risk after removing allowed ports from the device's risk data.
    .PARAMETER Device       Device object with openPorts, riskLevel, riskReasons.
    .PARAMETER AllowedPorts Array of allowedPort objects (with .port property).
    .RETURNS PSCustomObject with Level (string) and Reasons (string array).
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$Device,
        [array]$AllowedPorts = @()
    )

    if ($AllowedPorts.Count -eq 0) {
        return [PSCustomObject]@{ Level = $Device.riskLevel; Reasons = $Device.riskReasons }
    }

    $allowedPortNumbers = @($AllowedPorts | ForEach-Object { $_.port })
    $remainingPorts = @($Device.openPorts | Where-Object { $_ -notin $allowedPortNumbers })

    # Recalculate risk from remaining ports only
    return Get-DeviceRisk -OpenPorts $remainingPorts
}
```

- [ ] **Step 4: Integrate into scan loop**

In the risk check loop (after baseline matching, ~line 1527), before checking risk level, look up `allowedPorts` from the baseline and filter:

```powershell
# Replace the current risk check loop with:
$riskDevices = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($device in $foundDevices) {
    # Look up baseline entry for allowed ports
    $known = @($state.knownDevices) | Where-Object { $_.mac -eq $device.mac } | Select-Object -First 1
    $allowedPorts = if ($known -and $known.PSObject.Properties['allowedPorts']) {
        @($known.allowedPorts)
    } else { @() }

    # Filter allowed ports from risk
    $filtered = Get-FilteredRisk -Device $device -AllowedPorts $allowedPorts
    $device.riskLevel   = $filtered.Level
    $device.riskReasons = $filtered.Reasons

    if ($RISK_ORDER[$device.riskLevel] -ge $RISK_ORDER['HIGH']) {
        $isRogue = $rogueDevices | Where-Object { $_.mac -eq $device.mac }
        if (-not $isRogue) {
            Write-RddLog "RISK [$($device.riskLevel)]: $($device.ip) $($device.hostname) - $($device.riskReasons -join '; ')" -Level WARN
            Write-AuditLog -LogPath $cfg.logPath -EventName 'RISK_FOUND' -Device $device `
                -Details ($device.riskReasons -join '; ')
            $riskDevices.Add($device)
        }
    }
}
```

- [ ] **Step 5: Run tests, verify pass**

- [ ] **Step 6: Commit**

```bash
git commit -m "feat: filter allowed ports from risk warnings during scan

Adds Get-FilteredRisk function. Known devices with allowed ports no longer
trigger risk warnings for those specific ports. New unexpected ports still
get flagged."
```

---

### Task 5: Update alert messages and -ListDevices output

**Files:**
- Modify: `rogue-device-detector.ps1` (Send-RogueAlert, Send-SummaryReport, Show-Baseline)
- Modify: `tests/rogue-device-detector.Tests.ps1`

- [ ] **Step 1: Update Send-RogueAlert**

Change the copy-paste command from `-Approve` to `-ApproveDevice`:

```powershell
# In Send-RogueAlert, update line ~914:
$lines.Add("     & `"$scriptPath`" -ApproveDevice `"$($d.mac)`" -Label `"<device description>`"")
```

- [ ] **Step 2: Update Send-SummaryReport**

Change the approve command from `-Approve` to `-ApproveDevice` (line ~1166).

Add per-port allow commands in the risk findings section:

```powershell
# In the risk findings section (~line 1180-1186), update to:
if ($Report.riskDevices.Count -gt 0) {
    $lines.Add('')
    $lines.Add('--- Risk Findings (known devices) ---')
    $scriptPath = $PSCommandPath
    foreach ($d in $Report.riskDevices) {
        $lines.Add("  [$($d.riskLevel)] $($d.ip) ($($d.hostname)) - $($d.riskReasons -join '; ')")
        # Add per-port allow commands
        foreach ($reason in $d.riskReasons) {
            if ($reason -match '\(port (\d+)\)') {
                $port = $Matches[1]
                $lines.Add("    -> If expected: & `"$scriptPath`" -AllowPort $port -On `"$($d.mac)`"")
            }
        }
    }
}
```

- [ ] **Step 3: Update Show-Baseline to show allowed ports**

In Show-Baseline, add allowed ports display after the existing device info:

```powershell
# Add after $lastSeen line (~1065):
$allowedPortsStr = if ($d.PSObject.Properties['allowedPorts'] -and $d.allowedPorts.Count -gt 0) {
    " | Allowed ports: $(($d.allowedPorts | ForEach-Object { $_.port }) -join ', ')"
} else { '' }
# Include $allowedPortsStr in the Write-Host line
```

- [ ] **Step 4: Update comment-based help at the top of the script**

Update the `.PARAMETER` and `.EXAMPLE` sections to reflect new parameter names.

- [ ] **Step 5: Run all tests**

- [ ] **Step 6: Commit**

```bash
git commit -m "feat: update alerts and list output for new parameter names and port allowlist

Rogue alerts use -ApproveDevice. Risk findings include per-port -AllowPort
commands. -ListDevices shows allowed ports per device."
```

---

### Task 6: Run full test suite and verify zero PSScriptAnalyzer violations

**Files:** None (verification only)

- [ ] **Step 1: Run full Pester suite**

Run: `pwsh -NoProfile -Command "Invoke-Pester ./tests/ -Output Detailed"`

Expected: All tests pass.

- [ ] **Step 2: Run PSScriptAnalyzer with custom rules**

Run: `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./rogue-device-detector.ps1 -Severity Error,Warning -ExcludeRule PSAvoidUsingWriteHost -CustomRulePath ./rules/ | Format-Table RuleName, Line, Message -AutoSize"`

Expected: No output (zero violations, including zero Measure-UnsafeCountAccess warnings).

- [ ] **Step 3: Commit if any fixes were needed**
