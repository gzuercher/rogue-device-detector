#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
.SYNOPSIS
    Pester unit tests for rogue-device-detector.ps1

.DESCRIPTION
    Covers pure-logic functions that require no network access:
      - Get-SubnetInfo         (CIDR parsing)
      - Get-DeviceRisk         (risk evaluation)
      - Get-MacVendor          (OUI lookup)
      - Get-OsGuess            (TTL-based OS fingerprinting)
      - Get-State              (state file loading)
      - Save-State             (state file writing)
      - Get-Configuration      (config loading and overrides)
      - Invoke-ApproveDevice   (baseline management)
      - Invoke-RemoveDevice    (baseline management)
      - Test-IdentityChange    (hostname change detection)
      - Get-AbsentDevices      (absent device detection)
      - Write-AuditLog         (CSV audit log writing)

    Network-dependent functions (Invoke-PingSweep, Get-ArpEntry,
    Resolve-Hostname, Invoke-PortScan, Invoke-UpnpDiscovery) are not
    covered here as they require a live network environment.
#>

BeforeAll {
    # Dot-source the script to load all function definitions.
    # The guard in the script (if $MyInvocation.InvocationName -eq '.') prevents
    # the main body from running during dot-source.
    $script:ScriptPath = Resolve-Path "$PSScriptRoot\..\rogue-device-detector.ps1"
    . $script:ScriptPath
}

# ── Parameter Rename ──────────────────────────────────────────────────────────

Describe 'Parameter Rename' {

    BeforeAll {
        $script:ScriptCmd = Get-Command $script:ScriptPath
    }

    It 'has -ApproveDevice parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('ApproveDevice') | Should -Be $true
    }

    It 'has -RemoveDevice parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('RemoveDevice') | Should -Be $true
    }

    It 'has -ListDevices parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('ListDevices') | Should -Be $true
    }

    It 'has -AllowPort parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('AllowPort') | Should -Be $true
    }

    It 'has -BlockPort parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('BlockPort') | Should -Be $true
    }

    It 'has -On parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('On') | Should -Be $true
    }

    It 'does NOT have old -Approve parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('Approve') | Should -Be $false
    }

    It 'does NOT have old -Remove parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('Remove') | Should -Be $false
    }

    It 'does NOT have old -List parameter' {
        $script:ScriptCmd.Parameters.ContainsKey('List') | Should -Be $false
    }
}

# ── Get-SubnetInfo ─────────────────────────────────────────────────────────────

Describe 'Get-SubnetInfo' {

    It 'parses a /24 subnet: correct NetworkAddress, PrefixLength and HostCount' {
        $result = Get-SubnetInfo -Cidr '192.168.1.0/24'
        $result.NetworkAddress | Should -Be '192.168.1.0'
        $result.PrefixLength   | Should -Be 24
        $result.HostCount      | Should -Be 254
    }

    It 'parses a /16 subnet: HostCount is 65534' {
        $result = Get-SubnetInfo -Cidr '10.0.0.0/16'
        $result.NetworkAddress | Should -Be '10.0.0.0'
        $result.PrefixLength   | Should -Be 16
        $result.HostCount      | Should -Be 65534
    }

    It 'parses a /30 subnet: HostCount is 2' {
        $result = Get-SubnetInfo -Cidr '10.10.10.0/30'
        $result.HostCount | Should -Be 2
    }

    It 'masks the host bits: network address is derived correctly from a host IP' {
        # 192.168.5.42/24 -> network 192.168.5.0
        $result = Get-SubnetInfo -Cidr '192.168.5.42/24'
        $result.NetworkAddress | Should -Be '192.168.5.0'
    }

    It 'throws when CIDR has no prefix length' {
        { Get-SubnetInfo -Cidr '192.168.1.0' } | Should -Throw
    }

    It 'throws when CIDR format is completely invalid' {
        { Get-SubnetInfo -Cidr 'not-a-cidr' } | Should -Throw
    }

    It 'throws for /32 (no usable host addresses)' {
        { Get-SubnetInfo -Cidr '192.168.1.1/32' } | Should -Throw '*not scannable*'
    }

    It 'throws for /31 (no usable host addresses)' {
        { Get-SubnetInfo -Cidr '192.168.1.0/31' } | Should -Throw '*not scannable*'
    }

    It 'throws for invalid prefix length (e.g. /33)' {
        { Get-SubnetInfo -Cidr '192.168.1.0/33' } | Should -Throw '*Invalid prefix*'
    }
}

# ── Get-DeviceRisk ─────────────────────────────────────────────────────────────

Describe 'Get-DeviceRisk' {

    It 'returns NONE with no open ports' {
        $result = Get-DeviceRisk -OpenPorts @()
        $result.Level   | Should -Be 'NONE'
        $result.Reasons | Should -HaveCount 0
    }

    It 'returns NONE for HTTPS only (port 443 is explicitly risk-free)' {
        $result = Get-DeviceRisk -OpenPorts @(443)
        $result.Level | Should -Be 'NONE'
    }

    It 'returns NONE for HTTPS-alt only (port 8443)' {
        $result = Get-DeviceRisk -OpenPorts @(8443)
        $result.Level | Should -Be 'NONE'
    }

    It 'returns LOW for SSH (port 22)' {
        $result = Get-DeviceRisk -OpenPorts @(22)
        $result.Level   | Should -Be 'LOW'
        $result.Reasons | Should -HaveCount 1
    }

    It 'returns LOW for HTTP (port 80)' {
        $result = Get-DeviceRisk -OpenPorts @(80)
        $result.Level | Should -Be 'LOW'
    }

    It 'returns MEDIUM for SMTP (port 25)' {
        $result = Get-DeviceRisk -OpenPorts @(25)
        $result.Level | Should -Be 'MEDIUM'
    }

    It 'returns HIGH for FTP (port 21)' {
        $result = Get-DeviceRisk -OpenPorts @(21)
        $result.Level   | Should -Be 'HIGH'
        $result.Reasons | Should -HaveCount 1
    }

    It 'returns HIGH for SMB (port 445)' {
        $result = Get-DeviceRisk -OpenPorts @(445)
        $result.Level | Should -Be 'HIGH'
    }

    It 'returns HIGH for RDP (port 3389)' {
        $result = Get-DeviceRisk -OpenPorts @(3389)
        $result.Level | Should -Be 'HIGH'
    }

    It 'returns CRITICAL for Telnet (port 23)' {
        $result = Get-DeviceRisk -OpenPorts @(23)
        $result.Level   | Should -Be 'CRITICAL'
        $result.Reasons | Should -HaveCount 1
        $result.Reasons[0] | Should -Match 'Telnet'
    }

    It 'worst risk wins: Telnet + SSH -> CRITICAL with 2 reasons' {
        $result = Get-DeviceRisk -OpenPorts @(22, 23)
        $result.Level   | Should -Be 'CRITICAL'
        $result.Reasons | Should -HaveCount 2
    }

    It 'worst risk wins: FTP + SSH -> HIGH' {
        $result = Get-DeviceRisk -OpenPorts @(21, 22)
        $result.Level | Should -Be 'HIGH'
    }

    It 'ignores unknown ports gracefully' {
        $result = Get-DeviceRisk -OpenPorts @(9999, 12345)
        $result.Level   | Should -Be 'NONE'
        $result.Reasons | Should -HaveCount 0
    }

    It 'includes port number in reason text' {
        $result = Get-DeviceRisk -OpenPorts @(21)
        $result.Reasons[0] | Should -Match '\(port 21\)'
    }

    It 'skips NONE-risk ports when building reasons: HTTPS adds no reason' {
        $result = Get-DeviceRisk -OpenPorts @(22, 443)
        $result.Reasons | Should -HaveCount 1   # only SSH
    }
}

# ── Get-MacVendor ──────────────────────────────────────────────────────────────

Describe 'Get-MacVendor' {

    It 'returns Unknown for an empty OUI database' {
        $result = Get-MacVendor -Mac 'AA:BB:CC:DD:EE:FF' -OuiDb @{}
        $result | Should -Be 'Unknown'
    }

    It 'returns the vendor name for a known prefix' {
        $db     = @{ 'AABBCC' = 'Acme Networking' }
        $result = Get-MacVendor -Mac 'AA:BB:CC:DD:EE:FF' -OuiDb $db
        $result | Should -Be 'Acme Networking'
    }

    It 'returns Unknown for an unrecognised prefix' {
        $db     = @{ '112233' = 'Some Vendor' }
        $result = Get-MacVendor -Mac 'AA:BB:CC:DD:EE:FF' -OuiDb $db
        $result | Should -Be 'Unknown'
    }

    It 'is case-insensitive for the MAC input (lowercase colons)' {
        $db     = @{ 'AABBCC' = 'Acme Networking' }
        $result = Get-MacVendor -Mac 'aa:bb:cc:dd:ee:ff' -OuiDb $db
        $result | Should -Be 'Acme Networking'
    }

    It 'handles dash-separated MAC addresses' {
        $db     = @{ 'AABBCC' = 'Acme Networking' }
        $result = Get-MacVendor -Mac 'AA-BB-CC-DD-EE-FF' -OuiDb $db
        $result | Should -Be 'Acme Networking'
    }

    It 'handles MAC without separators' {
        $db     = @{ 'AABBCC' = 'Acme Networking' }
        $result = Get-MacVendor -Mac 'AABBCCDDEEFF' -OuiDb $db
        $result | Should -Be 'Acme Networking'
    }
}

# ── Get-OsGuess ───────────────────────────────────────────────────────────────

Describe 'Get-OsGuess' {

    It 'returns empty string for TTL 0 or negative' {
        Get-OsGuess -Ttl 0  | Should -Be ''
        Get-OsGuess -Ttl -1 | Should -Be ''
    }

    It 'returns Linux/macOS for TTL 64' {
        Get-OsGuess -Ttl 64 | Should -Be 'Linux/macOS'
    }

    It 'returns Linux/macOS for TTL below 64 (hops reduce TTL)' {
        Get-OsGuess -Ttl 58 | Should -Be 'Linux/macOS'
    }

    It 'returns Windows for TTL 128' {
        Get-OsGuess -Ttl 128 | Should -Be 'Windows'
    }

    It 'returns Windows for TTL between 65 and 128 (e.g. 120)' {
        Get-OsGuess -Ttl 120 | Should -Be 'Windows'
    }

    It 'returns Network device for TTL 255' {
        Get-OsGuess -Ttl 255 | Should -Be 'Network device'
    }

    It 'returns Network device for TTL above 128 (e.g. 250)' {
        Get-OsGuess -Ttl 250 | Should -Be 'Network device'
    }
}

# ── Test-IdentityChange ──────────────────────────────────────────────────────

Describe 'Test-IdentityChange' {

    It 'returns previous hostname when hostname changed' {
        $known = [PSCustomObject]@{ hostname = 'LAPTOP-JOHN'; ip = '192.168.1.10' }
        $found = [PSCustomObject]@{ hostname = 'DESKTOP-ADMIN'; ip = '192.168.1.10' }
        $result = Test-IdentityChange -KnownDevice $known -FoundDevice $found
        $result | Should -Be 'LAPTOP-JOHN'
    }

    It 'returns $null when hostname has not changed' {
        $known = [PSCustomObject]@{ hostname = 'LAPTOP-JOHN'; ip = '192.168.1.10' }
        $found = [PSCustomObject]@{ hostname = 'LAPTOP-JOHN'; ip = '192.168.1.10' }
        $result = Test-IdentityChange -KnownDevice $known -FoundDevice $found
        $result | Should -BeNullOrEmpty
    }

    It 'ignores changes where old hostname was an IP address (DNS flapping)' {
        $known = [PSCustomObject]@{ hostname = '192.168.1.10'; ip = '192.168.1.10' }
        $found = [PSCustomObject]@{ hostname = 'LAPTOP-NEW'; ip = '192.168.1.10' }
        $result = Test-IdentityChange -KnownDevice $known -FoundDevice $found
        $result | Should -BeNullOrEmpty
    }

    It 'returns $null when known hostname is empty' {
        $known = [PSCustomObject]@{ hostname = ''; ip = '192.168.1.10' }
        $found = [PSCustomObject]@{ hostname = 'LAPTOP-NEW'; ip = '192.168.1.10' }
        $result = Test-IdentityChange -KnownDevice $known -FoundDevice $found
        $result | Should -BeNullOrEmpty
    }

    It 'detects change when hostname changes to an IP (DNS stopped resolving)' {
        $known = [PSCustomObject]@{ hostname = 'LAPTOP-JOHN'; ip = '192.168.1.10' }
        $found = [PSCustomObject]@{ hostname = '192.168.1.10'; ip = '192.168.1.10' }
        $result = Test-IdentityChange -KnownDevice $known -FoundDevice $found
        $result | Should -Be 'LAPTOP-JOHN'
    }
}

# ── Get-AbsentDevices ─────────────────────────────────────────────────────────

Describe 'Get-AbsentDevices' {

    It 'returns devices not seen for more than the threshold' {
        $now = '2024-06-01T00:00:00Z'
        $devices = @(
            [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF'; lastSeen = '2024-05-01T00:00:00Z' },
            [PSCustomObject]@{ mac = '11:22:33:44:55:66'; lastSeen = '2024-05-30T00:00:00Z' }
        )
        $result = Get-AbsentDevices -KnownDevices $devices -AbsentDays 21 -Now $now
        $result | Should -HaveCount 1
        $result[0].mac | Should -Be 'AA:BB:CC:DD:EE:FF'
    }

    It 'returns empty array when all devices were seen recently' {
        $now = '2024-06-01T00:00:00Z'
        $devices = @(
            [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF'; lastSeen = '2024-05-30T00:00:00Z' }
        )
        $result = Get-AbsentDevices -KnownDevices $devices -AbsentDays 21 -Now $now
        $result | Should -HaveCount 0
    }

    It 'skips devices with no lastSeen value' {
        $now = '2024-06-01T00:00:00Z'
        $devices = @(
            [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF'; lastSeen = '' },
            [PSCustomObject]@{ mac = '11:22:33:44:55:66'; lastSeen = $null }
        )
        $result = Get-AbsentDevices -KnownDevices $devices -AbsentDays 21 -Now $now
        $result | Should -HaveCount 0
    }

    It 'uses the absentDays threshold correctly at the boundary' {
        $now = '2024-06-01T00:00:00Z'
        # Exactly 21 days ago = not absent yet (needs to be MORE than 21 days)
        $devices = @(
            [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF'; lastSeen = '2024-05-11T00:00:00Z' }
        )
        $result = Get-AbsentDevices -KnownDevices $devices -AbsentDays 21 -Now $now
        $result | Should -HaveCount 0
    }

    It 'returns all absent devices when multiple are past threshold' {
        $now = '2024-06-01T00:00:00Z'
        $devices = @(
            [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF'; lastSeen = '2024-04-01T00:00:00Z' },
            [PSCustomObject]@{ mac = '11:22:33:44:55:66'; lastSeen = '2024-03-15T00:00:00Z' },
            [PSCustomObject]@{ mac = 'CC:DD:EE:FF:00:11'; lastSeen = '2024-05-30T00:00:00Z' }
        )
        $result = Get-AbsentDevices -KnownDevices $devices -AbsentDays 21 -Now $now
        $result | Should -HaveCount 2
    }
}

# ── Get-State ──────────────────────────────────────────────────────────────────

Describe 'Get-State' {

    It 'returns empty state when file does not exist' {
        $path   = Join-Path $TestDrive 'nonexistent-state.json'
        $result = Get-State -StatePath $path

        $result.lastScan            | Should -BeNullOrEmpty
        @($result.knownDevices)     | Should -HaveCount 0
    }

    It 'loads an existing state file with one device' {
        $path  = Join-Path $TestDrive 'valid-state.json'
        [PSCustomObject]@{
            lastScan     = '2024-01-01T00:00:00.0000000Z'
            knownDevices = @(
                [PSCustomObject]@{
                    mac      = 'AA:BB:CC:DD:EE:FF'
                    ip       = '192.168.1.100'
                    hostname = 'test-pc'
                }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content $path

        $result = Get-State -StatePath $path
        $result.lastScan            | Should -Be '2024-01-01T00:00:00.0000000Z'
        @($result.knownDevices)     | Should -HaveCount 1
        $result.knownDevices[0].mac | Should -Be 'AA:BB:CC:DD:EE:FF'
    }

    It 'adds osGuess field to devices from older state files' {
        $path = Join-Path $TestDrive 'old-state.json'
        [PSCustomObject]@{
            lastScan     = '2024-01-01T00:00:00.0000000Z'
            knownDevices = @(
                [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.1' }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content $path

        $result = Get-State -StatePath $path
        $result.knownDevices[0].osGuess | Should -Be ''
    }

    It 'replaces null knownDevices with an empty array' {
        $path = Join-Path $TestDrive 'null-devices-state.json'
        '{ "lastScan": "2024-01-01T00:00:00Z", "knownDevices": null }' | Set-Content $path

        $result = Get-State -StatePath $path
        # Pester 5 enumerates empty arrays in the pipeline, so Should receives $null
        # rather than the array object itself. Test the null-ness as a scalar boolean.
        ($null -eq $result.knownDevices) | Should -BeFalse
        $result.knownDevices.Count       | Should -Be 0
    }
}

# ── Save-State / Get-State round-trip ─────────────────────────────────────────

Describe 'Save-State / Get-State round-trip' {

    It 'persists and reloads all device fields correctly' {
        $path  = Join-Path $TestDrive 'roundtrip-state.json'
        $state = [PSCustomObject]@{
            lastScan     = '2024-06-15T12:00:00.0000000Z'
            knownDevices = @(
                [PSCustomObject]@{
                    mac        = 'AA:BB:CC:DD:EE:FF'
                    ip         = '192.168.1.1'
                    hostname   = 'router.local'
                    vendor     = 'Cisco'
                    label      = 'Main router'
                    firstSeen  = '2024-01-01T00:00:00.0000000Z'
                    lastSeen   = '2024-06-15T12:00:00.0000000Z'
                    approvedBy = 'DOMAIN\admin'
                    approvedAt = '2024-01-01T00:00:00.0000000Z'
                }
            )
        }

        Save-State -State $state -StatePath $path
        $loaded = Get-State -StatePath $path

        $loaded.lastScan                   | Should -Be '2024-06-15T12:00:00.0000000Z'
        @($loaded.knownDevices)            | Should -HaveCount 1
        $loaded.knownDevices[0].mac        | Should -Be 'AA:BB:CC:DD:EE:FF'
        $loaded.knownDevices[0].vendor     | Should -Be 'Cisco'
        $loaded.knownDevices[0].label      | Should -Be 'Main router'
        $loaded.knownDevices[0].approvedBy | Should -Be 'DOMAIN\admin'
    }

    It 'produces valid UTF-8 encoded JSON' {
        $path  = Join-Path $TestDrive 'encoding-state.json'
        $state = [PSCustomObject]@{
            lastScan     = '2024-01-01T00:00:00Z'
            knownDevices = @(
                [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF'; label = 'Küche-PC' }
            )
        }

        Save-State -State $state -StatePath $path

        # File must exist and parse cleanly
        { Get-Content $path -Raw | ConvertFrom-Json } | Should -Not -Throw
        $raw = Get-Content $path -Encoding UTF8 -Raw
        $raw | Should -Match 'Küche-PC'
    }
}

# ── Invoke-ApproveDevice ───────────────────────────────────────────────────────

Describe 'Invoke-ApproveDevice' {

    It 'adds a new device to an empty baseline' {
        $state = [PSCustomObject]@{ lastScan = $null; knownDevices = @() }
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:FF' -Label 'Test device' `
                             -State $state -Now '2024-01-01T00:00:00Z'

        @($state.knownDevices)       | Should -HaveCount 1
        $state.knownDevices[0].mac   | Should -Be 'AA:BB:CC:DD:EE:FF'
        $state.knownDevices[0].label | Should -Be 'Test device'
    }

    It 'normalises dash-separated lowercase MAC to colon-separated uppercase' {
        $state = [PSCustomObject]@{ lastScan = $null; knownDevices = @() }
        Invoke-ApproveDevice -Mac 'aa-bb-cc-dd-ee-ff' -State $state -Now '2024-01-01T00:00:00Z'

        $state.knownDevices[0].mac | Should -Be 'AA:BB:CC:DD:EE:FF'
    }

    It 'normalises lowercase colon-separated MAC to uppercase' {
        $state = [PSCustomObject]@{ lastScan = $null; knownDevices = @() }
        Invoke-ApproveDevice -Mac 'aa:bb:cc:dd:ee:ff' -State $state -Now '2024-01-01T00:00:00Z'

        $state.knownDevices[0].mac | Should -Be 'AA:BB:CC:DD:EE:FF'
    }

    It 'updates label and approvedAt when device already exists in baseline' {
        $now   = '2024-01-01T00:00:00Z'
        $later = '2024-06-01T00:00:00Z'
        $state = [PSCustomObject]@{
            lastScan     = $null
            knownDevices = @(
                [PSCustomObject]@{
                    mac        = 'AA:BB:CC:DD:EE:FF'
                    ip         = '192.168.1.100'
                    hostname   = 'old-host'
                    vendor     = 'Vendor'
                    label      = 'Old label'
                    firstSeen  = $now
                    lastSeen   = $now
                    approvedBy = 'old-user'
                    approvedAt = $now
                }
            )
        }

        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:FF' -Label 'New label' `
                             -State $state -Now $later

        @($state.knownDevices)       | Should -HaveCount 1   # not duplicated
        $state.knownDevices[0].label | Should -Be 'New label'
        $state.knownDevices[0].approvedAt | Should -Be $later
    }

    It 'sets firstSeen and lastSeen to Now for new devices' {
        $now   = '2024-03-17T08:00:00Z'
        $state = [PSCustomObject]@{ lastScan = $null; knownDevices = @() }
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:FF' -State $state -Now $now

        $state.knownDevices[0].firstSeen | Should -Be $now
        $state.knownDevices[0].lastSeen  | Should -Be $now
    }

    It 'throws on invalid MAC address (too short)' {
        $state = [PSCustomObject]@{ lastScan = $null; knownDevices = @() }
        { Invoke-ApproveDevice -Mac 'AA:BB:CC' -State $state -Now '2024-01-01T00:00:00Z' } |
            Should -Throw
    }

    It 'throws on MAC that is not hex (letters out of range)' {
        $state = [PSCustomObject]@{ lastScan = $null; knownDevices = @() }
        { Invoke-ApproveDevice -Mac 'ZZ:ZZ:ZZ:ZZ:ZZ:ZZ' -State $state -Now '2024-01-01T00:00:00Z' } |
            Should -Throw
    }
}

# ── Invoke-RemoveDevice ────────────────────────────────────────────────────────

Describe 'Invoke-RemoveDevice' {

    It 'removes an existing device and returns $true' {
        $state = [PSCustomObject]@{
            lastScan     = $null
            knownDevices = @( [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF' } )
        }

        $result = Invoke-RemoveDevice -Mac 'AA:BB:CC:DD:EE:FF' -State $state

        $result                | Should -Be $true
        @($state.knownDevices) | Should -HaveCount 0
    }

    It 'returns $false when device is not in baseline' {
        $state = [PSCustomObject]@{ lastScan = $null; knownDevices = @() }

        $result = Invoke-RemoveDevice -Mac 'AA:BB:CC:DD:EE:FF' -State $state
        $result | Should -Be $false
    }

    It 'normalises MAC before comparison (dashes, lowercase)' {
        $state = [PSCustomObject]@{
            lastScan     = $null
            knownDevices = @( [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF' } )
        }

        $result = Invoke-RemoveDevice -Mac 'aa-bb-cc-dd-ee-ff' -State $state
        $result                | Should -Be $true
        @($state.knownDevices) | Should -HaveCount 0
    }

    It 'only removes the matching device, leaving others intact' {
        $state = [PSCustomObject]@{
            lastScan     = $null
            knownDevices = @(
                [PSCustomObject]@{ mac = 'AA:BB:CC:DD:EE:FF' },
                [PSCustomObject]@{ mac = '11:22:33:44:55:66' }
            )
        }

        Invoke-RemoveDevice -Mac 'AA:BB:CC:DD:EE:FF' -State $state

        @($state.knownDevices)     | Should -HaveCount 1
        $state.knownDevices[0].mac | Should -Be '11:22:33:44:55:66'
    }
}

# ── Get-Configuration ─────────────────────────────────────────────────────────

Describe 'Get-Configuration' {

    It 'returns defaults when config file does not exist' {
        $result = Get-Configuration -ConfigPath (Join-Path $TestDrive 'nonexistent.json')

        $result.subnet        | Should -BeNullOrEmpty
        $result.enrichment    | Should -Be $true
        $result.absentDays    | Should -Be 21
        $result.summaryReport | Should -Be $false
        $result.smtp.port     | Should -Be 587
        $result.smtp.host     | Should -BeNullOrEmpty
    }

    It 'loads absentDays and summaryReport from config file' {
        $configPath = Join-Path $TestDrive 'absent-config.json'
        @{ absentDays = 7; summaryReport = $true } |
            ConvertTo-Json | Set-Content $configPath

        $result = Get-Configuration -ConfigPath $configPath
        $result.absentDays    | Should -Be 7
        $result.summaryReport | Should -Be $true
    }

    It 'loads subnet and enrichment from a valid config file' {
        $configPath = Join-Path $TestDrive 'valid-config.json'
        @{ subnet = '10.0.0.0/24'; enrichment = $false } |
            ConvertTo-Json | Set-Content $configPath

        $result = Get-Configuration -ConfigPath $configPath
        $result.subnet     | Should -Be '10.0.0.0/24'
        $result.enrichment | Should -Be $false
    }

    It 'loads SMTP settings from config file' {
        $configPath = Join-Path $TestDrive 'smtp-config.json'
        @{
            smtp = @{
                host = 'smtp.example.com'
                port = 465
                to   = 'admin@example.com'
                from = 'rdd@example.com'
            }
        } | ConvertTo-Json | Set-Content $configPath

        $result = Get-Configuration -ConfigPath $configPath
        $result.smtp.host | Should -Be 'smtp.example.com'
        $result.smtp.port | Should -Be 465
        $result.smtp.to   | Should -Be 'admin@example.com'
        $result.smtp.from | Should -Be 'rdd@example.com'
    }

    It 'SubnetOverride takes precedence over config file subnet' {
        $configPath = Join-Path $TestDrive 'override-config.json'
        @{ subnet = '10.0.0.0/24' } | ConvertTo-Json | Set-Content $configPath

        $result = Get-Configuration -ConfigPath $configPath -SubnetOverride '192.168.99.0/24'
        $result.subnet | Should -Be '192.168.99.0/24'
    }

    It 'SubnetOverride works even when config has no subnet' {
        $configPath = Join-Path $TestDrive 'no-subnet-config.json'
        @{ enrichment = $true } | ConvertTo-Json | Set-Content $configPath

        $result = Get-Configuration -ConfigPath $configPath -SubnetOverride '172.16.0.0/12'
        $result.subnet | Should -Be '172.16.0.0/12'
    }

    It 'continues with defaults and does not throw when JSON is malformed' {
        $configPath = Join-Path $TestDrive 'bad-config.json'
        'this is { not valid json }}}' | Set-Content $configPath

        { Get-Configuration -ConfigPath $configPath } | Should -Not -Throw

        $result = Get-Configuration -ConfigPath $configPath
        $result.enrichment | Should -Be $true
        $result.smtp.port  | Should -Be 587
    }
}

# ── Write-AuditLog ─────────────────────────────────────────────────────────────

Describe 'Write-AuditLog' {

    It 'creates the log file with a header row on first use' {
        $logPath = Join-Path $TestDrive 'audit-new.csv'

        Write-AuditLog -LogPath $logPath -Event 'SCAN_START' -Details 'subnet=192.168.1.0/24'

        Test-Path $logPath | Should -Be $true
        $lines = Get-Content $logPath
        $lines[0] | Should -Match 'Timestamp'
        $lines[0] | Should -Match 'Event'
        $lines[0] | Should -Match 'MAC'
    }

    It 'appends event rows without overwriting the header' {
        $logPath = Join-Path $TestDrive 'audit-append.csv'

        Write-AuditLog -LogPath $logPath -Event 'SCAN_START'
        Write-AuditLog -LogPath $logPath -Event 'SCAN_DONE' -Details 'found=3'

        $lines = Get-Content $logPath
        $lines.Count | Should -Be 3   # header + 2 events
        $lines[1]    | Should -Match 'SCAN_START'
        $lines[2]    | Should -Match 'SCAN_DONE'
    }

    It 'writes device MAC and IP when a device object is supplied' {
        $logPath = Join-Path $TestDrive 'audit-device.csv'
        $device  = [PSCustomObject]@{
            mac        = 'AA:BB:CC:DD:EE:FF'
            ip         = '192.168.1.99'
            hostname   = 'rogue-pc'
            vendor     = 'Acme'
            openPorts  = @(22, 23)
            riskLevel  = 'CRITICAL'
        }

        Write-AuditLog -LogPath $logPath -Event 'DEVICE_ROGUE' -Device $device

        $content = Get-Content $logPath -Raw
        $content | Should -Match 'AA:BB:CC:DD:EE:FF'
        $content | Should -Match '192\.168\.1\.99'
        $content | Should -Match 'CRITICAL'
    }

    It 'escapes double-quotes in the Details field per CSV spec' {
        $logPath = Join-Path $TestDrive 'audit-escape.csv'

        Write-AuditLog -LogPath $logPath -Event 'SCAN_START' -Details 'label="test"'

        $content = Get-Content $logPath -Raw
        # CSV escaping: " becomes ""
        $content | Should -Match '""test""'
    }

    It 'does not throw when called without a device object' {
        $logPath = Join-Path $TestDrive 'audit-nodevice.csv'
        { Write-AuditLog -LogPath $logPath -Event 'SCAN_START' } | Should -Not -Throw
    }
}

# ── Test-PathWritable ──────────────────────────────────────────────────────────

Describe 'Test-PathWritable' {

    It 'returns $true for a writable path' {
        $path = Join-Path $TestDrive 'writable-test.txt'
        Test-PathWritable -FilePath $path | Should -Be $true
    }

    It 'returns $true for an existing writable file' {
        $path = Join-Path $TestDrive 'existing-file.txt'
        'content' | Set-Content $path
        Test-PathWritable -FilePath $path | Should -Be $true
    }

    It 'creates parent directories if they do not exist' {
        $path = Join-Path $TestDrive 'subdir/deep/writable-test.txt'
        Test-PathWritable -FilePath $path | Should -Be $true
        Test-Path (Split-Path $path -Parent) | Should -Be $true
    }
}

# ── Get-State (v1.3.0 schema version) ────────────────────────────────────────

Describe 'Get-State schema version' {

    It 'returns schemaVersion in empty state' {
        $path   = Join-Path $TestDrive 'new-state.json'
        $result = Get-State -StatePath $path
        $result.schemaVersion | Should -Be $STATE_SCHEMA_VERSION
    }

    It 'adds schemaVersion to legacy state files' {
        $path = Join-Path $TestDrive 'legacy-state.json'
        [PSCustomObject]@{
            lastScan     = '2024-01-01T00:00:00Z'
            knownDevices = @()
        } | ConvertTo-Json -Depth 5 | Set-Content $path

        $result = Get-State -StatePath $path
        $result.schemaVersion | Should -Be $STATE_SCHEMA_VERSION
    }

    It 'preserves existing schemaVersion from state file' {
        $path = Join-Path $TestDrive 'versioned-state.json'
        [PSCustomObject]@{
            schemaVersion = 99
            lastScan      = '2024-01-01T00:00:00Z'
            knownDevices  = @()
        } | ConvertTo-Json -Depth 5 | Set-Content $path

        $result = Get-State -StatePath $path
        $result.schemaVersion | Should -Be 99
    }
}

# ── Enter-ScanLock / Exit-ScanLock ────────────────────────────────────────────

Describe 'Enter-ScanLock / Exit-ScanLock' {

    It 'acquires a lock and returns a FileStream' {
        $statePath = Join-Path $TestDrive 'lock-test-state.json'
        $lock = Enter-ScanLock -StatePath $statePath
        try {
            $lock | Should -Not -BeNullOrEmpty
            $lock | Should -BeOfType [System.IO.FileStream]
            Test-Path "$statePath.lock" | Should -Be $true
        } finally {
            Exit-ScanLock -LockStream $lock -StatePath $statePath
        }
    }

    It 'Exit-ScanLock removes the lock file' {
        $statePath = Join-Path $TestDrive 'lock-cleanup-state.json'
        $lock = Enter-ScanLock -StatePath $statePath
        Exit-ScanLock -LockStream $lock -StatePath $statePath
        Test-Path "$statePath.lock" | Should -Be $false
    }

    It 'returns $null when lock is already held' {
        $statePath = Join-Path $TestDrive 'lock-contention-state.json'
        $lock1 = Enter-ScanLock -StatePath $statePath
        try {
            $lock2 = Enter-ScanLock -StatePath $statePath
            $lock2 | Should -BeNullOrEmpty
        } finally {
            Exit-ScanLock -LockStream $lock1 -StatePath $statePath
        }
    }

    It 'Exit-ScanLock handles $null stream gracefully' {
        $statePath = Join-Path $TestDrive 'lock-null-state.json'
        { Exit-ScanLock -LockStream $null -StatePath $statePath } | Should -Not -Throw
    }
}
