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

# ── Get-OsLabel ────────────────────────────────────────────────────────────────

Describe 'Get-OsLabel' {

    It 'extracts distro from OpenSSH banner' {
        Get-OsLabel -SshBanner 'SSH-2.0-OpenSSH_9.6 Ubuntu-22.04' | Should -Match 'Ubuntu'
    }

    It 'extracts Debian from OpenSSH banner with hyphen' {
        Get-OsLabel -SshBanner 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3' | Should -Match 'Debian'
    }

    It 'identifies dropbear-based devices' {
        Get-OsLabel -SshBanner 'SSH-2.0-dropbear_2022.83' | Should -Match 'Dropbear'
    }

    It 'extracts Ubuntu from HTTP server-with-parens header' {
        Get-OsLabel -HttpBanner 'Title | Server: nginx/1.24.0 (Ubuntu)' | Should -Be 'Ubuntu'
    }

    It 'identifies vendor from telnet banner' {
        Get-OsLabel -TelnetBanner 'Welcome to Cisco IOS XE Software' | Should -Be 'Cisco'
    }

    It 'falls back to TTL guess when no banner is informative' {
        Get-OsLabel -TtlGuess 'Linux/macOS' -SshBanner 'SSH-2.0-Custom_1.0' | Should -Be 'Linux/macOS'
    }

    It 'returns empty when nothing is known' {
        Get-OsLabel | Should -Be ''
    }
}

# ── Get-RelativeAge ────────────────────────────────────────────────────────────

Describe 'Get-RelativeAge' {

    BeforeAll {
        $script:fixedNow = [datetime]'2026-05-05T12:00:00Z'
    }

    It 'returns "today" for an event a few hours ago' {
        Get-RelativeAge -IsoTimestamp '2026-05-05T03:00:00Z' -Now $script:fixedNow | Should -Be 'today'
    }

    It 'returns "yesterday" for ~30 hours ago' {
        Get-RelativeAge -IsoTimestamp '2026-05-04T06:00:00Z' -Now $script:fixedNow | Should -Be 'yesterday'
    }

    It 'returns "N days ago" for several days back' {
        Get-RelativeAge -IsoTimestamp '2026-05-01T00:00:00Z' -Now $script:fixedNow | Should -Match '^\d+ days ago$'
    }

    It 'returns absolute date for events older than 14 days' {
        Get-RelativeAge -IsoTimestamp '2026-04-01T00:00:00Z' -Now $script:fixedNow | Should -Be '2026-04-01'
    }

    It 'returns empty string for empty input' {
        Get-RelativeAge -IsoTimestamp '' -Now $script:fixedNow | Should -Be ''
    }

    It 'returns the original string on parse failure' {
        Get-RelativeAge -IsoTimestamp 'not-a-date' -Now $script:fixedNow | Should -Be 'not-a-date'
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

    It 'accepts an empty baseline and returns nothing' {
        $now = '2024-06-01T00:00:00Z'
        $result = @(Get-AbsentDevices -KnownDevices @() -AbsentDays 21 -Now $now)
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

        $result.subnet         | Should -BeNullOrEmpty
        $result.enrichment     | Should -Be $true
        $result.absentDays     | Should -Be 21
        $result.summaryReport  | Should -Be $false
        $result.alertRiskLevel | Should -Be 'HIGH'
        $result.smtp.port      | Should -Be 587
        $result.smtp.host      | Should -BeNullOrEmpty
    }

    It 'loads alertRiskLevel from config and uppercases it' {
        $configPath = Join-Path $TestDrive 'alert-level-config.json'
        @{ alertRiskLevel = 'medium' } | ConvertTo-Json | Set-Content $configPath
        $result = Get-Configuration -ConfigPath $configPath
        $result.alertRiskLevel | Should -Be 'MEDIUM'
    }

    It 'falls back to default when alertRiskLevel is invalid' {
        $configPath = Join-Path $TestDrive 'alert-level-bad.json'
        @{ alertRiskLevel = 'EXTREME' } | ConvertTo-Json | Set-Content $configPath
        $result = Get-Configuration -ConfigPath $configPath
        $result.alertRiskLevel | Should -Be 'HIGH'
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

    It 'does not throw for a baseline device lacking openPorts/riskLevel (DEVICE_ABSENT regression)' {
        # Stored knownDevices objects have no openPorts/riskLevel properties.
        # Under Set-StrictMode -Version Latest, accessing a missing property throws
        # PropertyNotFoundException - this reproduces the DEVICE_ABSENT crash.
        $logPath = Join-Path $TestDrive 'audit-absent.csv'
        $absent  = [PSCustomObject]@{
            mac      = 'AA:BB:CC:11:22:33'
            ip       = '192.168.8.50'
            hostname = 'old-laptop'
            vendor   = 'Acme'
            label    = 'Reception'
            lastSeen = '2026-01-01T00:00:00Z'
        }

        { Write-AuditLog -LogPath $logPath -Event 'DEVICE_ABSENT' -Device $absent } |
            Should -Not -Throw

        $content = Get-Content $logPath -Raw
        $content | Should -Match 'DEVICE_ABSENT'
        $content | Should -Match 'AA:BB:CC:11:22:33'
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

# ── Invoke-AllowPort ──────────────────────────────────────────────────────────

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
        @($device.allowedPorts) | Should -HaveCount 1
        @($device.allowedPorts)[0].port | Should -Be 3389
    }

    It 'adds multiple ports at once' {
        Invoke-AllowPort -Ports @(3389, 22) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T10:00:00Z'
        $device = $script:state.knownDevices[0]
        @($device.allowedPorts) | Should -HaveCount 2
    }

    It 'is idempotent — re-allowing updates timestamp' {
        Invoke-AllowPort -Ports @(3389) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T10:00:00Z'
        Invoke-AllowPort -Ports @(3389) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T12:00:00Z'
        $device = $script:state.knownDevices[0]
        @($device.allowedPorts) | Should -HaveCount 1
        @($device.allowedPorts)[0].allowedAt | Should -Be '2026-03-23T12:00:00Z'
    }

    It 'throws if device not in baseline' {
        { Invoke-AllowPort -Ports @(3389) -Mac '11:22:33:44:55:66' -State $script:state -Now '2026-03-23T10:00:00Z' } |
            Should -Throw '*not found in baseline*'
    }

    It 'records allowedBy with current user' {
        Invoke-AllowPort -Ports @(22) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state -Now '2026-03-23T10:00:00Z'
        $device = $script:state.knownDevices[0]
        @($device.allowedPorts)[0].allowedBy | Should -Not -BeNullOrEmpty
    }
}

# ── Invoke-BlockPort ──────────────────────────────────────────────────────────

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
        @($device.allowedPorts) | Should -HaveCount 1
        @($device.allowedPorts)[0].port | Should -Be 22
    }

    It 'removes multiple ports at once' {
        Invoke-BlockPort -Ports @(3389, 22) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state
        $device = $script:state.knownDevices[0]
        @($device.allowedPorts) | Should -HaveCount 0
    }

    It 'is a no-op for ports not in the list (no error)' {
        Invoke-BlockPort -Ports @(80) -Mac 'AA:BB:CC:DD:EE:FF' -State $script:state
        $device = $script:state.knownDevices[0]
        @($device.allowedPorts) | Should -HaveCount 2
    }
}

# ── State Schema v5 ────────────────────────────────────────────────────────────

Describe 'State Schema v5' {

    It 'uses schema version 5' {
        $STATE_SCHEMA_VERSION | Should -Be 5
    }

    It 'new devices from Invoke-ApproveDevice include allowedPorts and aliases fields' {
        $state = [PSCustomObject]@{ schemaVersion = 5; knownDevices = @(); seenRogues = @(); lastScan = '' }
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:FF' -State $state -Now '2026-03-23T00:00:00Z'
        $device = $state.knownDevices[0]
        $device.PSObject.Properties.Name | Should -Contain 'allowedPorts'
        $device.PSObject.Properties.Name | Should -Contain 'aliases'
        @($device.allowedPorts) | Should -HaveCount 0
        @($device.aliases)      | Should -HaveCount 0
    }

    It 'Get-State migrates a v3 file by adding seenRogues' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "rdd-state-v3-$([guid]::NewGuid()).json"
        try {
            $v3 = @{ schemaVersion = 3; lastScan = ''; knownDevices = @() } | ConvertTo-Json
            Set-Content $tmp -Value $v3 -Encoding UTF8
            $state = Get-State -StatePath $tmp
            $state.PSObject.Properties.Name | Should -Contain 'seenRogues'
            @($state.seenRogues) | Should -HaveCount 0
        } finally {
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    }

    It 'Invoke-ApproveDevice removes the MAC from seenRogues' {
        $state = [PSCustomObject]@{
            schemaVersion = 5
            knownDevices  = @()
            seenRogues    = @(
                [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:FF'; firstSeen='2026-04-01'; lastSeen='2026-05-01' }
                [PSCustomObject]@{ mac='11:22:33:44:55:66'; firstSeen='2026-04-15'; lastSeen='2026-05-01' }
            )
            lastScan = ''
        }
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:FF' -State $state -Now '2026-05-05T00:00:00Z'
        @($state.seenRogues).Count | Should -Be 1
        @($state.seenRogues)[0].mac | Should -Be '11:22:33:44:55:66'
    }

    It 'Get-State migrates a v4 file by adding empty aliases per device' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "rdd-state-v4-$([guid]::NewGuid()).json"
        try {
            $v4 = @{
                schemaVersion = 4
                lastScan      = ''
                knownDevices  = @(@{ mac='AA:BB:CC:DD:EE:FF'; ip=''; hostname=''; vendor=''; label=''; firstSeen=''; lastSeen=''; approvedBy=''; approvedAt=''; allowedPorts=@() })
                seenRogues    = @()
            } | ConvertTo-Json -Depth 6
            Set-Content $tmp -Value $v4 -Encoding UTF8
            $state = Get-State -StatePath $tmp
            $state.knownDevices[0].PSObject.Properties.Name | Should -Contain 'aliases'
            @($state.knownDevices[0].aliases) | Should -HaveCount 0
        } finally {
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    }
}

# ── Aliases ────────────────────────────────────────────────────────────────────

Describe 'Find-KnownDevice' {

    BeforeEach {
        $script:state = [PSCustomObject]@{
            schemaVersion = 5
            knownDevices  = @(
                [PSCustomObject]@{
                    mac = 'AA:BB:CC:DD:EE:01'; ip='192.168.1.10'; hostname='nb-laptop-01'; vendor=''
                    label='Notebook 01'; firstSeen=''; lastSeen=''; approvedBy=''; approvedAt=''
                    allowedPorts=@(); aliases=@('AA:BB:CC:DD:EE:02')
                }
            )
            seenRogues = @()
            lastScan   = ''
        }
    }

    It 'matches the primary MAC' {
        $r = Find-KnownDevice -State $script:state -Mac 'AA:BB:CC:DD:EE:01'
        $r.MatchType | Should -Be 'primary'
        $r.Device.mac | Should -Be 'AA:BB:CC:DD:EE:01'
    }

    It 'matches an alias MAC and returns the same logical device' {
        $r = Find-KnownDevice -State $script:state -Mac 'AA:BB:CC:DD:EE:02'
        $r.MatchType | Should -Be 'alias'
        $r.Device.mac | Should -Be 'AA:BB:CC:DD:EE:01'
    }

    It 'is case-insensitive on the MAC' {
        (Find-KnownDevice -State $script:state -Mac 'aa:bb:cc:dd:ee:02').MatchType | Should -Be 'alias'
    }

    It 'returns MatchType=none when nothing matches' {
        (Find-KnownDevice -State $script:state -Mac 'FF:FF:FF:FF:FF:FF').MatchType | Should -Be 'none'
    }
}

Describe 'Invoke-ApproveDevice -AliasOf' {

    BeforeEach {
        $script:state = [PSCustomObject]@{
            schemaVersion = 5
            knownDevices  = @(
                [PSCustomObject]@{
                    mac = 'AA:BB:CC:DD:EE:01'; ip=''; hostname='nb-laptop-01'; vendor=''
                    label='Notebook 01'; firstSeen=''; lastSeen=''; approvedBy=''; approvedAt=''
                    allowedPorts=@(); aliases=@()
                }
            )
            seenRogues = @()
            lastScan   = ''
        }
    }

    It 'attaches the new MAC as alias of the primary' {
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:02' -AliasOf 'AA:BB:CC:DD:EE:01' `
            -State $script:state -Now '2026-05-06T00:00:00Z'
        @($script:state.knownDevices).Count | Should -Be 1
        @($script:state.knownDevices[0].aliases) | Should -Contain 'AA:BB:CC:DD:EE:02'
    }

    It 'is idempotent — re-aliasing the same MAC does not duplicate' {
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:02' -AliasOf 'AA:BB:CC:DD:EE:01' `
            -State $script:state -Now '2026-05-06T00:00:00Z'
        Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:02' -AliasOf 'AA:BB:CC:DD:EE:01' `
            -State $script:state -Now '2026-05-06T00:00:00Z'
        @($script:state.knownDevices[0].aliases) | Should -HaveCount 1
    }

    It 'throws when the primary MAC is unknown' {
        { Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:02' -AliasOf 'FF:FF:FF:FF:FF:FF' `
            -State $script:state -Now '2026-05-06T00:00:00Z' } | Should -Throw
    }

    It 'throws when MAC is already a primary device' {
        $script:state.knownDevices += [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:99'; ip=''; hostname=''; vendor=''; label=''
            firstSeen=''; lastSeen=''; approvedBy=''; approvedAt=''
            allowedPorts=@(); aliases=@()
        }
        { Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:99' -AliasOf 'AA:BB:CC:DD:EE:01' `
            -State $script:state -Now '2026-05-06T00:00:00Z' } | Should -Throw
    }

    It 'throws when alias would point to itself' {
        { Invoke-ApproveDevice -Mac 'AA:BB:CC:DD:EE:01' -AliasOf 'AA:BB:CC:DD:EE:01' `
            -State $script:state -Now '2026-05-06T00:00:00Z' } | Should -Throw
    }
}

Describe 'Invoke-RemoveDevice with alias' {

    BeforeEach {
        $script:state = [PSCustomObject]@{
            schemaVersion = 5
            knownDevices  = @(
                [PSCustomObject]@{
                    mac='AA:BB:CC:DD:EE:01'; ip=''; hostname='nb-laptop-01'; vendor=''
                    label=''; firstSeen=''; lastSeen=''; approvedBy=''; approvedAt=''
                    allowedPorts=@(); aliases=@('AA:BB:CC:DD:EE:02')
                }
            )
            seenRogues = @()
            lastScan   = ''
        }
    }

    It 'removing an alias MAC keeps the primary device' {
        $removed = Invoke-RemoveDevice -Mac 'AA:BB:CC:DD:EE:02' -State $script:state
        $removed | Should -BeTrue
        @($script:state.knownDevices).Count | Should -Be 1
        @($script:state.knownDevices[0].aliases) | Should -HaveCount 0
    }

    It 'removing the primary MAC drops the entire entry incl. aliases' {
        $removed = Invoke-RemoveDevice -Mac 'AA:BB:CC:DD:EE:01' -State $script:state
        $removed | Should -BeTrue
        @($script:state.knownDevices) | Should -HaveCount 0
    }
}

Describe 'Invoke-AllowPort by alias MAC' {

    It 'looks up the device via alias and adds the port' {
        $state = [PSCustomObject]@{
            schemaVersion = 5
            knownDevices  = @(
                [PSCustomObject]@{
                    mac='AA:BB:CC:DD:EE:01'; ip=''; hostname=''; vendor=''; label=''
                    firstSeen=''; lastSeen=''; approvedBy=''; approvedAt=''
                    allowedPorts=@(); aliases=@('AA:BB:CC:DD:EE:02')
                }
            )
            seenRogues=@(); lastScan=''
        }
        Invoke-AllowPort -Ports @(3389) -Mac 'AA:BB:CC:DD:EE:02' `
            -State $state -Now '2026-05-06T00:00:00Z'
        @($state.knownDevices[0].allowedPorts) | Should -HaveCount 1
        $state.knownDevices[0].allowedPorts[0].port | Should -Be 3389
    }
}

Describe 'Get-AliasMatchCandidates' {

    It 'flags an exact normalised hostname match' {
        $rogue = [PSCustomObject]@{ mac='ZZ:ZZ:ZZ:ZZ:ZZ:ZZ'; hostname='NB-LAPTOP-01.local' }
        $known = @(
            [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:01'; hostname='nb-laptop-01'; label='' }
            [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:02'; hostname='printer';      label='' }
        )
        $cands = @(Get-AliasMatchCandidates -Rogue $rogue -KnownDevices $known)
        $cands | Should -HaveCount 1
        $cands[0].IsExact   | Should -BeTrue
        $cands[0].Device.mac | Should -Be 'AA:BB:CC:DD:EE:01'
    }

    It 'returns prefix-similar candidates ranked by common-prefix length' {
        $rogue = [PSCustomObject]@{ mac='ZZ:ZZ:ZZ:ZZ:ZZ:ZZ'; hostname='nb-laptop-99' }
        $known = @(
            [PSCustomObject]@{ mac='M:01'; hostname='nb-laptop-01'; label='' }
            [PSCustomObject]@{ mac='M:02'; hostname='nb-server-02'; label='' }
            [PSCustomObject]@{ mac='M:03'; hostname='printer';      label='' }
        )
        $cands = @(Get-AliasMatchCandidates -Rogue $rogue -KnownDevices $known -Top 3)
        $cands | Should -HaveCount 2
        $cands[0].Device.mac | Should -Be 'M:01'   # longer common prefix wins
        $cands[1].Device.mac | Should -Be 'M:02'
    }

    It 'returns nothing when rogue has no resolvable hostname (just an IP)' {
        $rogue = [PSCustomObject]@{ mac='ZZ:ZZ:ZZ:ZZ:ZZ:ZZ'; hostname='192.168.1.50' }
        $known = @([PSCustomObject]@{ mac='AA'; hostname='nb-laptop-01'; label='' })
        @(Get-AliasMatchCandidates -Rogue $rogue -KnownDevices $known) | Should -HaveCount 0
    }

    It 'ignores common prefixes shorter than 3 characters' {
        $rogue = [PSCustomObject]@{ mac='ZZ:ZZ:ZZ:ZZ:ZZ:ZZ'; hostname='ab-thing' }
        $known = @([PSCustomObject]@{ mac='AA'; hostname='ax-other'; label='' })
        @(Get-AliasMatchCandidates -Rogue $rogue -KnownDevices $known) | Should -HaveCount 0
    }
}

# ── Get-FilteredRisk ─────────────────────────────────────────────────────────

Describe 'Get-FilteredRisk' {

    It 'excludes allowed ports from riskReasons' {
        $device = [PSCustomObject]@{
            mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.10'; hostname = 'server'
            openPorts = @(3389, 445); riskLevel = 'HIGH'
            riskReasons = @('Remote Desktop exposed (port 3389)', 'File sharing exposed (ransomware vector) (port 445)')
        }
        $allowedPorts = @([PSCustomObject]@{ port = 3389; allowedBy = 'admin'; allowedAt = '2026-03-23T00:00:00Z' })

        $filtered = Get-FilteredRisk -Device $device -AllowedPorts $allowedPorts
        @($filtered.Reasons) | Should -HaveCount 1
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
        @($filtered.Reasons) | Should -HaveCount 0
    }

    It 'passes through all risks when no ports are allowed' {
        $device = [PSCustomObject]@{
            mac = 'AA:BB:CC:DD:EE:FF'; ip = '192.168.1.10'; hostname = 'server'
            openPorts = @(3389, 22); riskLevel = 'HIGH'
            riskReasons = @('Remote Desktop exposed (port 3389)', 'Remote access (SSH) (port 22)')
        }

        $filtered = Get-FilteredRisk -Device $device -AllowedPorts @()
        @($filtered.Reasons) | Should -HaveCount 2
    }
}

# ── Hostname display polish ───────────────────────────────────────────────────

Describe 'Format-DisplayHostname' {

    It 'strips a trailing .local suffix' {
        Format-DisplayHostname -Hostname 'getafix.local' | Should -Be 'getafix'
    }

    It 'strips .LOCAL case-insensitively' {
        Format-DisplayHostname -Hostname 'PRINTER.LOCAL' | Should -Be 'PRINTER'
    }

    It 'tolerates a trailing FQDN dot' {
        Format-DisplayHostname -Hostname 'host.local.' | Should -Be 'host'
    }

    It 'leaves non-mDNS hostnames untouched' {
        Format-DisplayHostname -Hostname 'fileserver'           | Should -Be 'fileserver'
        Format-DisplayHostname -Hostname 'host.corp.example.com' | Should -Be 'host.corp.example.com'
    }

    It 'returns empty string for empty input' {
        Format-DisplayHostname -Hostname '' | Should -Be ''
    }
}

# ── Passive multicast resolver — packet builder ──────────────────────────────

Describe 'New-DnsPtrQueryPacket' {

    It 'produces a 12-byte header + reversed in-addr.arpa QNAME + PTR/IN footer' {
        $bytes = New-DnsPtrQueryPacket -IP '192.168.1.42'
        $bytes | Should -Not -BeNullOrEmpty
        # Header: 12 bytes; Question section: each label length-prefixed,
        # null-terminator, then 2 bytes QTYPE + 2 bytes QCLASS.
        # Labels: "42","1","168","192","in-addr","arpa" = 2+1+3+3+7+4 = 20 chars
        # plus 6 length bytes + 1 null + 4 type/class = 31 bytes after header.
        $bytes.Length | Should -Be 43

        # QTYPE = PTR (0x000C) at the end-4
        $bytes[-4] | Should -Be 0x00
        $bytes[-3] | Should -Be 0x0C
        # Without -UnicastResponseBit, QCLASS high byte is 0x00
        $bytes[-2] | Should -Be 0x00
        $bytes[-1] | Should -Be 0x01
    }

    It 'sets the QU bit when -UnicastResponseBit is given' {
        $bytes = New-DnsPtrQueryPacket -IP '10.0.0.5' -UnicastResponseBit
        $bytes[-2] | Should -Be 0x80
        $bytes[-1] | Should -Be 0x01
    }

    It 'returns $null for a malformed IP' {
        New-DnsPtrQueryPacket -IP 'not-an-ip' | Should -BeNullOrEmpty
    }
}

# ── AXFR helpers ──────────────────────────────────────────────────────────────

Describe 'New-DnsAxfrQueryPacket' {

    It 'builds a query for "corp.example.com" with QTYPE=AXFR and QCLASS=IN' {
        $bytes = New-DnsAxfrQueryPacket -Zone 'corp.example.com'
        $bytes | Should -Not -BeNullOrEmpty
        # Header (12) + labels: 4+7+3 chars + 3 length bytes + null + QTYPE + QCLASS
        # Labels: "corp"(4)+"example"(7)+"com"(3) = 14 chars + 3 length bytes + 1 null = 18
        # Plus 4 trailing (QTYPE+QCLASS) = 22 after header.
        $bytes.Length | Should -Be 34
        # QTYPE = 0x00FC (AXFR)
        $bytes[-4] | Should -Be 0x00
        $bytes[-3] | Should -Be 0xFC
        # QCLASS = 0x0001 (IN)
        $bytes[-2] | Should -Be 0x00
        $bytes[-1] | Should -Be 0x01
    }

    It 'tolerates a trailing dot on the zone' {
        $a = New-DnsAxfrQueryPacket -Zone 'corp.example.com'
        $b = New-DnsAxfrQueryPacket -Zone 'corp.example.com.'
        $a.Length | Should -Be $b.Length
    }

    It 'returns $null for empty zone' {
        New-DnsAxfrQueryPacket -Zone '' | Should -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-DnsAxfrMessage' {

    BeforeAll {
        function New-AxfrMessage {
            # Helper to assemble a valid DNS AXFR-style message in one shot:
            # transaction id 0x1234, response (QR=1) + authoritative, no error.
            # Provide the question section and answer records as raw byte arrays.
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions', '',
                Justification = 'Test fixture builder — returns a byte array, no system state mutated.'
            )]
            param(
                [byte[]]$Question = @(),
                [int]$QdCount = 0,
                [byte[]]$Answers = @(),
                [int]$AnCount = 0,
                [int]$Rcode   = 0
            )
            $flagsHi = 0x84    # QR=1, AA=1
            $flagsLo = $Rcode -band 0x0F
            $qdHi = ($QdCount -shr 8) -band 0xFF
            $qdLo = $QdCount -band 0xFF
            $anHi = ($AnCount -shr 8) -band 0xFF
            $anLo = $AnCount -band 0xFF
            $hdr = @(
                0x12, 0x34,
                $flagsHi, $flagsLo,
                $qdHi, $qdLo,
                $anHi, $anLo,
                0x00, 0x00, 0x00, 0x00
            )
            return ([byte[]]($hdr + $Question + $Answers))
        }

        function New-AxfrARecord {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions', '',
                Justification = 'Test fixture builder — returns a byte array, no system state mutated.'
            )]
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][string]$Ip
            )
            $bytes = [System.Collections.Generic.List[byte]]::new()
            foreach ($lbl in $Name.Split('.')) {
                $b = [System.Text.Encoding]::ASCII.GetBytes($lbl)
                $bytes.Add([byte]$b.Length); $bytes.AddRange($b)
            }
            $bytes.Add(0x00)
            $bytes.AddRange([byte[]](0x00, 0x01))                   # type=A
            $bytes.AddRange([byte[]](0x00, 0x01))                   # class=IN
            $bytes.AddRange([byte[]](0x00, 0x00, 0x01, 0x2C))       # ttl=300
            $bytes.AddRange([byte[]](0x00, 0x04))                   # rdlength=4
            foreach ($oct in $Ip.Split('.')) { $bytes.Add([byte][int]$oct) }
            return $bytes.ToArray()
        }

        function New-AxfrSoaRecord {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions', '',
                Justification = 'Test fixture builder — returns a byte array, no system state mutated.'
            )]
            param()
            $rdata = [byte[]](0..21)
            $bytes = [System.Collections.Generic.List[byte]]::new()
            $bytes.Add(0x00)
            $bytes.AddRange([byte[]](0x00, 0x06))                   # type=SOA
            $bytes.AddRange([byte[]](0x00, 0x01))                   # class=IN
            $bytes.AddRange([byte[]](0x00, 0x00, 0x0E, 0x10))       # ttl=3600
            $rdLenHi = ($rdata.Length -shr 8) -band 0xFF
            $rdLenLo = $rdata.Length -band 0xFF
            $bytes.AddRange([byte[]]($rdLenHi, $rdLenLo))
            $bytes.AddRange($rdata)
            return $bytes.ToArray()
        }
    }

    It 'extracts an A record from a one-shot AXFR message' {
        $a   = New-AxfrARecord -Name 'host1.corp.example.com' -Ip '192.168.1.10'
        $msg = New-AxfrMessage -AnCount 1 -Answers $a
        $r   = ConvertFrom-DnsAxfrMessage -Bytes $msg
        $r.Rcode | Should -Be 0
        $r.SoaCount | Should -Be 0
        @($r.ARecords).Count | Should -Be 1
        $r.ARecords[0].Name | Should -Be 'host1.corp.example.com'
        $r.ARecords[0].IP   | Should -Be '192.168.1.10'
    }

    It 'counts SOA records (start + end markers of an AXFR stream)' {
        $soa  = New-AxfrSoaRecord
        $a    = New-AxfrARecord -Name 'h.corp.example.com' -Ip '10.0.0.1'
        $body = $soa + $a + $soa
        $msg  = New-AxfrMessage -AnCount 3 -Answers $body
        $r = ConvertFrom-DnsAxfrMessage -Bytes $msg
        $r.SoaCount | Should -Be 2
        @($r.ARecords).Count | Should -Be 1
    }

    It 'reports a non-zero rcode (REFUSED) without throwing' {
        $msg = New-AxfrMessage -Rcode 5
        $r   = ConvertFrom-DnsAxfrMessage -Bytes $msg
        $r.Rcode | Should -Be 5
        @($r.ARecords).Count | Should -Be 0
    }

    It 'returns empty result on truncated input' {
        $r = ConvertFrom-DnsAxfrMessage -Bytes ([byte[]](0,0,0))
        $r.Rcode | Should -Be 0
        @($r.ARecords).Count | Should -Be 0
    }

    It 'parses ANCOUNT > 255 correctly (regression: byte-shift overflow)' {
        # Regression for v1.6.2 bug: $byte -shl 8 truncates to 0 because
        # PowerShell preserves the byte type. With ANCOUNT high-byte = 1
        # the count must be 257, not 1.
        $allBytes = [System.Collections.Generic.List[byte]]::new()
        for ($i = 0; $i -lt 257; $i++) {
            $rec = [byte[]](New-AxfrARecord -Name ('h{0}.corp.example.com' -f $i) `
                -Ip "10.0.$([Math]::Floor($i/256)).$($i % 256)")
            $allBytes.AddRange($rec)
        }
        $msg = New-AxfrMessage -AnCount 257 -Answers $allBytes.ToArray()
        $r = ConvertFrom-DnsAxfrMessage -Bytes $msg
        @($r.ARecords).Count | Should -Be 257
    }

    It 'parses RDLENGTH > 255 correctly (regression: byte-shift overflow)' {
        # Build a fake answer record where RDLENGTH high-byte is non-zero
        # (a real-world TXT or SOA can hit this). We don't care about the
        # rdata, only that the parser advances by the full length.
        $name = 'host.corp.example.com'
        $bytes = [System.Collections.Generic.List[byte]]::new()
        foreach ($lbl in $name.Split('.')) {
            $b = [System.Text.Encoding]::ASCII.GetBytes($lbl)
            $bytes.Add([byte]$b.Length); $bytes.AddRange($b)
        }
        $bytes.Add(0x00)
        $bytes.AddRange([byte[]](0x00, 0x10))                   # type=TXT
        $bytes.AddRange([byte[]](0x00, 0x01))                   # class=IN
        $bytes.AddRange([byte[]](0x00, 0x00, 0x01, 0x2C))       # ttl=300
        $bytes.AddRange([byte[]](0x01, 0x00))                   # rdlength=256 (high byte = 1!)
        $bytes.AddRange((New-Object 'byte[]' 256))              # 256 bytes of rdata
        # Append a real A record after, so the parser must skip the TXT correctly
        $aRec = [byte[]](New-AxfrARecord -Name 'after.corp.example.com' -Ip '10.0.0.1')
        $bytes.AddRange($aRec)

        $msg = New-AxfrMessage -AnCount 2 -Answers $bytes.ToArray()
        $r   = ConvertFrom-DnsAxfrMessage -Bytes $msg
        @($r.ARecords).Count | Should -Be 1
        $r.ARecords[0].Name | Should -Be 'after.corp.example.com'
    }
}

Describe 'Get-DnsRcodeName' {

    It 'maps known rcodes to mnemonics' {
        Get-DnsRcodeName -Rcode 0 | Should -Be 'NOERROR'
        Get-DnsRcodeName -Rcode 5 | Should -Be 'REFUSED'
        Get-DnsRcodeName -Rcode 4 | Should -Be 'NOTIMP'
    }

    It 'falls back to a numeric label for unknown rcodes' {
        Get-DnsRcodeName -Rcode 99 | Should -Match 'rcode=99'
    }
}

Describe 'Test-ZtcEnabled / Get-ZtcField' {

    It 'reads enabled=true from a hashtable' {
        Test-ZtcEnabled -Config @{ enabled = $true; server = ''; zone = '' } | Should -BeTrue
    }

    It 'reads enabled=true from a PSCustomObject (JSON-style config)' {
        Test-ZtcEnabled -Config ([PSCustomObject]@{ enabled = $true }) | Should -BeTrue
    }

    It 'returns $false when the block is $null or missing the field' {
        Test-ZtcEnabled -Config $null              | Should -BeFalse
        Test-ZtcEnabled -Config @{}                | Should -BeFalse
        Test-ZtcEnabled -Config @{ enabled = $false } | Should -BeFalse
    }

    It 'Get-ZtcField returns the value for hashtable and PSCustomObject alike' {
        Get-ZtcField -Config @{ server = '1.2.3.4' }                 -Name 'server' | Should -Be '1.2.3.4'
        Get-ZtcField -Config ([PSCustomObject]@{ zone = 'corp.tld' }) -Name 'zone'   | Should -Be 'corp.tld'
        Get-ZtcField -Config @{}                                      -Name 'server' | Should -BeNullOrEmpty
    }
}

# ── Static analysis: comma-binds-before-band trap ─────────────────────────────
#
# Regression for v1.6.4 production bug: PowerShell parses the comma operator
# before -band, so an idiom like
#     [byte[]]@(($x -shr 8) -band 0xFF, $x -band 0xFF)
# is interpreted as
#     ($x -shr 8) -band <Object[] of (0xFF, ($x -band 0xFF))>
# and crashes at runtime with "op_BitwiseAnd not found on Object[]". The
# defensive idiom is to compute each byte to a separate variable first.
# This test scans the main script for the trap so it can't sneak back in.

Describe 'Static analysis: comma-band-array trap' {

    It 'main script has no `[byte[]]@(... -band ..., ...)` patterns' {
        $scriptPath = "$PSScriptRoot/../rogue-device-detector.ps1"
        $code = Get-Content $scriptPath -Raw
        # Pattern: a [byte[]] cast wrapping an array literal whose first
        # comma is preceded by something containing -band on the same line.
        # The capture deliberately stops at the first comma, so subsequent
        # array elements don't matter.
        $bandHits = [regex]::Matches($code, '\[byte\[\]\]@?\([^)\r\n]*-band[^,\r\n]*,')
        if ($bandHits.Count -gt 0) {
            $hits = ($bandHits | ForEach-Object { $_.Value }) -join "`n  "
            throw "Found $($bandHits.Count) byte-array literal(s) with -band before the first comma — PowerShell will parse the comma first and crash with op_BitwiseAnd. Fix by computing each byte separately. Hits:`n  $hits"
        }
    }
}
