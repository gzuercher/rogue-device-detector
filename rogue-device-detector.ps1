#Requires -Version 5.1
<#
.SYNOPSIS
    Detects rogue/unauthorized devices on a network.

.DESCRIPTION
    Performs a network scan via ICMP ping sweep and ARP cache analysis.
    Compares discovered devices against a known-device baseline (state.json).
    Sends an SMTP alert when unknown devices are detected.

    On first run (no state.json), or when -LearningMode is set, all found
    devices are written to the baseline without triggering alerts.

.PARAMETER Config
    Path to config.json. Defaults to config.json in the script directory.

.PARAMETER Subnet
    CIDR subnet to scan, e.g. "192.168.1.0/24".
    Overrides the value in config.json. Auto-detected if omitted.

.PARAMETER LearningMode
    Merges all currently found devices into the baseline without alerts.
    Use for initial setup or after deliberately adding new devices.

.EXAMPLE
    # First-time setup - establish baseline
    .\rogue-device-detector.ps1 -LearningMode

    # Regular scan (run via scheduler)
    .\rogue-device-detector.ps1

    # Override subnet
    .\rogue-device-detector.ps1 -Subnet "10.0.1.0/24"
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [string]$Subnet = '',
    [switch]$LearningMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ──────────────────────────────────────────────────────────────────

$SCRIPT_VERSION   = '1.0.0'
$OUI_URL          = 'https://standards-oui.ieee.org/oui/oui.csv'
$OUI_MAX_AGE_DAYS = 30

# ── Logging ────────────────────────────────────────────────────────────────────

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped log message to the console.
    .PARAMETER Message Text to log.
    .PARAMETER Level INFO (default), WARN, or ERROR.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        'WARN'  { Write-Warning $line }
        'ERROR' { Write-Error $line -ErrorAction Continue }
        default { Write-Host $line }
    }
}

# ── Configuration ──────────────────────────────────────────────────────────────

function Get-Configuration {
    <#
    .SYNOPSIS
        Loads config.json and applies command-line parameter overrides.
    .PARAMETER ConfigPath Absolute path to config.json.
    .PARAMETER SubnetOverride Subnet override from the -Subnet script parameter.
    .RETURNS Hashtable with all resolved configuration values.
    #>
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$SubnetOverride = ''
    )

    $cfg = @{
        subnet    = ''
        statePath = Join-Path $PSScriptRoot 'state.json'
        ouiPath   = Join-Path $PSScriptRoot 'oui.csv'
        smtp      = @{
            host     = ''
            port     = 587
            user     = ''
            password = ''
            from     = ''
            to       = ''
        }
    }

    if (Test-Path $ConfigPath) {
        try {
            $file = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            if ($file.subnet)    { $cfg.subnet    = $file.subnet }
            if ($file.statePath) { $cfg.statePath = $file.statePath }
            if ($file.ouiPath)   { $cfg.ouiPath   = $file.ouiPath }
            if ($null -ne $file.smtp) {
                if ($file.smtp.host)     { $cfg.smtp.host     = $file.smtp.host }
                if ($file.smtp.port)     { $cfg.smtp.port     = [int]$file.smtp.port }
                if ($file.smtp.user)     { $cfg.smtp.user     = $file.smtp.user }
                if ($file.smtp.password) { $cfg.smtp.password = $file.smtp.password }
                if ($file.smtp.from)     { $cfg.smtp.from     = $file.smtp.from }
                if ($file.smtp.to)       { $cfg.smtp.to       = $file.smtp.to }
            }
        } catch {
            Write-Log "Could not parse config file '$ConfigPath': $_" -Level WARN
        }
    } else {
        Write-Log "Config file not found at '$ConfigPath'. Using defaults." -Level WARN
    }

    if ($SubnetOverride) { $cfg.subnet = $SubnetOverride }
    return $cfg
}

# ── Network ────────────────────────────────────────────────────────────────────

function Get-LocalSubnet {
    <#
    .SYNOPSIS
        Detects the local subnet from the primary active network adapter.
    .RETURNS CIDR string, e.g. "192.168.1.0/24".
    #>
    $addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notmatch '^127\.'      -and
            $_.IPAddress -notmatch '^169\.254\.' -and
            $_.PrefixLength -ge 8               -and
            $_.PrefixLength -le 30
        } |
        Sort-Object InterfaceMetric |
        Select-Object -First 1

    if (-not $addr) {
        throw 'No suitable network adapter found. Set subnet manually in config.json.'
    }

    $ipBytes = [System.Net.IPAddress]::Parse($addr.IPAddress).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt    = [System.BitConverter]::ToUInt32($ipBytes, 0)
    $mask     = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $addr.PrefixLength))
    $netInt   = $ipInt -band $mask
    $netBytes = [System.BitConverter]::GetBytes([uint32]$netInt)
    [Array]::Reverse($netBytes)

    return "$([System.Net.IPAddress]::new($netBytes))/$($addr.PrefixLength)"
}

function Get-SubnetInfo {
    <#
    .SYNOPSIS
        Parses a CIDR string into its components.
    .PARAMETER Cidr CIDR notation, e.g. "192.168.1.0/24".
    .RETURNS Hashtable: NetworkAddress, PrefixLength, BaseInt, HostCount.
    #>
    param([Parameter(Mandatory)][string]$Cidr)

    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { throw "Invalid CIDR format: '$Cidr'" }

    $prefix   = [int]$parts[1]
    $ipBytes  = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt    = [System.BitConverter]::ToUInt32($ipBytes, 0)
    $mask     = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $prefix))
    $baseInt  = $ipInt -band $mask
    $netBytes = [System.BitConverter]::GetBytes([uint32]$baseInt)
    [Array]::Reverse($netBytes)

    return @{
        NetworkAddress = [System.Net.IPAddress]::new($netBytes).ToString()
        PrefixLength   = $prefix
        BaseInt        = $baseInt
        HostCount      = [int]([Math]::Pow(2, 32 - $prefix) - 2)
    }
}

function Invoke-PingSweep {
    <#
    .SYNOPSIS
        Sends concurrent ICMP pings to all hosts in a subnet to populate the ARP cache.
    .PARAMETER SubnetInfo Hashtable from Get-SubnetInfo.
    #>
    param([Parameter(Mandatory)][hashtable]$SubnetInfo)

    if ($SubnetInfo.HostCount -gt 2046) {
        Write-Log "Subnet has $($SubnetInfo.HostCount) hosts - scan may take a while." -Level WARN
    }

    Write-Log "Pinging $($SubnetInfo.HostCount) host(s) in $($SubnetInfo.NetworkAddress)/$($SubnetInfo.PrefixLength)..."

    $tasks = [System.Collections.Generic.List[hashtable]]::new()

    for ($i = 1; $i -le $SubnetInfo.HostCount; $i++) {
        $hostInt   = $SubnetInfo.BaseInt + [uint32]$i
        $hostBytes = [System.BitConverter]::GetBytes([uint32]$hostInt)
        [Array]::Reverse($hostBytes)
        $ip   = [System.Net.IPAddress]::new($hostBytes).ToString()
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $tasks.Add(@{ IP = $ip; Ping = $ping; Task = $ping.SendPingAsync($ip, 500) })
    }

    $count = 0
    foreach ($t in $tasks) {
        try {
            $reply = $t.Task.GetAwaiter().GetResult()
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $count++ }
        } catch { }
        finally { $t.Ping.Dispose() }
    }

    Write-Log "Ping sweep complete: $count host(s) responded."
}

function Get-ArpEntries {
    <#
    .SYNOPSIS
        Reads the ARP cache and returns MAC/IP pairs within the target subnet.
    .PARAMETER SubnetInfo Hashtable from Get-SubnetInfo.
    .RETURNS Array of PSCustomObjects with IP and MAC properties.
    #>
    param([Parameter(Mandatory)][hashtable]$SubnetInfo)

    $entries   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mask      = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $SubnetInfo.PrefixLength))
    $arpOutput = & arp -a 2>$null

    foreach ($line in $arpOutput) {
        if ($line -notmatch '^\s+(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})\s+') {
            continue
        }
        $ip  = $Matches[1]
        $mac = ($Matches[2] -replace '-', ':').ToUpper()

        # Skip multicast (224.x.x.x+) and broadcast
        if ([int]($ip.Split('.')[0]) -ge 224) { continue }

        # Check if IP belongs to our subnet
        $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
        if (($ipInt -band $mask) -ne $SubnetInfo.BaseInt) { continue }

        $entries.Add([PSCustomObject]@{ IP = $ip; MAC = $mac })
    }

    return $entries.ToArray()
}

function Resolve-Hostnames {
    <#
    .SYNOPSIS
        Resolves hostnames for an array of devices concurrently via async DNS.
        All requests are fired simultaneously, each with a 2-second timeout.
        Updates the hostname property of each device object in place.
    .PARAMETER Devices Array of PSCustomObjects with an 'ip' property.
    #>
    param([Parameter(Mandatory)][array]$Devices)

    $timeoutMs = 2000

    # Fire all DNS requests concurrently before waiting for any
    $tasks = $Devices | ForEach-Object {
        [PSCustomObject]@{
            Device      = $_
            DnsTask     = [System.Net.Dns]::GetHostEntryAsync($_.ip)
            TimeoutTask = [System.Threading.Tasks.Task]::Delay($timeoutMs)
        }
    }

    $resolved = 0
    $total    = $tasks.Count
    $i        = 0

    foreach ($t in $tasks) {
        $i++
        Write-Progress -Activity 'Resolving hostnames' `
                       -Status "$i/$total - $($t.Device.ip)" `
                       -PercentComplete ([int]($i / $total * 100))
        try {
            $taskArray = [System.Threading.Tasks.Task[]]@($t.DnsTask, $t.TimeoutTask)
            $winner    = [System.Threading.Tasks.Task]::WhenAny($taskArray).GetAwaiter().GetResult()
            if ($winner -eq $t.DnsTask -and $t.DnsTask.Status -eq 'RanToCompletion') {
                $h = $t.DnsTask.Result.HostName
                if ($h -and $h -ne $t.Device.ip) {
                    $t.Device.hostname = $h
                    $resolved++
                }
            }
        } catch { }
    }

    Write-Progress -Activity 'Resolving hostnames' -Completed
    Write-Log "Hostname resolution complete: $resolved/$total resolved."
}

# ── OUI Lookup ─────────────────────────────────────────────────────────────────

function Get-OuiDatabase {
    <#
    .SYNOPSIS
        Loads the IEEE OUI vendor database, downloading or refreshing the cache as needed.
    .PARAMETER CachePath Path to the local oui.csv cache file.
    .RETURNS Hashtable mapping 6-char OUI prefix (uppercase) to vendor name.
    #>
    param([Parameter(Mandatory)][string]$CachePath)

    $stale = (-not (Test-Path $CachePath)) -or
             ((Get-Item $CachePath).LastWriteTime -lt (Get-Date).AddDays(-$OUI_MAX_AGE_DAYS))

    if ($stale) {
        try {
            Write-Log 'Updating OUI database from IEEE...'
            Invoke-WebRequest -Uri $OUI_URL -OutFile $CachePath -TimeoutSec 60 -UseBasicParsing
            Write-Log 'OUI database updated.'
        } catch {
            Write-Log "OUI download failed: $_. Vendor names will show as 'Unknown'." -Level WARN
            if (-not (Test-Path $CachePath)) { return @{} }
        }
    }

    $db = @{}
    try {
        Import-Csv -Path $CachePath | ForEach-Object {
            $key = $_.'Assignment'
            if ($key -and $key.Length -ge 6) {
                $db[$key.Substring(0, 6).ToUpper()] = $_.'Organization Name'
            }
        }
        Write-Log "OUI database loaded: $($db.Count) vendor entries."
    } catch {
        Write-Log "Failed to parse OUI database: $_" -Level WARN
        return @{}
    }

    return $db
}

function Get-MacVendor {
    <#
    .SYNOPSIS
        Looks up the vendor name for a MAC address using the OUI database.
    .PARAMETER Mac Normalized MAC address (e.g. "00:15:5D:04:6D:04").
    .PARAMETER OuiDb Hashtable from Get-OuiDatabase.
    .RETURNS Vendor name string, or "Unknown".
    #>
    param(
        [Parameter(Mandatory)][string]$Mac,
        [Parameter(Mandatory)][hashtable]$OuiDb
    )

    if ($OuiDb.Count -eq 0) { return 'Unknown' }
    $prefix = ($Mac -replace '[^0-9A-Fa-f]', '').Substring(0, 6).ToUpper()
    if ($OuiDb.ContainsKey($prefix)) { return $OuiDb[$prefix] }
    return 'Unknown'
}

# ── State ──────────────────────────────────────────────────────────────────────

function Get-State {
    <#
    .SYNOPSIS
        Loads the state file, returning an empty state object if none exists.
    .PARAMETER StatePath Path to state.json.
    .RETURNS PSCustomObject with lastScan and knownDevices properties.
    #>
    param([Parameter(Mandatory)][string]$StatePath)

    if (Test-Path $StatePath) {
        $raw = Get-Content $StatePath -Raw | ConvertFrom-Json
        if ($null -eq $raw.knownDevices) { $raw.knownDevices = @() }
        return $raw
    }

    return [PSCustomObject]@{
        lastScan     = $null
        knownDevices = @()
    }
}

function Save-State {
    <#
    .SYNOPSIS
        Serializes the state object to a JSON file.
    .PARAMETER State PSCustomObject to persist.
    .PARAMETER StatePath Target path for state.json.
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$State,
        [Parameter(Mandatory)][string]$StatePath
    )

    $State | ConvertTo-Json -Depth 10 | Set-Content -Path $StatePath -Encoding UTF8
}

# ── Alert ──────────────────────────────────────────────────────────────────────

function Send-RogueAlert {
    <#
    .SYNOPSIS
        Sends an SMTP email listing newly discovered rogue devices.
    .PARAMETER Devices Array of rogue device PSCustomObjects.
    .PARAMETER SmtpConfig Hashtable with SMTP connection settings from config.
    #>
    param(
        [Parameter(Mandatory)][array]$Devices,
        [Parameter(Mandatory)][hashtable]$SmtpConfig
    )

    if (-not $SmtpConfig.host -or -not $SmtpConfig.to -or -not $SmtpConfig.from) {
        Write-Log 'SMTP not configured - skipping email alert.' -Level WARN
        return
    }

    $deviceLines = ($Devices | ForEach-Object {
        "  MAC:      $($_.mac)`n  IP:       $($_.ip)`n  Hostname: $($_.hostname)`n  Vendor:   $($_.vendor)"
    }) -join "`n`n"

    $body = @"
Rogue Device Detector - Alert

The following unknown device(s) were found on the network:

$deviceLines

Scan time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Scanner   : $env:COMPUTERNAME

Action required:
  Authorized device   -> Re-run with -LearningMode to add to baseline
  Unauthorized device -> Remove from the network immediately
"@

    $mailParams = @{
        From       = $SmtpConfig.from
        To         = $SmtpConfig.to
        Subject    = "[$env:COMPUTERNAME] $($Devices.Count) rogue device(s) detected - $(Get-Date -Format 'yyyy-MM-dd')"
        Body       = $body
        SmtpServer = $SmtpConfig.host
        Port       = [int]$SmtpConfig.port
        UseSsl     = $true
    }

    if ($SmtpConfig.user) {
        $securePass        = ConvertTo-SecureString -String $SmtpConfig.password -AsPlainText -Force
        $mailParams.Credential = New-Object System.Management.Automation.PSCredential($SmtpConfig.user, $securePass)
    }

    try {
        Send-MailMessage @mailParams
        Write-Log "Alert sent to $($SmtpConfig.to)."
    } catch {
        Write-Log "Failed to send alert: $_" -Level ERROR
    }
}

# ── Main ───────────────────────────────────────────────────────────────────────

Write-Log "Rogue Device Detector v$SCRIPT_VERSION starting on $env:COMPUTERNAME"

# Load configuration
$configPath = if ($Config) { $Config } else { Join-Path $PSScriptRoot 'config.json' }
$cfg        = Get-Configuration -ConfigPath $configPath -SubnetOverride $Subnet

# Resolve target subnet
$targetSubnet = if ($cfg.subnet) { $cfg.subnet } else { Get-LocalSubnet }
Write-Log "Target subnet: $targetSubnet"
$subnetInfo = Get-SubnetInfo -Cidr $targetSubnet

# Load OUI vendor database
$ouiDb = Get-OuiDatabase -CachePath $cfg.ouiPath

# Populate ARP cache via ping sweep, then read ARP table
Invoke-PingSweep -SubnetInfo $subnetInfo
$arpEntries = Get-ArpEntries -SubnetInfo $subnetInfo
Write-Log "$($arpEntries.Count) device(s) found in ARP table."

if ($arpEntries.Count -eq 0) {
    Write-Log 'ARP table empty after ping sweep. Exiting.' -Level WARN
    exit 0
}

# Build device list, resolve hostnames concurrently, then look up vendors
$foundDevices = $arpEntries | ForEach-Object {
    [PSCustomObject]@{
        mac      = $_.MAC
        ip       = $_.IP
        hostname = $_.IP   # placeholder, overwritten by Resolve-Hostnames
        vendor   = ''
    }
}

Resolve-Hostnames -Devices $foundDevices

foreach ($d in $foundDevices) {
    $d.vendor = Get-MacVendor -Mac $d.mac -OuiDb $ouiDb
}

# Load state
$stateFileExists = Test-Path $cfg.statePath
$state           = Get-State -StatePath $cfg.statePath
$now             = (Get-Date).ToUniversalTime().ToString('o')

# Learning mode: merge found devices into baseline without alerts
if ($LearningMode -or -not $stateFileExists) {
    if (-not $stateFileExists) {
        Write-Log 'No state file found - creating baseline (learning mode).'
    } else {
        Write-Log 'Learning mode - merging found devices into baseline.'
    }

    foreach ($device in $foundDevices) {
        $known = @($state.knownDevices) | Where-Object { $_.mac -eq $device.mac } | Select-Object -First 1
        if ($known) {
            $known.lastSeen = $now
            $known.ip       = $device.ip
            $known.hostname = $device.hostname
        } else {
            $state.knownDevices += [PSCustomObject]@{
                mac       = $device.mac
                ip        = $device.ip
                hostname  = $device.hostname
                vendor    = $device.vendor
                firstSeen = $now
                lastSeen  = $now
            }
        }
    }

    $state.lastScan = $now
    Save-State -State $state -StatePath $cfg.statePath
    Write-Log "Baseline saved: $($state.knownDevices.Count) device(s) → $($cfg.statePath)"
    exit 0
}

# Normal scan: compare found devices against baseline
$rogueDevices = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($device in $foundDevices) {
    $known = @($state.knownDevices) | Where-Object { $_.mac -eq $device.mac } | Select-Object -First 1
    if ($known) {
        $known.lastSeen = $now
        $known.ip       = $device.ip
        $known.hostname = $device.hostname
    } else {
        Write-Log "ROGUE: $($device.mac)  $($device.ip)  $($device.hostname)  [$($device.vendor)]" -Level WARN
        $rogueDevices.Add([PSCustomObject]@{
            mac       = $device.mac
            ip        = $device.ip
            hostname  = $device.hostname
            vendor    = $device.vendor
            firstSeen = $now
            lastSeen  = $now
        })
    }
}

$state.lastScan = $now
Save-State -State $state -StatePath $cfg.statePath

if ($rogueDevices.Count -gt 0) {
    Write-Log "$($rogueDevices.Count) rogue device(s) detected."
    Send-RogueAlert -Devices $rogueDevices.ToArray() -SmtpConfig $cfg.smtp
} else {
    Write-Log 'Scan complete - all devices are known.'
}
