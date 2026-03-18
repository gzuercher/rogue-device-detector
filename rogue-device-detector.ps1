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

.PARAMETER Approve
    MAC address to approve and add to the baseline (e.g. "AA:BB:CC:DD:EE:FF").
    Optionally combine with -Label to store a human-readable device name.
    Use this to approve a specific device shown in an alert without a full scan.

.PARAMETER Label
    Human-readable name for the device being approved (e.g. "John's laptop").
    Only used together with -Approve.

.PARAMETER Remove
    MAC address to remove from the baseline (e.g. "AA:BB:CC:DD:EE:FF").
    Use this to un-approve a device that was added by mistake or left the network.

.PARAMETER List
    Displays all approved devices in the baseline and exits.
    No scan is performed.

.EXAMPLE
    # First-time setup - establish baseline
    .\rogue-device-detector.ps1 -LearningMode

    # Regular scan (run via scheduler)
    .\rogue-device-detector.ps1

    # Override subnet
    .\rogue-device-detector.ps1 -Subnet "10.0.1.0/24"

    # Approve a specific device from an alert (copy-paste the command from the email)
    .\rogue-device-detector.ps1 -Approve "AA:BB:CC:DD:EE:FF" -Label "John's laptop"

    # Remove a device that left the network
    .\rogue-device-detector.ps1 -Remove "AA:BB:CC:DD:EE:FF"

    # Show all approved devices
    .\rogue-device-detector.ps1 -List
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [string]$Subnet = '',
    [switch]$LearningMode,
    [string]$Approve = '',
    [string]$Label   = '',
    [string]$Remove  = '',
    [switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ──────────────────────────────────────────────────────────────────

$SCRIPT_VERSION       = '1.2.0'
$OUI_URL          = 'https://standards-oui.ieee.org/oui/oui.csv'
$OUI_MAX_AGE_DAYS = 30

$SECURITY_PORTS = @(
    [PSCustomObject]@{ Port = 21;   Label = 'FTP';        Risk = 'HIGH';     Reason = 'Unencrypted file transfer' },
    [PSCustomObject]@{ Port = 22;   Label = 'SSH';        Risk = 'LOW';      Reason = 'Remote access (SSH)' },
    [PSCustomObject]@{ Port = 23;   Label = 'Telnet';     Risk = 'CRITICAL'; Reason = 'Unencrypted remote access (Telnet)' },
    [PSCustomObject]@{ Port = 25;   Label = 'SMTP';       Risk = 'MEDIUM';   Reason = 'Mail server exposed' },
    [PSCustomObject]@{ Port = 80;   Label = 'HTTP';       Risk = 'LOW';      Reason = 'Unencrypted web interface' },
    [PSCustomObject]@{ Port = 443;  Label = 'HTTPS';      Risk = 'NONE';     Reason = '' },
    [PSCustomObject]@{ Port = 445;  Label = 'SMB';        Risk = 'HIGH';     Reason = 'File sharing exposed (ransomware vector)' },
    [PSCustomObject]@{ Port = 3389; Label = 'RDP';        Risk = 'HIGH';     Reason = 'Remote Desktop exposed' },
    [PSCustomObject]@{ Port = 8080; Label = 'HTTP-alt';   Risk = 'LOW';      Reason = 'Alternate web interface' },
    [PSCustomObject]@{ Port = 8443; Label = 'HTTPS-alt';  Risk = 'NONE';     Reason = '' }
)

$RISK_ORDER = @{ 'NONE' = 0; 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }

$ABSENT_DAYS_DEFAULT = 21

# ── Logging ────────────────────────────────────────────────────────────────────

function Write-RddLog {
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
        subnet        = ''
        statePath     = Join-Path $PSScriptRoot 'state.json'
        ouiPath       = Join-Path $PSScriptRoot 'oui.csv'
        logPath       = Join-Path $PSScriptRoot 'rdd-audit.csv'
        enrichment    = $true
        absentDays    = $ABSENT_DAYS_DEFAULT
        summaryReport = $false
        smtp          = @{
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
            $p = $file.PSObject.Properties
            if ($p['subnet']     -and $file.subnet)    { $cfg.subnet     = $file.subnet }
            if ($p['statePath']  -and $file.statePath) { $cfg.statePath  = $file.statePath }
            if ($p['ouiPath']    -and $file.ouiPath)   { $cfg.ouiPath    = $file.ouiPath }
            if ($p['logPath']    -and $file.logPath)   { $cfg.logPath    = $file.logPath }
            if ($p['enrichment'] -and $null -ne $file.enrichment) { $cfg.enrichment = [bool]$file.enrichment }
            if ($p['absentDays'] -and $null -ne $file.absentDays) { $cfg.absentDays = [int]$file.absentDays }
            if ($p['summaryReport'] -and $null -ne $file.summaryReport) { $cfg.summaryReport = [bool]$file.summaryReport }
            if ($p['smtp'] -and $null -ne $file.smtp) {
                $sp = $file.smtp.PSObject.Properties
                if ($sp['host']     -and $file.smtp.host)     { $cfg.smtp.host     = $file.smtp.host }
                if ($sp['port']     -and $file.smtp.port)     { $cfg.smtp.port     = [int]$file.smtp.port }
                if ($sp['user']     -and $file.smtp.user)     { $cfg.smtp.user     = $file.smtp.user }
                if ($sp['password'] -and $file.smtp.password) { $cfg.smtp.password = $file.smtp.password }
                if ($sp['from']     -and $file.smtp.from)     { $cfg.smtp.from     = $file.smtp.from }
                if ($sp['to']       -and $file.smtp.to)       { $cfg.smtp.to       = $file.smtp.to }
            }
        } catch {
            Write-RddLog "Could not parse config file '$ConfigPath': $_" -Level WARN
        }
    } else {
        Write-RddLog "Config file not found at '$ConfigPath'. Using defaults." -Level WARN
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
    .RETURNS Hashtable mapping IP address to TTL value for hosts that responded.
    #>
    param([Parameter(Mandatory)][hashtable]$SubnetInfo)

    if ($SubnetInfo.HostCount -gt 2046) {
        Write-RddLog "Subnet has $($SubnetInfo.HostCount) hosts - scan may take a while." -Level WARN
    }

    Write-RddLog "Pinging $($SubnetInfo.HostCount) host(s) in $($SubnetInfo.NetworkAddress)/$($SubnetInfo.PrefixLength)..."

    $tasks = [System.Collections.Generic.List[hashtable]]::new()

    for ($i = 1; $i -le $SubnetInfo.HostCount; $i++) {
        $hostInt   = $SubnetInfo.BaseInt + [uint32]$i
        $hostBytes = [System.BitConverter]::GetBytes([uint32]$hostInt)
        [Array]::Reverse($hostBytes)
        $ip   = [System.Net.IPAddress]::new($hostBytes).ToString()
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $tasks.Add(@{ IP = $ip; Ping = $ping; Task = $ping.SendPingAsync($ip, 500) })
    }

    $ttlMap = @{}
    $count  = 0
    foreach ($t in $tasks) {
        try {
            $reply = $t.Task.GetAwaiter().GetResult()
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $count++
                if ($reply.Options -and $reply.Options.Ttl -gt 0) {
                    $ttlMap[$t.IP] = [int]$reply.Options.Ttl
                }
            }
        } catch {
            Write-RddLog "Ping failed for $($t.IP): $_" -Level WARN
        }
        finally { $t.Ping.Dispose() }
    }

    Write-RddLog "Ping sweep complete: $count host(s) responded."
    return $ttlMap
}

function Get-OsGuess {
    <#
    .SYNOPSIS
        Guesses the operating system family from a ping reply TTL value.
    .PARAMETER Ttl TTL value from the ICMP reply.
    .RETURNS String: 'Windows', 'Linux/macOS', 'Network device', or ''.
    #>
    param([int]$Ttl)

    if ($Ttl -le 0)   { return '' }
    if ($Ttl -le 64)  { return 'Linux/macOS' }
    if ($Ttl -le 128) { return 'Windows' }
    return 'Network device'
}

function Get-ArpEntry {
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

        # Skip network address (host bits all 0) and broadcast (host bits all 1)
        $hostMask = [uint32]([Math]::Pow(2, 32 - $SubnetInfo.PrefixLength) - 1)
        if (($ipInt -band $hostMask) -eq 0 -or ($ipInt -band $hostMask) -eq $hostMask) { continue }

        $entries.Add([PSCustomObject]@{ IP = $ip; MAC = $mac })
    }

    return $entries.ToArray()
}

function Resolve-Hostname {
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
        } catch {
            Write-RddLog "DNS lookup failed for $($t.Device.ip): $_" -Level WARN
        }
    }

    Write-Progress -Activity 'Resolving hostnames' -Completed
    Write-RddLog "Hostname resolution complete: $resolved/$total resolved."
}

# ── Enrichment ─────────────────────────────────────────────────────────────────

function Invoke-PortScan {
    <#
    .SYNOPSIS
        Scans security-relevant TCP ports on a single host concurrently.
    .PARAMETER IP Target IP address.
    .PARAMETER TimeoutMs Connection timeout per port in milliseconds.
    .RETURNS Array of open port numbers.
    #>
    param(
        [Parameter(Mandatory)][string]$IP,
        [int]$TimeoutMs = 500
    )

    $tasks = $SECURITY_PORTS | ForEach-Object {
        $client = [System.Net.Sockets.TcpClient]::new()
        [PSCustomObject]@{
            Port    = $_.Port
            Client  = $client
            Task    = $client.ConnectAsync($IP, $_.Port)
            Timeout = [System.Threading.Tasks.Task]::Delay($TimeoutMs)
        }
    }

    $open = [System.Collections.Generic.List[int]]::new()
    foreach ($t in $tasks) {
        try {
            $arr    = [System.Threading.Tasks.Task[]]@($t.Task, $t.Timeout)
            $winner = [System.Threading.Tasks.Task]::WhenAny($arr).GetAwaiter().GetResult()
            if ($winner -eq $t.Task -and $t.Task.Status -eq 'RanToCompletion') {
                $open.Add($t.Port)
            }
        } catch {
            Write-RddLog "Port scan error on ${IP}:$($t.Port): $_" -Level WARN
        }
        finally { try { $t.Client.Dispose() } catch { $null = $_ } }
    }

    return $open.ToArray()
}

function Get-HttpBanner {
    <#
    .SYNOPSIS
        Grabs the page title and Server header from a device's web interface.
    .PARAMETER IP Target IP address.
    .PARAMETER OpenPorts Array of open port numbers to check.
    .RETURNS Descriptive string, or empty string if no web interface found.
    #>
    param(
        [Parameter(Mandatory)][string]$IP,
        [int[]]$OpenPorts
    )

    $webPorts = @($OpenPorts | Where-Object { $_ -in @(80, 443, 8080, 8443) })
    if ($webPorts.Count -eq 0) { return '' }

    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        $url    = "${scheme}://${IP}:${port}/"
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 3 -UseBasicParsing `
                -ErrorAction Stop `
                -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($response.Content -match '<title[^>]*>([^<]{2,80})</title>') {
                $parts.Add($Matches[1].Trim())
            }
            $server = $response.Headers['Server']
            if ($server) { $parts.Add("Server: $server") }
            if ($parts.Count -gt 0) { return $parts -join ' | ' }
        } catch {
            Write-RddLog "HTTP banner grab failed for ${url}: $_" -Level WARN
        }
    }
    return ''
}

function Invoke-UpnpDiscovery {
    <#
    .SYNOPSIS
        Sends a UPnP/SSDP M-SEARCH broadcast and collects device responses.
    .PARAMETER ListenSeconds How long to listen for responses.
    .RETURNS Hashtable of IP address -> SERVER string.
    #>
    param([int]$ListenSeconds = 3)

    $results = @{}
    try {
        $client = [System.Net.Sockets.UdpClient]::new()
        $client.Client.ReceiveTimeout = 500
        $msg   = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: $ListenSeconds`r`nST: upnp:rootdevice`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
        $ep    = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse('239.255.255.250'), 1900)
        $client.Send($bytes, $bytes.Length, $ep) | Out-Null

        $stop = (Get-Date).AddSeconds($ListenSeconds)
        while ((Get-Date) -lt $stop) {
            try {
                $remote   = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                $data     = $client.Receive([ref]$remote)
                $response = [System.Text.Encoding]::ASCII.GetString($data)
                $ip       = $remote.Address.ToString()
                if ($response -match '(?i)SERVER:\s*(.+)') {
                    $results[$ip] = $Matches[1].Trim()
                } elseif (-not $results.ContainsKey($ip)) {
                    $results[$ip] = 'UPnP device'
                }
            } catch { $null = $_ }
        }
        $client.Dispose()
    } catch {
        Write-RddLog "UPnP discovery failed: $_" -Level WARN
    }

    return $results
}

function Get-DeviceRisk {
    <#
    .SYNOPSIS
        Evaluates the risk level of a device based on its open ports.
    .PARAMETER OpenPorts Array of open port numbers.
    .RETURNS PSCustomObject with Level (string) and Reasons (string array).
    #>
    param([int[]]$OpenPorts)

    $level   = 'NONE'
    $reasons = [System.Collections.Generic.List[string]]::new()

    foreach ($port in $OpenPorts) {
        $def = $SECURITY_PORTS | Where-Object { $_.Port -eq $port } | Select-Object -First 1
        if (-not $def -or $def.Risk -eq 'NONE' -or -not $def.Reason) { continue }
        $reasons.Add("$($def.Reason) (port $port)")
        if ($RISK_ORDER[$def.Risk] -gt $RISK_ORDER[$level]) { $level = $def.Risk }
    }

    return [PSCustomObject]@{ Level = $level; Reasons = $reasons.ToArray() }
}

function Invoke-DeviceEnrichment {
    <#
    .SYNOPSIS
        Enriches a device list with port scan, HTTP banner, UPnP, and risk data.
        Updates device objects in place.
    .PARAMETER Devices Array of device PSCustomObjects.
    #>
    param([Parameter(Mandatory)][array]$Devices)

    Write-RddLog "Enriching $($Devices.Count) device(s) (ports / banner / UPnP)..."
    Write-RddLog 'Running UPnP discovery...'
    $upnpMap = Invoke-UpnpDiscovery

    $i = 0
    foreach ($d in $Devices) {
        $i++
        Write-Progress -Activity 'Enriching devices' `
                       -Status "$i/$($Devices.Count) - $($d.ip)" `
                       -PercentComplete ([int]($i / $Devices.Count * 100))

        $d.openPorts   = Invoke-PortScan -IP $d.ip
        $d.httpBanner  = Get-HttpBanner  -IP $d.ip -OpenPorts $d.openPorts
        $d.upnpInfo    = if ($upnpMap.ContainsKey($d.ip)) { $upnpMap[$d.ip] } else { '' }
        $risk          = Get-DeviceRisk  -OpenPorts $d.openPorts
        $d.riskLevel   = $risk.Level
        $d.riskReasons = $risk.Reasons
    }

    Write-Progress -Activity 'Enriching devices' -Completed
    $risky = @($Devices | Where-Object { $_.riskLevel -ne 'NONE' }).Count
    Write-RddLog "Enrichment done: $risky/$($Devices.Count) device(s) with risk findings."
}

# ── Audit Log ──────────────────────────────────────────────────────────────────

function Write-AuditLog {
    <#
    .SYNOPSIS
        Appends a single event to the CSV audit log (append-only).
        Creates the file with headers on first use.
    .PARAMETER LogPath  Path to the audit CSV file.
    .PARAMETER Event    SCAN_START | SCAN_DONE | DEVICE_NEW | DEVICE_ROGUE | RISK_FOUND
    .PARAMETER Device   Optional device PSCustomObject (for device events).
    .PARAMETER Details  Optional free-text details field.
    #>
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$EventName,
        [PSCustomObject]$Device  = $null,
        [string]$Details         = ''
    )

    if (-not (Test-Path $LogPath)) {
        Set-Content -Path $LogPath -Encoding UTF8 `
            -Value 'Timestamp,Event,Scanner,MAC,IP,Hostname,Vendor,OpenPorts,Risk,Details'
    }

    $fields = @(
        (Get-Date).ToUniversalTime().ToString('o'),
        $EventName,
        $env:COMPUTERNAME,
        $(if ($Device) { $Device.mac }                                       else { '' }),
        $(if ($Device) { $Device.ip }                                        else { '' }),
        $(if ($Device) { $Device.hostname }                                  else { '' }),
        $(if ($Device) { $Device.vendor }                                    else { '' }),
        $(if ($Device -and $Device.openPorts) { $Device.openPorts -join ' '} else { '' }),
        $(if ($Device -and $Device.riskLevel) { $Device.riskLevel }          else { '' }),
        $Details
    ) | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }

    Add-Content -Path $LogPath -Value ($fields -join ',') -Encoding UTF8
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
            Write-RddLog 'Updating OUI database from IEEE...'
            # Use system proxy and a browser User-Agent to pass corporate firewalls
            [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            Invoke-WebRequest -Uri $OUI_URL -OutFile $CachePath -TimeoutSec 60 -UseBasicParsing `
                -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            Write-RddLog 'OUI database updated.'
        } catch {
            Write-RddLog "OUI download failed: $_. Vendor names will show as 'Unknown'." -Level WARN
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
        Write-RddLog "OUI database loaded: $($db.Count) vendor entries."
    } catch {
        Write-RddLog "Failed to parse OUI database: $_" -Level WARN
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
        # PowerShell 7 ConvertFrom-Json auto-parses ISO-8601 strings as DateTime;
        # normalise back to the string format the rest of the code expects.
        if ($raw.lastScan -is [datetime]) {
            Add-Member -InputObject $raw -NotePropertyName 'lastScan' `
                -NotePropertyValue ($raw.lastScan.ToUniversalTime().ToString('o')) -Force
        }
        # Ensure knownDevices is always an array (ConvertFrom-Json yields $null for "null").
        if ($null -eq $raw.knownDevices) {
            Add-Member -InputObject $raw -NotePropertyName 'knownDevices' `
                -NotePropertyValue ([object[]]@()) -Force
        }
        # Ensure devices from older state files have the osGuess field.
        foreach ($d in @($raw.knownDevices)) {
            if (-not ($d.PSObject.Properties['osGuess'])) {
                $d | Add-Member -MemberType NoteProperty -Name 'osGuess' -Value ''
            }
        }
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
    # Password is read from a plain-text config file; SecureString conversion at this
    # boundary is unavoidable without a full credential-store integration.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Password sourced from config file; plain-text conversion is unavoidable at this integration point.'
    )]
    param(
        [Parameter(Mandatory)][array]$Devices,
        [Parameter(Mandatory)][hashtable]$SmtpConfig
    )

    if (-not $SmtpConfig.host -or -not $SmtpConfig.to -or -not $SmtpConfig.from) {
        Write-RddLog 'SMTP not configured - skipping email alert.' -Level WARN
        return
    }

    $scriptPath = $PSCommandPath

    $deviceLines = ($Devices | ForEach-Object {
        $d     = $_
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("  MAC:      $($d.mac)")
        $lines.Add("  IP:       $($d.ip)")
        $lines.Add("  Hostname: $($d.hostname)")
        $lines.Add("  Vendor:   $($d.vendor)")
        if ($d.openPorts -and $d.openPorts.Count -gt 0) {
            $labels = $d.openPorts | ForEach-Object {
                $def = $SECURITY_PORTS | Where-Object { $_.Port -eq $_ } | Select-Object -First 1
                if ($def) { "$_/$($def.Label)" } else { "$_" }
            }
            $lines.Add("  Ports:    $($labels -join ', ')")
        }
        if ($d.riskLevel -and $d.riskLevel -ne 'NONE') {
            $lines.Add("  RISK:     [$($d.riskLevel)] $($d.riskReasons -join '; ')")
        }
        if ($d.osGuess)    { $lines.Add("  OS:       $($d.osGuess)") }
        if ($d.httpBanner) { $lines.Add("  Banner:   $($d.httpBanner)") }
        if ($d.upnpInfo)   { $lines.Add("  UPnP:     $($d.upnpInfo)") }
        $lines.Add('')
        $lines.Add("  -> If AUTHORIZED, run on $($env:COMPUTERNAME):")
        $lines.Add("     & `"$scriptPath`" -Approve `"$($d.mac)`" -Label `"<device description>`"")
        $lines.Add('  -> If UNAUTHORIZED: isolate/remove from network immediately.')
        $lines -join "`n"
    }) -join "`n`n---`n`n"

    $body = @"
Rogue Device Detector - Alert

$($Devices.Count) unknown device(s) found on the network:

$deviceLines

---
Scan time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Scanner   : $env:COMPUTERNAME

To review the full baseline:
  & "$scriptPath" -List
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
        Write-RddLog "Alert sent to $($SmtpConfig.to)."
    } catch {
        Write-RddLog "Failed to send alert: $_" -Level ERROR
    }
}

# ── Baseline Management ────────────────────────────────────────────────────────

function Invoke-ApproveDevice {
    <#
    .SYNOPSIS
        Adds or updates a device in the baseline without running a scan.
    .PARAMETER Mac     MAC address to approve (normalized to uppercase AA:BB:CC:DD:EE:FF).
    .PARAMETER Label   Optional human-readable device name.
    .PARAMETER State   State object loaded from state.json.
    .PARAMETER Now     ISO timestamp string for approvedAt / lastSeen.
    #>
    param(
        [Parameter(Mandatory)][string]$Mac,
        [string]$Label = '',
        [Parameter(Mandatory)][PSCustomObject]$State,
        [Parameter(Mandatory)][string]$Now
    )

    # Normalize MAC to uppercase colon-separated
    $mac = ($Mac -replace '[^0-9A-Fa-f]', '') -replace '(.{2})(?!$)', '$1:'
    $mac = $mac.ToUpper()
    if ($mac.Length -ne 17) {
        throw "Invalid MAC address format: '$Mac'. Expected AA:BB:CC:DD:EE:FF."
    }

    $existing = @($State.knownDevices) | Where-Object { $_.mac -eq $mac } | Select-Object -First 1
    if ($existing) {
        if ($Label) { $existing.label = $Label }
        $existing.approvedBy = "$env:USERDOMAIN\$env:USERNAME"
        $existing.approvedAt = $Now
        Write-RddLog "Updated existing device $mac in baseline$(if ($Label) { " (label: '$Label')" } else { '' })."
    } else {
        $State.knownDevices += [PSCustomObject]@{
            mac        = $mac
            ip         = ''
            hostname   = ''
            vendor     = ''
            label      = $Label
            firstSeen  = $Now
            lastSeen   = $Now
            approvedBy = "$env:USERDOMAIN\$env:USERNAME"
            approvedAt = $Now
        }
        Write-RddLog "Approved new device $mac$(if ($Label) { " (label: '$Label')" } else { '' }) - added to baseline."
    }
}

function Invoke-RemoveDevice {
    <#
    .SYNOPSIS
        Removes a device from the baseline by MAC address.
    .PARAMETER Mac   MAC address to remove.
    .PARAMETER State State object loaded from state.json.
    .RETURNS $true if removed, $false if not found.
    #>
    param(
        [Parameter(Mandatory)][string]$Mac,
        [Parameter(Mandatory)][PSCustomObject]$State
    )

    $mac = ($Mac -replace '[^0-9A-Fa-f]', '') -replace '(.{2})(?!$)', '$1:'
    $mac = $mac.ToUpper()

    # Determine removal before modifying; avoids relying on Count after PSCustomObject
    # property re-assignment, which can behave unexpectedly with empty arrays in strict mode.
    $removed = $null -ne (@($State.knownDevices) | Where-Object { $_.mac -eq $mac } | Select-Object -First 1)
    # @() around the pipeline ensures an array even when nothing passes the filter.
    $State.knownDevices = [object[]]@($State.knownDevices | Where-Object { $_.mac -ne $mac })

    if ($removed) {
        Write-RddLog "Removed device $mac from baseline."
    } else {
        Write-RddLog "Device $mac not found in baseline." -Level WARN
    }
    return $removed
}

function Show-Baseline {
    <#
    .SYNOPSIS
        Displays all approved devices in the baseline in a human-readable format.
    .PARAMETER State     State object loaded from state.json.
    .PARAMETER StatePath Path shown in the header for reference.
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$State,
        [Parameter(Mandatory)][string]$StatePath
    )

    $devices = @($State.knownDevices)
    $lastScan = if ($State.lastScan) { $State.lastScan } else { 'never' }

    Write-Host ''
    Write-Host "Approved devices baseline - $StatePath"
    Write-Host "Last scan : $lastScan"
    Write-Host "Devices   : $($devices.Count)"
    Write-Host ("-" * 80)

    if ($devices.Count -eq 0) {
        Write-Host '  (no devices in baseline)'
    } else {
        foreach ($d in ($devices | Sort-Object mac)) {
            $label      = if ($d.label)      { " | Label: $($d.label)" }            else { '' }
            $approvedBy = if ($d.approvedBy) { " | Approved by: $($d.approvedBy)" } else { '' }
            $approvedAt = if ($d.approvedAt) { " | Approved: $($d.approvedAt)" }    else { '' }
            $hostname   = if ($d.hostname -and $d.hostname -ne $d.ip) { " | Host: $($d.hostname)" } else { '' }
            $vendor     = if ($d.vendor)     { " | Vendor: $($d.vendor)" }          else { '' }
            $osGuess    = if ($d.osGuess)    { " | OS: $($d.osGuess)" }             else { '' }
            $lastSeen   = if ($d.lastSeen)   { " | Last seen: $($d.lastSeen)" }     else { '' }
            Write-Host "  $($d.mac)  IP: $(($d.ip).PadRight(15))$hostname$vendor$osGuess$label$lastSeen$approvedBy$approvedAt"
        }
    }

    Write-Host ("-" * 80)
    Write-Host ''
}

function Test-IdentityChange {
    <#
    .SYNOPSIS
        Checks whether a known device's hostname has changed to a new real hostname.
        Ignores changes where either hostname is just an IP address (DNS resolution flapping).
    .PARAMETER KnownDevice  Device from the baseline (state.json).
    .PARAMETER FoundDevice  Device from the current scan.
    .RETURNS Previous hostname string if a real change occurred, $null otherwise.
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$KnownDevice,
        [Parameter(Mandatory)][PSCustomObject]$FoundDevice
    )

    $oldHost = $KnownDevice.hostname
    $newHost = $FoundDevice.hostname
    if ($oldHost -and $newHost -ne $oldHost -and $oldHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        return $oldHost
    }
    return $null
}

function Get-AbsentDevices {
    <#
    .SYNOPSIS
        Returns baseline devices that have not been seen for more than the given number of days.
    .PARAMETER KnownDevices Array of baseline device objects.
    .PARAMETER AbsentDays   Number of days after which a device is considered absent.
    .PARAMETER Now          Current UTC timestamp (ISO-8601 string).
    .RETURNS Array of absent device objects.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Function returns a collection of devices; plural is intentional.')]
    param(
        [Parameter(Mandatory)][array]$KnownDevices,
        [Parameter(Mandatory)][int]$AbsentDays,
        [Parameter(Mandatory)][string]$Now
    )

    $threshold = [DateTime]::Parse($Now).AddDays(-$AbsentDays)
    $absent = @($KnownDevices | Where-Object {
        $_.lastSeen -and [DateTime]::Parse($_.lastSeen) -lt $threshold
    })
    return $absent
}

function Send-SummaryReport {
    <#
    .SYNOPSIS
        Sends a comprehensive network health summary email.
    .PARAMETER Report  Hashtable with scan results (foundCount, baselineCount, rogueDevices, etc.).
    .PARAMETER SmtpConfig  Hashtable with SMTP connection settings from config.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Password sourced from config file; plain-text conversion is unavoidable at this integration point.'
    )]
    param(
        [Parameter(Mandatory)][hashtable]$Report,
        [Parameter(Mandatory)][hashtable]$SmtpConfig
    )

    if (-not $SmtpConfig.host -or -not $SmtpConfig.to -or -not $SmtpConfig.from) {
        Write-RddLog 'SMTP not configured - skipping summary report.' -Level WARN
        return
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('Rogue Device Detector - Network Health Report')
    $lines.Add('')
    $lines.Add("Scanner   : $env:COMPUTERNAME")
    $lines.Add("Subnet    : $($Report.subnet)")
    $lines.Add("Scan time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add('')
    $lines.Add('--- Overview ---')
    $lines.Add("  Devices scanned    : $($Report.foundCount)")
    $lines.Add("  Baseline devices   : $($Report.baselineCount)")
    $lines.Add("  Rogue devices      : $($Report.rogueDevices.Count)")
    $lines.Add("  Absent devices     : $($Report.absentDevices.Count)  (not seen for $($Report.absentDays)+ days)")
    $lines.Add("  Risk findings      : $($Report.riskDevices.Count)")
    $lines.Add("  Identity changes   : $($Report.identityChanges.Count)")

    if ($Report.rogueDevices.Count -gt 0) {
        $lines.Add('')
        $lines.Add('--- Rogue Devices ---')
        $scriptPath = $PSCommandPath
        foreach ($d in $Report.rogueDevices) {
            $os = if ($d.osGuess) { "  OS: $($d.osGuess)" } else { '' }
            $lines.Add("  $($d.mac)  $($d.ip)  $($d.hostname)  [$($d.vendor)]$os")
            if ($d.riskLevel -and $d.riskLevel -ne 'NONE') {
                $lines.Add("    RISK: [$($d.riskLevel)] $($d.riskReasons -join '; ')")
            }
            $lines.Add("    -> Approve: & `"$scriptPath`" -Approve `"$($d.mac)`" -Label `"<description>`"")
        }
    }

    if ($Report.absentDevices.Count -gt 0) {
        $lines.Add('')
        $lines.Add("--- Absent Devices (not seen for $($Report.absentDays)+ days) ---")
        foreach ($d in $Report.absentDevices) {
            $label = if ($d.label) { "  Label: $($d.label)" } else { '' }
            $os    = if ($d.osGuess) { "  OS: $($d.osGuess)" } else { '' }
            $lines.Add("  $($d.mac)  Last IP: $($d.ip)  Last seen: $($d.lastSeen)$label$os")
        }
    }

    if ($Report.riskDevices.Count -gt 0) {
        $lines.Add('')
        $lines.Add('--- Risk Findings (known devices) ---')
        foreach ($d in $Report.riskDevices) {
            $lines.Add("  [$($d.riskLevel)] $($d.ip) ($($d.hostname)) - $($d.riskReasons -join '; ')")
        }
    }

    if ($Report.identityChanges.Count -gt 0) {
        $lines.Add('')
        $lines.Add('--- Identity Changes ---')
        foreach ($c in $Report.identityChanges) {
            $lines.Add("  $($c.mac)  $($c.ip)  hostname changed: '$($c.oldHostname)' -> '$($c.newHostname)'")
        }
    }

    # OS breakdown
    $osGroups = @($Report.foundDevices | Where-Object { $_.osGuess } | Group-Object osGuess | Sort-Object Count -Descending)
    if ($osGroups.Count -gt 0) {
        $lines.Add('')
        $lines.Add('--- OS Breakdown ---')
        foreach ($g in $osGroups) {
            $lines.Add("  $($g.Name.PadRight(20)): $($g.Count)")
        }
        $noOs = @($Report.foundDevices | Where-Object { -not $_.osGuess }).Count
        if ($noOs -gt 0) { $lines.Add("  $('Unknown'.PadRight(20)): $noOs") }
    }

    $status = if ($Report.rogueDevices.Count -gt 0) {
        "$($Report.rogueDevices.Count) ROGUE"
    } elseif ($Report.absentDevices.Count -gt 0 -or $Report.riskDevices.Count -gt 0) {
        'WARNINGS'
    } else {
        'OK'
    }
    $subject = "[$env:COMPUTERNAME] Network Health Report [$status] - $(Get-Date -Format 'yyyy-MM-dd')"

    $mailParams = @{
        From       = $SmtpConfig.from
        To         = $SmtpConfig.to
        Subject    = $subject
        Body       = $lines -join "`n"
        SmtpServer = $SmtpConfig.host
        Port       = [int]$SmtpConfig.port
        UseSsl     = $true
    }

    if ($SmtpConfig.user) {
        $securePass = ConvertTo-SecureString -String $SmtpConfig.password -AsPlainText -Force
        $mailParams.Credential = New-Object System.Management.Automation.PSCredential($SmtpConfig.user, $securePass)
    }

    try {
        Send-MailMessage @mailParams
        Write-RddLog "Summary report sent to $($SmtpConfig.to)."
    } catch {
        Write-RddLog "Failed to send summary report: $_" -Level ERROR
    }
}

# ── Main ───────────────────────────────────────────────────────────────────────
# Guard: skip main body when dot-sourced for unit testing (e.g. Pester)
if ($MyInvocation.InvocationName -eq '.') { return }

Write-RddLog "Rogue Device Detector v$SCRIPT_VERSION starting on $env:COMPUTERNAME"

# Load configuration
$configPath = if ($Config) { $Config } else { Join-Path $PSScriptRoot 'config.json' }
$cfg        = Get-Configuration -ConfigPath $configPath -SubnetOverride $Subnet

# ── Management commands (no scan required) ─────────────────────────────────────

if ($List) {
    $state = Get-State -StatePath $cfg.statePath
    Show-Baseline -State $state -StatePath $cfg.statePath
    exit 0
}

if ($Approve) {
    $state = Get-State -StatePath $cfg.statePath
    $now   = (Get-Date).ToUniversalTime().ToString('o')
    Invoke-ApproveDevice -Mac $Approve -Label $Label -State $state -Now $now
    Save-State -State $state -StatePath $cfg.statePath
    Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_APPROVED' `
        -Details "mac=$Approve label=$Label approvedBy=$env:USERDOMAIN\$env:USERNAME"
    exit 0
}

if ($Remove) {
    $state   = Get-State -StatePath $cfg.statePath
    $removed = Invoke-RemoveDevice -Mac $Remove -State $state
    if ($removed) {
        Save-State -State $state -StatePath $cfg.statePath
        Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_REMOVED' -Details "mac=$Remove removedBy=$env:USERDOMAIN\$env:USERNAME"
    }
    exit 0
}

# Resolve target subnet
$targetSubnet = if ($cfg.subnet) { $cfg.subnet } else { Get-LocalSubnet }
Write-AuditLog -LogPath $cfg.logPath -EventName 'SCAN_START' -Details "subnet=$targetSubnet mode=$(if ($LearningMode) { 'learning' } else { 'normal' })"
Write-RddLog "Target subnet: $targetSubnet"
$subnetInfo = Get-SubnetInfo -Cidr $targetSubnet

# Load OUI vendor database
$ouiDb = Get-OuiDatabase -CachePath $cfg.ouiPath

# Populate ARP cache via ping sweep (returns TTL map for OS fingerprinting)
$ttlMap = Invoke-PingSweep -SubnetInfo $subnetInfo
$arpEntries = Get-ArpEntry -SubnetInfo $subnetInfo
Write-RddLog "$($arpEntries.Count) device(s) found in ARP table."

if ($arpEntries.Count -eq 0) {
    Write-RddLog 'ARP table empty after ping sweep. Exiting.' -Level WARN
    exit 0
}

# Build device list, resolve hostnames concurrently, then look up vendors
$foundDevices = $arpEntries | ForEach-Object {
    $osGuess = if ($ttlMap.ContainsKey($_.IP)) { Get-OsGuess -Ttl $ttlMap[$_.IP] } else { '' }
    [PSCustomObject]@{
        mac         = $_.MAC
        ip          = $_.IP
        hostname    = $_.IP   # placeholder, overwritten by Resolve-Hostname
        vendor      = ''
        osGuess     = $osGuess
        openPorts   = @()
        httpBanner  = ''
        upnpInfo    = ''
        riskLevel   = 'NONE'
        riskReasons = @()
    }
}

Resolve-Hostname -Devices $foundDevices

foreach ($d in $foundDevices) {
    $d.vendor = Get-MacVendor -Mac $d.mac -OuiDb $ouiDb
}

if ($cfg.enrichment) {
    Invoke-DeviceEnrichment -Devices $foundDevices
}

# Load state
$stateFileExists = Test-Path $cfg.statePath
$state           = Get-State -StatePath $cfg.statePath
$now             = (Get-Date).ToUniversalTime().ToString('o')

# Learning mode: merge found devices into baseline without alerts
if ($LearningMode -or -not $stateFileExists) {
    if (-not $stateFileExists) {
        Write-RddLog 'No state file found - creating baseline (learning mode).'
    } else {
        Write-RddLog 'Learning mode - merging found devices into baseline.'
    }

    $newDevices = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($device in $foundDevices) {
        $known = @($state.knownDevices) | Where-Object { $_.mac -eq $device.mac } | Select-Object -First 1
        if ($known) {
            $previousHost = Test-IdentityChange -KnownDevice $known -FoundDevice $device
            if ($previousHost) {
                Write-RddLog "IDENTITY CHANGE: $($device.mac) hostname changed from '$previousHost' to '$($device.hostname)'" -Level WARN
                Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_CHANGED' -Device $device `
                    -Details "previousHostname=$previousHost"
            }
            $known.lastSeen = $now
            $known.ip       = $device.ip
            $known.hostname = $device.hostname
            $known.osGuess  = $device.osGuess
        } else {
            $newDevices.Add($device)
            $state.knownDevices += [PSCustomObject]@{
                mac        = $device.mac
                ip         = $device.ip
                hostname   = $device.hostname
                vendor     = $device.vendor
                osGuess    = $device.osGuess
                label      = ''
                firstSeen  = $now
                lastSeen   = $now
                approvedBy = "$env:USERDOMAIN\$env:USERNAME"
                approvedAt = $now
            }
        }
    }

    $state.lastScan = $now
    Save-State -State $state -StatePath $cfg.statePath
    Write-RddLog "Baseline saved: $($state.knownDevices.Count) device(s) -> $($cfg.statePath)"

    if ($newDevices.Count -gt 0) {
        Write-RddLog "--- SIMULATED ALERT: $($newDevices.Count) new device(s) added to baseline ---"
        foreach ($d in $newDevices) {
            $riskTag = if ($d.riskLevel -ne 'NONE') { " [$($d.riskLevel)]" } else { '' }
            Write-RddLog "  NEW  MAC: $($d.mac)  IP: $($d.ip)  Hostname: $($d.hostname)  Vendor: $($d.vendor)$riskTag"
            if ($d.riskReasons -and $d.riskReasons.Count -gt 0) {
                Write-RddLog "       RISK: $($d.riskReasons -join '; ')" -Level WARN
            }
            Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_NEW' -Device $d -Details 'Added to baseline'
        }
        Write-RddLog '--- In normal scan mode these would trigger an alert email. ---'
    } else {
        Write-RddLog 'No new devices found - baseline unchanged.'
    }

    Write-AuditLog -LogPath $cfg.logPath -EventName 'SCAN_DONE' `
        -Details "found=$($foundDevices.Count) new=$($newDevices.Count) mode=learning"
    exit 0
}

# Normal scan: compare found devices against baseline
$rogueDevices    = [System.Collections.Generic.List[PSCustomObject]]::new()
$identityChanges = [System.Collections.Generic.List[hashtable]]::new()

foreach ($device in $foundDevices) {
    $known = @($state.knownDevices) | Where-Object { $_.mac -eq $device.mac } | Select-Object -First 1
    if ($known) {
        $previousHost = Test-IdentityChange -KnownDevice $known -FoundDevice $device
        if ($previousHost) {
            Write-RddLog "IDENTITY CHANGE: $($device.mac) hostname changed from '$previousHost' to '$($device.hostname)'" -Level WARN
            Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_CHANGED' -Device $device `
                -Details "previousHostname=$previousHost"
            $identityChanges.Add(@{
                mac         = $device.mac
                ip          = $device.ip
                oldHostname = $previousHost
                newHostname = $device.hostname
            })
        }
        $known.lastSeen = $now
        $known.ip       = $device.ip
        $known.hostname = $device.hostname
        $known.osGuess  = $device.osGuess
    } else {
        $riskTag = if ($device.riskLevel -ne 'NONE') { " [$($device.riskLevel)]" } else { '' }
        Write-RddLog "ROGUE: $($device.mac)  $($device.ip)  $($device.hostname)  [$($device.vendor)]$riskTag" -Level WARN
        $rogueDevices.Add($device)
        Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_ROGUE' -Device $device `
            -Details ($device.riskReasons -join '; ')
    }
}

# Log risk findings for known devices with HIGH or CRITICAL risk
$riskDevices = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($device in $foundDevices) {
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

# Detect devices that have not been seen for too long
$absentDevices = Get-AbsentDevices -KnownDevices @($state.knownDevices) `
    -AbsentDays $cfg.absentDays -Now $now
if ($absentDevices.Count -gt 0) {
    Write-RddLog "$($absentDevices.Count) device(s) not seen for $($cfg.absentDays)+ days." -Level WARN
    foreach ($d in $absentDevices) {
        $label = if ($d.label) { " ($($d.label))" } else { '' }
        Write-RddLog "  ABSENT: $($d.mac)$label  Last seen: $($d.lastSeen)" -Level WARN
        Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_ABSENT' -Device $d `
            -Details "lastSeen=$($d.lastSeen) absentDays=$($cfg.absentDays)"
    }
}

$state.lastScan = $now
Save-State -State $state -StatePath $cfg.statePath

$riskCount = @($foundDevices | Where-Object { $_.riskLevel -ne 'NONE' }).Count
Write-AuditLog -LogPath $cfg.logPath -EventName 'SCAN_DONE' `
    -Details "found=$($foundDevices.Count) rogue=$($rogueDevices.Count) absent=$($absentDevices.Count) risks=$riskCount mode=normal"

# Send alerts / summary report
if ($cfg.summaryReport) {
    $report = @{
        subnet          = $targetSubnet
        foundCount      = $foundDevices.Count
        foundDevices    = $foundDevices
        baselineCount   = @($state.knownDevices).Count
        rogueDevices    = $rogueDevices.ToArray()
        absentDevices   = $absentDevices
        absentDays      = $cfg.absentDays
        riskDevices     = $riskDevices.ToArray()
        identityChanges = $identityChanges.ToArray()
    }
    Send-SummaryReport -Report $report -SmtpConfig $cfg.smtp
} elseif ($rogueDevices.Count -gt 0) {
    Write-RddLog "$($rogueDevices.Count) rogue device(s) detected."
    Send-RogueAlert -Devices $rogueDevices.ToArray() -SmtpConfig $cfg.smtp
} else {
    Write-RddLog 'Scan complete - all devices are known.'
}

# Exit code bitmask for RMM integration (e.g. NinjaRMM conditions)
#   0 = clean, 1 = rogue devices, 2 = high/critical risk, 4 = absent devices
$exitCode = 0
if ($rogueDevices.Count -gt 0) { $exitCode = $exitCode -bor 1 }
if ($riskDevices.Count -gt 0)  { $exitCode = $exitCode -bor 2 }
if ($absentDevices.Count -gt 0) { $exitCode = $exitCode -bor 4 }
exit $exitCode
