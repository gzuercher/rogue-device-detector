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

.PARAMETER ApproveDevice
    MAC address to approve and add to the baseline (e.g. "AA:BB:CC:DD:EE:FF").
    Optionally combine with -Label to store a human-readable device name.
    Use this to approve a specific device shown in an alert without a full scan.

.PARAMETER Label
    Human-readable name for the device being approved (e.g. "John's laptop").
    Only used together with -ApproveDevice.

.PARAMETER RemoveDevice
    MAC address to remove from the baseline (e.g. "AA:BB:CC:DD:EE:FF").
    Use this to un-approve a device that was added by mistake or left the network.

.PARAMETER ListDevices
    Displays all approved devices in the baseline and exits.
    No scan is performed.

.PARAMETER AllowPort
    One or more port numbers to add to the allowed-ports list for a device.
    Must be used together with -On to specify the target MAC address.

.PARAMETER BlockPort
    One or more port numbers to remove from the allowed-ports list for a device.
    Must be used together with -On to specify the target MAC address.

.PARAMETER On
    MAC address of the device to modify when using -AllowPort or -BlockPort.

.EXAMPLE
    .\rogue-device-detector.ps1 -LearningMode
    First-time setup: merge every found device into the baseline without alerts.

.EXAMPLE
    .\rogue-device-detector.ps1
    Regular scan; sends an alert email if rogue/risk/absent devices are found.

.EXAMPLE
    .\rogue-device-detector.ps1 -Subnet "10.0.1.0/24"
    Override the auto-detected subnet for a single run.

.EXAMPLE
    .\rogue-device-detector.ps1 -ApproveDevice "AA:BB:CC:DD:EE:FF" -Label "John's laptop"
    Approve a single device from an alert without re-scanning.

.EXAMPLE
    .\rogue-device-detector.ps1 -RemoveDevice "AA:BB:CC:DD:EE:FF"
    Remove a device that left the network.

.EXAMPLE
    .\rogue-device-detector.ps1 -ListDevices
    Print all approved devices in the baseline.

.EXAMPLE
    .\rogue-device-detector.ps1 -AllowPort 80,443 -On "AA:BB:CC:DD:EE:FF"
    Allowlist ports 80 and 443 on a known device (suppresses risk warnings).

.EXAMPLE
    .\rogue-device-detector.ps1 -BlockPort 23 -On "AA:BB:CC:DD:EE:FF"
    Revoke a previously allowlisted port.

.EXAMPLE
    .\rogue-device-detector.ps1 -ApproveAllRogues
    Run a full scan and add every detected rogue device to the baseline in
    one go. Useful when reviewing alerts in bulk after a known network
    change. Risk findings are NOT auto-allowed - any risky open ports on
    the approved devices will be reported as RISK on the next scan.

.EXAMPLE
    .\rogue-device-detector.ps1 -Version
    Print the script version and exit.

.EXAMPLE
    .\rogue-device-detector.ps1 -TestSmtp
    Send a test email to the configured recipient and exit, without scanning.
    Use during initial setup to validate smtp.host / port / credentials / TLS.

.EXAMPLE
    .\rogue-device-detector.ps1 -DryRun
    Run a full scan but do not save state, do not send mail, do not write
    to the audit log. Useful for testing config changes without side effects.
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(ParameterSetName = 'Scan')]
    [Parameter(ParameterSetName = 'ApproveAllRogues')]
    [string]$Config = '',

    [Parameter(ParameterSetName = 'Scan')]
    [Parameter(ParameterSetName = 'ApproveAllRogues')]
    [string]$Subnet = '',

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$LearningMode,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$DryRun,

    [Parameter(Mandatory, ParameterSetName = 'ApproveAllRogues')]
    [switch]$ApproveAllRogues,

    [Parameter(Mandatory, ParameterSetName = 'Version')]
    [switch]$Version,

    [Parameter(Mandatory, ParameterSetName = 'TestSmtp')]
    [switch]$TestSmtp,

    [Parameter(ParameterSetName = 'TestSmtp')]
    [string]$TestSmtpConfig = '',

    [Parameter(Mandatory, ParameterSetName = 'ApproveDevice')]
    [ValidateNotNullOrEmpty()]
    [string]$ApproveDevice,

    [Parameter(ParameterSetName = 'ApproveDevice')]
    [string]$Label = '',

    [Parameter(Mandatory, ParameterSetName = 'RemoveDevice')]
    [ValidateNotNullOrEmpty()]
    [string]$RemoveDevice,

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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ──────────────────────────────────────────────────────────────────

$SCRIPT_VERSION       = '1.5.2'
$OUI_URL              = 'https://standards-oui.ieee.org/oui/oui.csv'
$OUI_MAX_AGE_DAYS     = 30
$STATE_SCHEMA_VERSION = 4

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

# Audit log rotation: when the active CSV exceeds this size, it is renamed to
# <base>.YYYY-MM-DD-HHmmss.csv and a fresh file is started. Old rotations are
# kept on disk for the operator to archive or prune.
$AUDIT_LOG_MAX_BYTES = 10MB

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
        configured    = $true
        smtp          = @{
            host     = ''
            port     = 587
            user     = ''
            password = ''
            from     = ''
            to       = ''
            useSsl   = $true
        }
    }

    $useSslExplicit = $false
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
            if ($p['configured']    -and $null -ne $file.configured)    { $cfg.configured    = [bool]$file.configured }
            if ($p['smtp'] -and $null -ne $file.smtp) {
                $sp = $file.smtp.PSObject.Properties
                if ($sp['host']     -and $file.smtp.host)     { $cfg.smtp.host     = $file.smtp.host }
                if ($sp['port']     -and $file.smtp.port)     { $cfg.smtp.port     = [int]$file.smtp.port }
                if ($sp['user']     -and $file.smtp.user)     { $cfg.smtp.user     = $file.smtp.user }
                if ($sp['password'] -and $file.smtp.password) { $cfg.smtp.password = $file.smtp.password }
                if ($sp['from']     -and $file.smtp.from)     { $cfg.smtp.from     = $file.smtp.from }
                if ($sp['to']       -and $file.smtp.to)       { $cfg.smtp.to       = $file.smtp.to }
                if ($sp['useSsl']   -and $null -ne $file.smtp.useSsl) {
                    $cfg.smtp.useSsl = [bool]$file.smtp.useSsl
                    $useSslExplicit  = $true
                }
            }
        } catch {
            Write-RddLog "Could not parse config file '$ConfigPath': $_" -Level WARN
        }
    } else {
        Write-RddLog "Config file not found at '$ConfigPath'. Using defaults." -Level WARN
    }

    # Sane SMTP-SSL default: plain on port 25 (typical local relay), TLS otherwise.
    # Honour an explicit useSsl value in the config without override.
    if (-not $useSslExplicit) {
        $cfg.smtp.useSsl = ($cfg.smtp.port -ne 25)
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
    if ($prefix -lt 0 -or $prefix -gt 32) { throw "Invalid prefix length: $prefix (must be 0-32)" }
    if ($prefix -ge 31) {
        throw "Prefix /$prefix is not scannable (no usable host addresses)."
    }

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

function Get-OsLabel {
    <#
    .SYNOPSIS
        Combines TTL guess with service banners into the most informative
        OS label available. Banner-derived strings (which usually identify
        distro + version) win over the coarse TTL bucket.
    .PARAMETER TtlGuess     Coarse OS family from Get-OsGuess.
    .PARAMETER HttpBanner   Output of Get-HttpBanner.
    .PARAMETER SshBanner    Output of Get-SshBanner.
    .PARAMETER TelnetBanner Output of Get-TelnetBanner.
    #>
    param(
        [string]$TtlGuess     = '',
        [string]$HttpBanner   = '',
        [string]$SshBanner    = '',
        [string]$TelnetBanner = ''
    )

    # SSH banner: 'SSH-2.0-OpenSSH_9.6 Ubuntu-22.04' -> 'Ubuntu 22.04'
    if ($SshBanner -match 'SSH-2\.0-OpenSSH[_\s]\S+\s+(Debian|Ubuntu|Alpine|CentOS|Fedora|FreeBSD|OpenBSD|NetBSD|Raspbian)[\s\-]?(\S+)?') {
        $distro = $Matches[1]
        $ver    = if ($Matches[2]) { " $($Matches[2])" } else { '' }
        return "$distro$ver".Trim()
    }
    if ($SshBanner -match 'SSH-2\.0-(dropbear|libssh|paramiko|cisco|wolfssh)') {
        return "$($Matches[1].ToUpper().Substring(0,1))$($Matches[1].Substring(1)) host"
    }

    # HTTP banner: 'nginx/1.24.0 (Ubuntu)' or 'Apache/2.4.41 (Ubuntu)'
    if ($HttpBanner -match '\(([A-Za-z][\w\-/. ]{1,30})\)') {
        $parens = $Matches[1].Trim()
        if ($parens -match '^(Ubuntu|Debian|CentOS|Fedora|RHEL|Win\d+|FreeBSD|Synology|Unix)') {
            return $parens
        }
    }

    # Telnet banner: hostnames/banners often reveal vendor directly
    if ($TelnetBanner -match '(Cisco|Hikvision|MikroTik|Synology|FreeBSD|HP\s*ProCurve|Aruba|FortiGate|Ubiquiti)') {
        return $Matches[1]
    }

    return $TtlGuess
}

function Get-SshBanner {
    <#
    .SYNOPSIS
        Reads the SSH protocol banner (first line server sends on connect).
        Format: 'SSH-2.0-<software> <comment>'.
    .RETURNS Banner string or empty on failure / port closed.
    #>
    param(
        [Parameter(Mandatory)][string]$IP,
        [int]$Port = 22,
        [int]$TimeoutMs = 1500
    )

    if ($Port -ne 22) { return '' }
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $task   = $client.ConnectAsync($IP, $Port)
        if (-not $task.Wait($TimeoutMs)) { return '' }
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $buf  = [byte[]]::new(256)
        $read = $stream.Read($buf, 0, 256)
        if ($read -gt 0) {
            $line = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
            return ($line -split "`n" | Select-Object -First 1).Trim()
        }
    } catch { $null = $_ }
    finally { if ($client) { try { $client.Dispose() } catch { $null = $_ } } }
    return ''
}

function Get-TelnetBanner {
    <#
    .SYNOPSIS
        Grabs the first chunk of a Telnet session, stripping IAC negotiation
        bytes. The remaining text is usually a vendor banner or login prompt.
    .RETURNS Printable banner or empty on failure.
    #>
    param(
        [Parameter(Mandatory)][string]$IP,
        [int]$Port = 23,
        [int]$TimeoutMs = 1500
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $task   = $client.ConnectAsync($IP, $Port)
        if (-not $task.Wait($TimeoutMs)) { return '' }
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $buf  = [byte[]]::new(512)
        $read = $stream.Read($buf, 0, 512)
        if ($read -le 0) { return '' }

        # Strip Telnet IAC (0xFF) negotiation triplets.
        $sb = [System.Text.StringBuilder]::new()
        $i = 0
        while ($i -lt $read) {
            if ($buf[$i] -eq 0xFF -and ($i + 2) -lt $read) {
                $i += 3   # skip IAC + verb + option
                continue
            }
            $b = $buf[$i]
            if ($b -ge 0x20 -and $b -lt 0x7F) {
                [void]$sb.Append([char]$b)
            } elseif ($b -eq 0x0A -or $b -eq 0x0D) {
                [void]$sb.Append(' ')
            }
            $i++
        }
        return $sb.ToString().Trim() -replace '\s+', ' '
    } catch { $null = $_ }
    finally { if ($client) { try { $client.Dispose() } catch { $null = $_ } } }
    return ''
}

function Get-RelativeAge {
    <#
    .SYNOPSIS
        Formats an ISO timestamp as a short relative-age string.
        today | yesterday | N days ago | YYYY-MM-DD (for older dates)
    #>
    param(
        [string]$IsoTimestamp,
        [datetime]$Now = (Get-Date).ToUniversalTime()
    )
    if (-not $IsoTimestamp) { return '' }
    try {
        $then = [datetime]::Parse($IsoTimestamp).ToUniversalTime()
        $diff = $Now - $then
        if ($diff.TotalHours -lt 24) { return 'today' }
        if ($diff.TotalHours -lt 48) { return 'yesterday' }
        if ($diff.TotalDays  -lt 14) { return ("{0} days ago" -f [int]$diff.TotalDays) }
        return $then.ToString('yyyy-MM-dd')
    } catch {
        return $IsoTimestamp
    }
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

function Resolve-HostnameNetBios {
    <#
    .SYNOPSIS
        Attempts NetBIOS name resolution for a single IP address via UDP port 137.
    .PARAMETER IP Target IP address.
    .PARAMETER TimeoutMs Timeout in milliseconds.
    .RETURNS Hostname string or empty string if resolution failed.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns', '',
        Justification = 'NetBios is a proper name (NetBIOS), not a plural noun.'
    )]
    param(
        [Parameter(Mandatory)][string]$IP,
        [int]$TimeoutMs = 1500
    )

    try {
        $client = [System.Net.Sockets.UdpClient]::new()
        $client.Client.ReceiveTimeout = $TimeoutMs

        # NetBIOS Name Query: transaction ID 0x0001, standard query, 1 question, wildcard name *
        $query = [byte[]](
            0x00, 0x01,  # Transaction ID
            0x00, 0x00,  # Flags: standard query
            0x00, 0x01,  # Questions: 1
            0x00, 0x00,  # Answer RRs: 0
            0x00, 0x00,  # Authority RRs: 0
            0x00, 0x00,  # Additional RRs: 0
            0x20,        # Name length: 32
            # Encoded wildcard name "*" (0x2A padded to 16 bytes, half-ASCII encoded)
            0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x00,        # Name terminator
            0x00, 0x21,  # Type: NBSTAT
            0x00, 0x01   # Class: IN
        )

        $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($IP), 137)
        $client.Send($query, $query.Length, $ep) | Out-Null

        $remote   = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $response = $client.Receive([ref]$remote)
        $client.Dispose()

        if ($response.Length -gt 57) {
            $nameCount = $response[56]
            if ($nameCount -gt 0) {
                $nameBytes = $response[57..72]
                $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).Trim()
                if ($name -and $name -notmatch '^\s*$') {
                    return $name
                }
            }
        }
    } catch {
        $null = $_
    } finally {
        if ($client) { try { $client.Dispose() } catch { $null = $_ } }
    }
    return ''
}

function Resolve-Hostname {
    <#
    .SYNOPSIS
        Resolves hostnames for an array of devices concurrently via async DNS.
        All requests are fired simultaneously with a 2-second timeout.
        Falls back to NetBIOS name resolution for unresolved devices.
        Updates the hostname property of each device object in place.
    .PARAMETER Devices Array of PSCustomObjects with an 'ip' property.
    #>
    param([Parameter(Mandatory)][array]$Devices)

    $timeoutMs = 2000
    $total     = @($Devices).Count

    Write-RddLog "Resolving hostnames via DNS for $total device(s)..."

    # Fire all DNS requests concurrently before waiting for any
    $tasks = $Devices | ForEach-Object {
        [PSCustomObject]@{
            Device      = $_
            DnsTask     = [System.Net.Dns]::GetHostEntryAsync($_.ip)
            TimeoutTask = [System.Threading.Tasks.Task]::Delay($timeoutMs)
        }
    }

    # Create a combined task that completes when ALL WhenAny pairs are done
    $whenAnyTasks = $tasks | ForEach-Object {
        [System.Threading.Tasks.Task]::WhenAny(
            [System.Threading.Tasks.Task[]]@($_.DnsTask, $_.TimeoutTask)
        )
    }
    # Wait for all WhenAny tasks to complete (truly concurrent)
    [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($whenAnyTasks))

    $resolved = 0
    $unresolved = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($t in $tasks) {
        try {
            if ($t.DnsTask.Status -eq 'RanToCompletion') {
                $h = $t.DnsTask.Result.HostName
                if ($h -and $h -ne $t.Device.ip) {
                    $t.Device.hostname = $h
                    $resolved++
                    continue
                }
            }
        } catch { $null = $_ }
        $unresolved.Add($t.Device)
    }

    # NetBIOS fallback for unresolved devices
    if ($unresolved.Count -gt 0) {
        Write-RddLog "Trying NetBIOS fallback for $($unresolved.Count) unresolved device(s)..."
        foreach ($d in $unresolved) {
            $nbName = Resolve-HostnameNetBios -IP $d.ip
            if ($nbName) {
                $d.hostname = $nbName
                $resolved++
            }
        }
    }

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

    # Disable certificate validation once for all HTTPS banner grabs (self-signed certs are common on network devices)
    $isPS5 = $PSVersionTable.PSVersion.Major -lt 7
    if ($isPS5) {
        $prevCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    try {
    foreach ($port in $webPorts) {
        $scheme = if ($port -in @(443, 8443)) { 'https' } else { 'http' }
        $url    = "${scheme}://${IP}:${port}/"
        try {
            $iwrParams = @{
                Uri            = $url
                TimeoutSec     = 3
                UseBasicParsing = $true
                ErrorAction    = 'Stop'
                UserAgent      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }
            if (-not $isPS5) {
                $iwrParams['SkipCertificateCheck'] = $true
            }
            $response = Invoke-WebRequest @iwrParams
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($response.Content -match '<title[^>]*>([^<]{2,80})</title>') {
                $parts.Add($Matches[1].Trim())
            }
            $server = $response.Headers['Server']
            if ($server) { $parts.Add("Server: $server") }
            if ($parts.Count -gt 0) { return $parts -join ' | ' }
        } catch {
            # Connection failures, resets, and HTTP errors are expected for network devices
            continue
        }
    }
    } finally {
        if ($isPS5) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCallback
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

    if (@($AllowedPorts).Count -eq 0) {
        return [PSCustomObject]@{ Level = $Device.riskLevel; Reasons = $Device.riskReasons }
    }

    # Defensive: Get-State normalises allowedPorts on load, but if a malformed
    # entry slips through (e.g. baseline edited mid-scan), don't crash the run.
    $allowedPortNumbers = @($AllowedPorts | ForEach-Object {
        if ($null -eq $_) { return }
        if ($_ -is [int] -or $_ -is [long]) { $_ }
        elseif ($_ -is [string]) { [int]$_ }
        elseif ($_.PSObject.Properties['port']) { $_.port }
    } | Where-Object { $null -ne $_ })
    $remainingPorts = @($Device.openPorts | Where-Object { $_ -notin $allowedPortNumbers })

    return Get-DeviceRisk -OpenPorts $remainingPorts
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

        $d.openPorts    = @(Invoke-PortScan -IP $d.ip)
        $d.httpBanner   = Get-HttpBanner  -IP $d.ip -OpenPorts $d.openPorts
        $d.sshBanner    = if (22 -in $d.openPorts) { Get-SshBanner    -IP $d.ip } else { '' }
        $d.telnetBanner = if (23 -in $d.openPorts) { Get-TelnetBanner -IP $d.ip } else { '' }
        $d.upnpInfo     = if ($upnpMap.ContainsKey($d.ip)) { $upnpMap[$d.ip] } else { '' }
        $d.osLabel      = Get-OsLabel -TtlGuess $d.osGuess `
                                       -HttpBanner $d.httpBanner `
                                       -SshBanner  $d.sshBanner `
                                       -TelnetBanner $d.telnetBanner
        $risk           = Get-DeviceRisk  -OpenPorts $d.openPorts
        $d.riskLevel    = $risk.Level
        $d.riskReasons  = $risk.Reasons
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

    # DryRun mode: skip audit writes so a test scan leaves no trace.
    if ((Get-Variable -Name DryRun -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) { return }

    $logDir = Split-Path $LogPath -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Size-based rotation: if the active log exceeds the cap, move it aside
    # with a timestamp suffix. Keeps the active CSV manageable as an email
    # attachment without losing history.
    if (Test-Path $LogPath) {
        $size = (Get-Item $LogPath).Length
        if ($size -gt $AUDIT_LOG_MAX_BYTES) {
            $base    = [System.IO.Path]::GetFileNameWithoutExtension($LogPath)
            $ext     = [System.IO.Path]::GetExtension($LogPath)
            $stamp   = Get-Date -Format 'yyyy-MM-dd-HHmmss'
            $rotated = Join-Path $logDir "$base.$stamp$ext"
            try {
                Move-Item -Path $LogPath -Destination $rotated -Force -ErrorAction Stop
            } catch {
                # Log rotation must never break the scan; carry on appending.
                $null = $_
            }
        }
    }

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
             ((Get-Item $CachePath).Length -eq 0) -or
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
            # Remove empty file left behind by failed Invoke-WebRequest -OutFile
            if ((Test-Path $CachePath) -and (Get-Item $CachePath).Length -eq 0) {
                Remove-Item $CachePath -Force -ErrorAction SilentlyContinue
            }
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
        Handles schema migration from older versions automatically.
    .PARAMETER StatePath Path to state.json.
    .RETURNS PSCustomObject with schemaVersion, lastScan, and knownDevices properties.
    #>
    param([Parameter(Mandatory)][string]$StatePath)

    if (Test-Path $StatePath) {
        $raw = Get-Content $StatePath -Raw | ConvertFrom-Json
        # Guard against empty/corrupt state file
        if ($null -eq $raw) {
            Write-RddLog "State file '$StatePath' is empty or corrupt - creating fresh baseline." -Level WARN
            return [PSCustomObject]@{
                schemaVersion = $STATE_SCHEMA_VERSION
                lastScan      = $null
                knownDevices  = @()
                seenRogues    = @()
            }
        }
        # Ensure lastScan property exists (older state files may lack it)
        if (-not ($raw.PSObject.Properties['lastScan'])) {
            Add-Member -InputObject $raw -NotePropertyName 'lastScan' -NotePropertyValue $null -Force
        }
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

        # Schema migration: add missing fields from older versions
        $requiredDeviceFields = @{ osGuess = '' }
        foreach ($d in @($raw.knownDevices)) {
            foreach ($field in $requiredDeviceFields.Keys) {
                if (-not ($d.PSObject.Properties[$field])) {
                    $d | Add-Member -MemberType NoteProperty -Name $field -Value $requiredDeviceFields[$field]
                }
            }
            # ConvertFrom-Json turns "allowedPorts": [] into $null on PS 5.1;
            # normalise to a real empty array so downstream code can iterate safely.
            if (-not $d.PSObject.Properties['allowedPorts'] -or $null -eq $d.allowedPorts) {
                $d | Add-Member -NotePropertyName 'allowedPorts' -NotePropertyValue @() -Force
            }
            # Canonicalise each allowedPorts entry to PSCustomObject with .port (int).
            # Tolerates legacy/manually-edited baselines using bare ints/strings.
            $d.allowedPorts = @(@($d.allowedPorts) | ForEach-Object {
                if ($null -eq $_) { return }
                if ($_ -is [int] -or $_ -is [long] -or $_ -is [string]) {
                    [PSCustomObject]@{
                        port      = [int]$_
                        allowedBy = ''
                        allowedAt = ''
                    }
                } elseif ($_.PSObject.Properties['port']) {
                    $_
                }
            })
        }

        # Ensure schemaVersion exists
        if (-not ($raw.PSObject.Properties['schemaVersion'])) {
            Add-Member -InputObject $raw -NotePropertyName 'schemaVersion' `
                -NotePropertyValue $STATE_SCHEMA_VERSION -Force
        }
        # v3 -> v4 migration: seenRogues tracks unapproved-but-recurring MACs so
        # the rogue alert can show "first seen N days ago" instead of always today.
        if (-not $raw.PSObject.Properties['seenRogues'] -or $null -eq $raw.seenRogues) {
            Add-Member -InputObject $raw -NotePropertyName 'seenRogues' `
                -NotePropertyValue ([object[]]@()) -Force
        }
        return $raw
    }

    return [PSCustomObject]@{
        schemaVersion = $STATE_SCHEMA_VERSION
        lastScan      = $null
        knownDevices  = @()
        seenRogues    = @()
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

    # DryRun mode: skip persistence so a test scan leaves no trace.
    if ((Get-Variable -Name DryRun -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) { return }

    $stateDir = Split-Path $StatePath -Parent
    if ($stateDir -and -not (Test-Path $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }

    $State | ConvertTo-Json -Depth 10 | Set-Content -Path $StatePath -Encoding UTF8
}

# ── Alert ──────────────────────────────────────────────────────────────────────

function Invoke-SmtpTest {
    <#
    .SYNOPSIS
        Sends a one-shot self-test email to verify SMTP configuration.
        Sets $global:LASTEXITCODE to 0 on success, 1 on failure.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Password sourced from config file; plain-text conversion is unavoidable at this integration point.'
    )]
    param(
        [Parameter(Mandatory)][hashtable]$SmtpConfig,
        [Parameter(Mandatory)][string]$Version
    )

    if (-not $SmtpConfig.host -or -not $SmtpConfig.from -or -not $SmtpConfig.to) {
        Write-RddLog 'SMTP not configured (host/from/to required). Edit config.json first.' -Level ERROR
        $global:LASTEXITCODE = 1
        return
    }

    $useSsl = [bool]$SmtpConfig.useSsl
    Write-RddLog "Sending test email via SMTP $($SmtpConfig.host):$($SmtpConfig.port) (useSsl=$useSsl) ..."
    $mailParams = @{
        From       = $SmtpConfig.from
        To         = $SmtpConfig.to
        Subject    = "[$env:COMPUTERNAME] Rogue Device Detector - SMTP test - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Body       = "<p>This is a test email from <code>rogue-device-detector.ps1</code> v$Version running on <strong>$env:COMPUTERNAME</strong>.</p><p>If you received this, your SMTP configuration is working.</p>"
        BodyAsHtml = $true
        SmtpServer = $SmtpConfig.host
        Port       = [int]$SmtpConfig.port
        UseSsl     = $useSsl
    }
    if ($SmtpConfig.user) {
        $securePass            = ConvertTo-SecureString -String $SmtpConfig.password -AsPlainText -Force
        $mailParams.Credential = New-Object System.Management.Automation.PSCredential($SmtpConfig.user, $securePass)
    }
    try {
        Send-MailMessage @mailParams
        Write-RddLog "Test email sent to $($SmtpConfig.to)."
        $global:LASTEXITCODE = 0
    } catch {
        Write-RddLog "SMTP test failed: $_" -Level ERROR
        $global:LASTEXITCODE = 1
    }
}

function Send-RogueAlert {
    <#
    .SYNOPSIS
        Sends an HTML alert email summarising rogue devices, risk findings,
        and absent devices.
    .PARAMETER Devices             Rogue (unknown-MAC) devices.
    .PARAMETER SmtpConfig          Hashtable with SMTP connection settings.
    .PARAMETER RiskDevices         Known devices with HIGH/CRITICAL risk findings.
    .PARAMETER AbsentDevices       Known devices not seen for >= absentDays.
    .PARAMETER IdentityChangeCount Count of hostname-change events this scan.
    .PARAMETER Subnet              Scanned subnet (for the email header).
    .PARAMETER SeenRogues          State.seenRogues list (for "first seen" age in
                                   the rogue table).
    #>
    # Password is read from a plain-text config file; SecureString conversion at this
    # boundary is unavoidable without a full credential-store integration.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Password sourced from config file; plain-text conversion is unavoidable at this integration point.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'SeenRogues',
        Justification = 'SeenRogues is consumed inside the $firstSeenCell scriptblock via closure; PSSA cannot track that.'
    )]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Devices,
        [Parameter(Mandatory)][hashtable]$SmtpConfig,
        [array]$RiskDevices = @(),
        [array]$AbsentDevices = @(),
        [int]$IdentityChangeCount = 0,
        [string]$Subnet = '',
        [array]$SeenRogues = @()
    )

    if (-not $SmtpConfig.host -or -not $SmtpConfig.to -or -not $SmtpConfig.from) {
        Write-RddLog 'SMTP not configured - skipping email alert.' -Level WARN
        return
    }

    if (($Devices.Count + $RiskDevices.Count + $AbsentDevices.Count) -eq 0) {
        # Defensive: caller already gates this; nothing to report.
        return
    }

    $scriptPath = $PSCommandPath
    $hostname   = $env:COMPUTERNAME
    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Build a copy-paste-safe path token. Outlook can mangle '& "..."' on
    # paste (drops the leading '& "' and trailing '"'). For paths without
    # whitespace we emit the raw path so the line works even if quoting
    # gets stripped. For paths with spaces we fall back to the call operator
    # with single-quoted path (single quotes survive copy-paste better).
    $invokeToken = if ($scriptPath -match '\s') { "& '$scriptPath'" } else { $scriptPath }

    $esc = {
        param($t)
        if ($null -eq $t) { return '' }
        [System.Net.WebUtility]::HtmlEncode([string]$t)
    }

    $riskBadge = {
        param($Level)
        $bg = switch ($Level) {
            'CRITICAL' { '#dc2626' }
            'HIGH'     { '#ea580c' }
            'MEDIUM'   { '#d97706' }
            'LOW'      { '#ca8a04' }
            default    { '#718096' }
        }
        $safe = & $esc $Level
        "<span style=`"display:inline-block;padding:2px 8px;background:$bg;color:#fff;border-radius:3px;font-size:11px;font-weight:600;`">$safe</span>"
    }

    $codeBlock = {
        param($Code)
        $safe = & $esc $Code
        "<pre style=`"background:#1a202c;color:#cbd5e0;padding:10px 12px;margin:0 24px 8px;font-family:Consolas,Monaco,'Courier New',monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;`">$safe</pre>"
    }

    # Stack non-empty identifier hints for one device into a multi-line cell.
    # Defensive PSObject.Properties checks because some callers (e.g. Risk
    # devices in Send-SummaryReport, or hand-built test fixtures) may omit
    # banner/upnp fields entirely.
    $detailsCell = {
        param($Device)
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($pair in @(
            @{ Field='upnpInfo';     Label='upnp'   },
            @{ Field='httpBanner';   Label='http'   },
            @{ Field='sshBanner';    Label='ssh'    },
            @{ Field='telnetBanner'; Label='telnet' }
        )) {
            if ($Device.PSObject.Properties[$pair.Field]) {
                $val = $Device.($pair.Field)
                if ($val) { $lines.Add("$($pair.Label): $(& $esc $val)") }
            }
        }
        if ($lines.Count -eq 0) { return '<span style="color:#a0aec0;">-</span>' }
        ($lines -join '<br>')
    }

    $now = (Get-Date).ToUniversalTime()
    $firstSeenCell = {
        param($Mac)
        $entry = @($SeenRogues) | Where-Object { $_.mac -eq $Mac } | Select-Object -First 1
        $iso = if ($entry -and $entry.firstSeen) { $entry.firstSeen } else { $null }
        if (-not $iso) { return 'today' }
        Get-RelativeAge -IsoTimestamp ([string]$iso) -Now $now
    }

    $thStyle     = 'padding:10px;font-weight:600;color:#4a5568;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;background:#edf2f7;border-bottom:2px solid #cbd5e0;'
    $tdStyle     = 'padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;'
    $tdMono      = "$tdStyle font-family:Consolas,Monaco,monospace;font-size:12px;"
    $h2Style     = 'font-size:15px;margin:18px 24px 8px;color:#1a202c;font-weight:600;border-left:4px solid;padding-left:10px;'
    $tableStyle  = 'width:auto;min-width:calc(100% - 48px);margin:0 24px;border-collapse:collapse;border:1px solid #e2e8f0;'
    $actionLabel = 'font-size:11px;color:#718096;margin:10px 24px 4px;text-transform:uppercase;letter-spacing:0.4px;font-weight:600;'

    $criticalCount = @($RiskDevices | Where-Object { $_.riskLevel -eq 'CRITICAL' }).Count
    $highCount     = @($RiskDevices | Where-Object { $_.riskLevel -eq 'HIGH' }).Count

    # ---- Summary badges ----
    $summaryBadges = [System.Collections.Generic.List[string]]::new()
    $badgeStyle = 'display:inline-block;padding:6px 12px;border-radius:4px;font-weight:600;font-size:13px;margin:0 6px 6px 0;'
    if ($Devices.Count -gt 0) {
        $summaryBadges.Add("<span style=`"$badgeStyle background:#fed7d7;color:#c53030;`">$($Devices.Count) rogue</span>")
    }
    if ($RiskDevices.Count -gt 0) {
        $detail = if ($criticalCount -gt 0 -or $highCount -gt 0) { " ($criticalCount critical, $highCount high)" } else { '' }
        $summaryBadges.Add("<span style=`"$badgeStyle background:#feebc8;color:#9c4221;`">$($RiskDevices.Count) risk$detail</span>")
    }
    if ($AbsentDevices.Count -gt 0) {
        $summaryBadges.Add("<span style=`"$badgeStyle background:#e2e8f0;color:#4a5568;`">$($AbsentDevices.Count) absent</span>")
    }
    if ($IdentityChangeCount -gt 0) {
        $summaryBadges.Add("<span style=`"$badgeStyle background:#bee3f8;color:#2c5282;`">$IdentityChangeCount hostname change(s)</span>")
    }

    # ---- Rogue section ----
    $rogueSection = ''
    if ($Devices.Count -gt 0) {
        $rows = ($Devices | ForEach-Object {
            $d         = $_
            $macCell   = & $esc $d.mac
            $ipCell    = & $esc $d.ip
            $hostCell  = if ($d.hostname -and $d.hostname -ne $d.ip) { & $esc $d.hostname } else { '<span style="color:#a0aec0;">-</span>' }
            $vendor    = & $esc $d.vendor
            $osText    = if ($d.PSObject.Properties['osLabel'] -and $d.osLabel) { $d.osLabel } else { $d.osGuess }
            $os        = & $esc $osText
            $firstSeen = & $firstSeenCell $d.mac
            $details   = & $detailsCell  $d
            @"
<tr>
<td style="$tdMono white-space:nowrap;">$macCell</td>
<td style="$tdMono">$ipCell</td>
<td style="$tdStyle">$hostCell</td>
<td style="$tdStyle color:#4a5568;">$vendor</td>
<td style="$tdStyle color:#4a5568;">$os</td>
<td style="$tdStyle color:#4a5568;font-size:12px;">$firstSeen</td>
<td style="$tdStyle color:#4a5568;font-size:12px;line-height:1.4;">$details</td>
</tr>
"@
        }) -join "`n"

        # One generic command per use case, not per MAC. Operator copies the
        # MAC from the table and substitutes the placeholder.
        $approveCmds = @(
            "# Accept every rogue listed above in one go:"
            "$invokeToken -ApproveAllRogues"
            ""
            "# Or accept a single device (replace <MAC> from the table above):"
            "$invokeToken -ApproveDevice '<MAC>' -Label '<description>'"
        ) -join "`n"

        $rogueSection = @"
<h2 style="$h2Style border-left-color:#dc2626;">Rogue Devices ($($Devices.Count))</h2>
<table cellpadding="0" cellspacing="0" style="$tableStyle">
<thead>
<tr>
<th align="left" style="$thStyle">MAC</th>
<th align="left" style="$thStyle">IP</th>
<th align="left" style="$thStyle">Hostname</th>
<th align="left" style="$thStyle">Vendor</th>
<th align="left" style="$thStyle">OS</th>
<th align="left" style="$thStyle">First Seen</th>
<th align="left" style="$thStyle">Details</th>
</tr>
</thead>
<tbody>
$rows
</tbody>
</table>
<div style="$actionLabel">Actions on $(& $esc $hostname):</div>
$(& $codeBlock $approveCmds)
"@
    }

    # ---- Risk section ----
    $riskSection = ''
    if ($RiskDevices.Count -gt 0) {
        $rows = ($RiskDevices | ForEach-Object {
            $d        = $_
            $macCell  = & $esc $d.mac
            $ipCell   = & $esc $d.ip
            $hostCell = if ($d.hostname -and $d.hostname -ne $d.ip) { & $esc $d.hostname } else { '<span style="color:#a0aec0;">-</span>' }
            $reasons  = if ($d.riskReasons) { & $esc ($d.riskReasons -join '; ') } else { '' }
            $portsTxt = if ($d.openPorts -and $d.openPorts.Count -gt 0) { & $esc ($d.openPorts -join ', ') } else { '-' }
            $riskHtml = & $riskBadge $d.riskLevel
            $details  = & $detailsCell $d
            @"
<tr>
<td style="$tdMono white-space:nowrap;">$macCell</td>
<td style="$tdMono">$ipCell</td>
<td style="$tdStyle">$hostCell</td>
<td style="$tdStyle text-align:center;">$riskHtml</td>
<td style="$tdStyle color:#4a5568;">$reasons</td>
<td style="$tdMono">$portsTxt</td>
<td style="$tdStyle color:#4a5568;font-size:12px;line-height:1.4;">$details</td>
</tr>
"@
        }) -join "`n"

        # One generic template, not per MAC. Operator picks the MAC from the
        # table above and the port(s) from the Open Ports column.
        $allowCmds = "$invokeToken -AllowPort <port> -On '<MAC>'"

        $riskSection = @"
<h2 style="$h2Style border-left-color:#ea580c;">Risk Findings on Known Devices ($($RiskDevices.Count))</h2>
<table cellpadding="0" cellspacing="0" style="$tableStyle">
<thead>
<tr>
<th align="left" style="$thStyle">MAC</th>
<th align="left" style="$thStyle">IP</th>
<th align="left" style="$thStyle">Hostname</th>
<th align="center" style="$thStyle">Level</th>
<th align="left" style="$thStyle">Reasons</th>
<th align="left" style="$thStyle">Open Ports</th>
<th align="left" style="$thStyle">Details</th>
</tr>
</thead>
<tbody>
$rows
</tbody>
</table>
<div style="$actionLabel">If a port is intentional, allow it (replace &lt;MAC&gt; from the table and &lt;port&gt; from Open Ports):</div>
$(& $codeBlock $allowCmds)
"@
    }

    # ---- Absent section ----
    $absentSection = ''
    if ($AbsentDevices.Count -gt 0) {
        $rows = ($AbsentDevices | ForEach-Object {
            $d        = $_
            $macCell  = & $esc $d.mac
            $label    = if ($d.label) { & $esc $d.label } else { '<span style="color:#a0aec0;">-</span>' }
            $lastSeen = & $esc $d.lastSeen
            "<tr><td style=`"$tdMono white-space:nowrap;`">$macCell</td><td style=`"$tdStyle`">$label</td><td style=`"$tdMono`">$lastSeen</td></tr>"
        }) -join "`n"

        $absentSection = @"
<h2 style="$h2Style border-left-color:#718096;">Absent Devices ($($AbsentDevices.Count))</h2>
<table cellpadding="0" cellspacing="0" style="$tableStyle margin-bottom:8px;">
<thead>
<tr>
<th align="left" style="$thStyle">MAC</th>
<th align="left" style="$thStyle">Label</th>
<th align="left" style="$thStyle">Last Seen</th>
</tr>
</thead>
<tbody>
$rows
</tbody>
</table>
"@
    }

    # ---- Footer ----
    $listCmd = & $esc "$invokeToken -ListDevices"

    # ---- Assemble ----
    $subnetDisplay = if ($Subnet) { " &middot; subnet $(& $esc $Subnet)" } else { '' }
    $body = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Rogue Device Detector</title></head>
<body style="font-family:'Segoe UI',Arial,sans-serif;color:#1a202c;background:#f7fafc;margin:0;padding:20px;">
<div style="max-width:960px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;">

<div style="background:#1a202c;color:#fff;padding:18px 24px;">
<div style="font-size:18px;font-weight:600;letter-spacing:0.3px;">Rogue Device Detector</div>
<div style="font-size:13px;color:#a0aec0;margin-top:4px;">$(& $esc $hostname) &middot; $(& $esc $timestamp)$subnetDisplay</div>
</div>

<div style="padding:18px 24px;background:#f7fafc;border-bottom:1px solid #e2e8f0;">
<div style="font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;">Scan summary</div>
<div style="margin-top:10px;">
$($summaryBadges -join "`n")
</div>
</div>

$rogueSection
$riskSection
$absentSection

<div style="padding:14px 24px;background:#f7fafc;font-size:12px;color:#718096;border-top:1px solid #e2e8f0;line-height:1.6;">
Run <code style="background:#edf2f7;padding:1px 5px;border-radius:2px;font-size:12px;">$listCmd</code> on $(& $esc $hostname) for the full baseline.
</div>

</div>
</body>
</html>
"@

    # ---- Subject ----
    $subjectParts = [System.Collections.Generic.List[string]]::new()
    if ($Devices.Count -gt 0)       { $subjectParts.Add("$($Devices.Count) rogue") }
    if ($RiskDevices.Count -gt 0)   { $subjectParts.Add("$($RiskDevices.Count) risk") }
    if ($AbsentDevices.Count -gt 0) { $subjectParts.Add("$($AbsentDevices.Count) absent") }

    $useSsl = if ($SmtpConfig.ContainsKey('useSsl') -and $null -ne $SmtpConfig.useSsl) {
        [bool]$SmtpConfig.useSsl
    } else { $true }

    $mailParams = @{
        From       = $SmtpConfig.from
        To         = $SmtpConfig.to
        Subject    = "[$hostname] $($subjectParts -join ', ') - $(Get-Date -Format 'yyyy-MM-dd')"
        Body       = $body
        BodyAsHtml = $true
        SmtpServer = $SmtpConfig.host
        Port       = [int]$SmtpConfig.port
        UseSsl     = $useSsl
    }

    if ($SmtpConfig.user) {
        $securePass            = ConvertTo-SecureString -String $SmtpConfig.password -AsPlainText -Force
        $mailParams.Credential = New-Object System.Management.Automation.PSCredential($SmtpConfig.user, $securePass)
    }

    try {
        Send-MailMessage @mailParams
        Write-RddLog "Alert sent to $($SmtpConfig.to)."
    } catch {
        Write-RddLog "Failed to send notification email via SMTP $($SmtpConfig.host):$($SmtpConfig.port) - $_" -Level ERROR
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
            allowedPorts = @()
        }
        Write-RddLog "Approved new device $mac$(if ($Label) { " (label: '$Label')" } else { '' }) - added to baseline."
    }

    # An approved MAC is no longer a rogue; clean it out of seenRogues.
    if ($State.PSObject.Properties['seenRogues']) {
        $State.seenRogues = @(@($State.seenRogues) | Where-Object { $_.mac -ne $mac })
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
        Write-RddLog "Blocked $removed port(s) on ${mac}: $($Ports -join ', ')"
    } else {
        Write-RddLog "Port(s) $($Ports -join ', ') not in allowed list for $mac." -Level WARN
    }
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
            $allowedPortsStr = if ($d.PSObject.Properties['allowedPorts'] -and @($d.allowedPorts).Count -gt 0) {
                " | Allowed ports: $((@($d.allowedPorts) | ForEach-Object { $_.port }) -join ', ')"
            } else { '' }
            Write-Host "  $($d.mac)  IP: $(($d.ip).PadRight(15))$hostname$vendor$osGuess$label$lastSeen$approvedBy$approvedAt$allowedPortsStr"
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
        $scriptPath  = $PSCommandPath
        $invokeToken = if ($scriptPath -match '\s') { "& '$scriptPath'" } else { $scriptPath }
        foreach ($d in $Report.rogueDevices) {
            $os = if ($d.osGuess) { "  OS: $($d.osGuess)" } else { '' }
            $lines.Add("  $($d.mac)  $($d.ip)  $($d.hostname)  [$($d.vendor)]$os")
            if ($d.riskLevel -and $d.riskLevel -ne 'NONE') {
                $lines.Add("    RISK: [$($d.riskLevel)] $($d.riskReasons -join '; ')")
            }
            $lines.Add("    -> Approve: $invokeToken -ApproveDevice '$($d.mac)' -Label '<description>'")
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
        $scriptPath  = $PSCommandPath
        $invokeToken = if ($scriptPath -match '\s') { "& '$scriptPath'" } else { $scriptPath }
        foreach ($d in $Report.riskDevices) {
            $lines.Add("  [$($d.riskLevel)] $($d.ip) ($($d.hostname)) - $($d.riskReasons -join '; ')")
            foreach ($reason in $d.riskReasons) {
                if ($reason -match '\(port (\d+)\)') {
                    $port = $Matches[1]
                    $lines.Add("    -> If expected: $invokeToken -AllowPort $port -On '$($d.mac)'")
                }
            }
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

    $useSsl = if ($SmtpConfig.ContainsKey('useSsl') -and $null -ne $SmtpConfig.useSsl) {
        [bool]$SmtpConfig.useSsl
    } else { $true }

    $mailParams = @{
        From       = $SmtpConfig.from
        To         = $SmtpConfig.to
        Subject    = $subject
        Body       = $lines -join "`n"
        SmtpServer = $SmtpConfig.host
        Port       = [int]$SmtpConfig.port
        UseSsl     = $useSsl
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

function Test-PathWritable {
    <#
    .SYNOPSIS
        Tests whether a file path is writable by attempting to open it for append.
    .PARAMETER FilePath Path to test.
    .RETURNS $true if writable, $false otherwise.
    #>
    param([Parameter(Mandatory)][string]$FilePath)

    $dir = Split-Path $FilePath -Parent
    if ($dir -and -not (Test-Path $dir)) {
        try { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        catch { return $false }
    }

    try {
        $stream = [System.IO.File]::Open($FilePath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::ReadWrite)
        $stream.Dispose()
        return $true
    } catch {
        return $false
    }
}

function Enter-ScanLock {
    <#
    .SYNOPSIS
        Acquires an exclusive lock file to prevent concurrent scans.
        Returns the lock file stream that must be disposed when done.
    .PARAMETER StatePath Path to state.json (lock file is derived from it).
    .RETURNS FileStream holding the lock, or $null if another scan is running.
    #>
    param([Parameter(Mandatory)][string]$StatePath)

    $lockPath = "$StatePath.lock"
    try {
        $stream = [System.IO.File]::Open($lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        $writer = [System.IO.StreamWriter]::new($stream)
        $writer.Write("locked by $env:COMPUTERNAME PID $PID at $(Get-Date -Format 'o')")
        $writer.Flush()
        return $stream
    } catch {
        return $null
    }
}

function Exit-ScanLock {
    <#
    .SYNOPSIS
        Releases the scan lock and removes the lock file.
    .PARAMETER LockStream FileStream returned by Enter-ScanLock.
    .PARAMETER StatePath  Path to state.json (lock file is derived from it).
    #>
    param(
        [System.IO.FileStream]$LockStream,
        [Parameter(Mandatory)][string]$StatePath
    )

    $lockPath = "$StatePath.lock"
    if ($LockStream) {
        try { $LockStream.Dispose() } catch { $null = $_ }
    }
    if (Test-Path $lockPath) {
        try { Remove-Item $lockPath -Force } catch { $null = $_ }
    }
}

# ── Main ───────────────────────────────────────────────────────────────────────
# Guard: skip main body when dot-sourced for unit testing (e.g. Pester)
if ($MyInvocation.InvocationName -eq '.') { return }

# -Version: print and exit before doing anything else.
if ($Version) {
    Write-Host $SCRIPT_VERSION
    exit 0
}

Write-RddLog "Rogue Device Detector v$SCRIPT_VERSION starting on $env:COMPUTERNAME"
if ($DryRun) {
    Write-RddLog "[DryRun] No state, audit, or email side effects will be written." -Level WARN
}

# Load configuration
$configPath = if ($TestSmtp -and $TestSmtpConfig) { $TestSmtpConfig }
              elseif ($Config) { $Config }
              else { Join-Path $PSScriptRoot 'config.json' }
$cfg        = Get-Configuration -ConfigPath $configPath -SubnetOverride $Subnet

# -TestSmtp: send a self-test email and exit. No scan, no state mutation.
if ($TestSmtp) {
    Invoke-SmtpTest -SmtpConfig $cfg.smtp -Version $SCRIPT_VERSION
    exit $LASTEXITCODE
}

# ── Path validation ───────────────────────────────────────────────────────────

$pathErrors = @()
foreach ($entry in @(
    @{ Name = 'statePath'; Path = $cfg.statePath },
    @{ Name = 'logPath';   Path = $cfg.logPath },
    @{ Name = 'ouiPath';   Path = $cfg.ouiPath }
)) {
    if (-not (Test-PathWritable -FilePath $entry.Path)) {
        $pathErrors += "$($entry.Name) '$($entry.Path)'"
    }
}
if ($pathErrors.Count -gt 0) {
    Write-RddLog "Cannot write to: $($pathErrors -join ', '). Check paths and permissions." -Level ERROR
    exit 1
}

# ── Management commands (no scan required) ─────────────────────────────────────

if ($ListDevices) {
    $state = Get-State -StatePath $cfg.statePath
    Show-Baseline -State $state -StatePath $cfg.statePath
    exit 0
}

if ($ApproveDevice) {
    $state = Get-State -StatePath $cfg.statePath
    $now   = (Get-Date).ToUniversalTime().ToString('o')
    Invoke-ApproveDevice -Mac $ApproveDevice -Label $Label -State $state -Now $now
    Save-State -State $state -StatePath $cfg.statePath
    Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_APPROVED' `
        -Details "mac=$ApproveDevice label=$Label approvedBy=$env:USERDOMAIN\$env:USERNAME"
    exit 0
}

if ($RemoveDevice) {
    $state   = Get-State -StatePath $cfg.statePath
    $removed = Invoke-RemoveDevice -Mac $RemoveDevice -State $state
    if ($removed) {
        Save-State -State $state -StatePath $cfg.statePath
        Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_REMOVED' -Details "mac=$RemoveDevice removedBy=$env:USERDOMAIN\$env:USERNAME"
    }
    exit 0
}

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

# ── Acquire scan lock ─────────────────────────────────────────────────────────

$scanLock = Enter-ScanLock -StatePath $cfg.statePath
if (-not $scanLock) {
    Write-RddLog 'Another scan is already running (lock file held). Exiting.' -Level ERROR
    exit 1
}

try {

# Resolve target subnet
$targetSubnet = if ($cfg.subnet) { $cfg.subnet } else { Get-LocalSubnet }
Write-AuditLog -LogPath $cfg.logPath -EventName 'SCAN_START' -Details "subnet=$targetSubnet mode=$(if ($LearningMode) { 'learning' } else { 'normal' })"
Write-RddLog "Target subnet: $targetSubnet"
$subnetInfo = Get-SubnetInfo -Cidr $targetSubnet

# Load OUI vendor database
$ouiDb = Get-OuiDatabase -CachePath $cfg.ouiPath

# Populate ARP cache via ping sweep (returns TTL map for OS fingerprinting)
$ttlMap = Invoke-PingSweep -SubnetInfo $subnetInfo
$arpEntries = @(Get-ArpEntry -SubnetInfo $subnetInfo)
Write-RddLog "$($arpEntries.Count) device(s) found in ARP table."

if ($arpEntries.Count -eq 0) {
    Write-RddLog 'ARP table empty after ping sweep. Exiting.' -Level WARN
    exit 0
}

# Build device list, resolve hostnames concurrently, then look up vendors
$foundDevices = @($arpEntries | ForEach-Object {
    $osGuess = if ($ttlMap.ContainsKey($_.IP)) { Get-OsGuess -Ttl $ttlMap[$_.IP] } else { '' }
    [PSCustomObject]@{
        mac           = $_.MAC
        ip            = $_.IP
        hostname      = $_.IP   # placeholder, overwritten by Resolve-Hostname
        vendor        = ''
        osGuess       = $osGuess
        osLabel       = $osGuess  # refined later by Get-OsLabel using banners
        openPorts     = @()
        httpBanner    = ''
        sshBanner     = ''
        telnetBanner  = ''
        upnpInfo      = ''
        riskLevel     = 'NONE'
        riskReasons   = @()
    }
})

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
                allowedPorts = @()
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
            $hostStr = if ($d.hostname -and $d.hostname -ne $d.ip) { $d.hostname } else { '-' }
            Write-RddLog "  NEW  MAC: $($d.mac)  IP: $($d.ip)  Hostname: $hostStr  Vendor: $($d.vendor)$riskTag"
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

# Refuse to run a normal scan against an unreviewed default config.
# Updater-generated configs ship with "configured": false; the operator
# must review smtp settings (and anything else) and flip the flag.
# Admin operations (-LearningMode handled earlier; -ApproveAllRogues here)
# bypass the gate. Back-compat: configs without the field default to $true.
if (-not $cfg.configured -and -not $ApproveAllRogues) {
    Write-RddLog "Config has 'configured: false' (unreviewed default config)." -Level ERROR
    Write-RddLog "Edit '$configPath' - review smtp settings, then set 'configured': true." -Level ERROR
    Write-RddLog "Use -LearningMode to seed the baseline before flipping the flag." -Level ERROR
    exit 1
}

# Normal scan: compare found devices against baseline
$rogueDevices    = [System.Collections.Generic.List[PSCustomObject]]::new()
$identityChanges = [System.Collections.Generic.List[hashtable]]::new()

foreach ($device in $foundDevices) {
    $known = @($state.knownDevices) | Where-Object { $_.mac -eq $device.mac } | Select-Object -First 1
    if ($known) {
        $previousHost = Test-IdentityChange -KnownDevice $known -FoundDevice $device
        if ($previousHost) {
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
        $rogueDevices.Add($device)
        Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_ROGUE' -Device $device `
            -Details ($device.riskReasons -join '; ')
    }
}

# Track rogue first/last sightings so the alert can show "first seen N days ago"
# rather than always 'today'. Updated in place; serialised on the next Save-State.
foreach ($d in $rogueDevices) {
    $entry = @($state.seenRogues) | Where-Object { $_.mac -eq $d.mac } | Select-Object -First 1
    if ($entry) {
        $entry.lastSeen = $now
    } else {
        $state.seenRogues = @($state.seenRogues) + @([PSCustomObject]@{
            mac       = $d.mac
            firstSeen = $now
            lastSeen  = $now
        })
    }
}

# Bulk-approve mode: add every detected rogue to the baseline and exit.
# Risk findings are NOT carried into allowedPorts - they will be reported
# on the next scan, giving the operator a chance to review per-port.
if ($ApproveAllRogues) {
    if ($rogueDevices.Count -eq 0) {
        Write-RddLog 'No rogue devices found - baseline already covers every device on the subnet.'
        exit 0
    }

    $approver = "$env:USERDOMAIN\$env:USERNAME"
    $highRiskApproved = 0
    foreach ($d in $rogueDevices) {
        $state.knownDevices += [PSCustomObject]@{
            mac          = $d.mac
            ip           = $d.ip
            hostname     = $d.hostname
            vendor       = $d.vendor
            osGuess      = $d.osGuess
            label        = ''
            firstSeen    = $now
            lastSeen     = $now
            approvedBy   = $approver
            approvedAt   = $now
            allowedPorts = @()
        }
        $riskTag = if ($d.riskLevel -and $d.riskLevel -ne 'NONE') { " [$($d.riskLevel)]" } else { '' }
        if ($d.riskLevel -and $RISK_ORDER[$d.riskLevel] -ge $RISK_ORDER['HIGH']) { $highRiskApproved++ }
        Write-RddLog "  Approved: $($d.mac)  $($d.ip)  $($d.hostname)  [$($d.vendor)]$riskTag"
        Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_APPROVED' -Device $d `
            -Details "bulk-approve risk=$($d.riskLevel)"
    }

    # The approved MACs are no longer rogues; clean them out of seenRogues.
    $approvedMacs = @($rogueDevices | ForEach-Object { $_.mac })
    $state.seenRogues = @(@($state.seenRogues) | Where-Object { $_.mac -notin $approvedMacs })

    $state.lastScan = $now
    Save-State -State $state -StatePath $cfg.statePath
    Write-RddLog "$($rogueDevices.Count) device(s) approved into baseline."
    if ($highRiskApproved -gt 0) {
        Write-RddLog "$highRiskApproved approved device(s) have HIGH/CRITICAL risk findings; they will be reported as RISK on the next scan." -Level WARN
    }
    exit 0
}

# Filter allowed ports and log risk findings for known devices
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
            Write-AuditLog -LogPath $cfg.logPath -EventName 'RISK_FOUND' -Device $device `
                -Details ($device.riskReasons -join '; ')
            $riskDevices.Add($device)
        }
    }
}

# Detect devices that have not been seen for too long
$absentDevices = @(Get-AbsentDevices -KnownDevices @($state.knownDevices) `
    -AbsentDays $cfg.absentDays -Now $now)
foreach ($d in $absentDevices) {
    Write-AuditLog -LogPath $cfg.logPath -EventName 'DEVICE_ABSENT' -Device $d `
        -Details "lastSeen=$($d.lastSeen) absentDays=$($cfg.absentDays)"
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
    if ($DryRun) {
        Write-RddLog "[DryRun] Skipping summary report email."
    } else {
        Send-SummaryReport -Report $report -SmtpConfig $cfg.smtp
    }
} else {
    $criticalCount = @($riskDevices | Where-Object { $_.riskLevel -eq 'CRITICAL' }).Count
    $highCount     = @($riskDevices | Where-Object { $_.riskLevel -eq 'HIGH' }).Count
    $riskBreakdown = if ($riskDevices.Count -gt 0) { " ($criticalCount critical, $highCount high)" } else { '' }
    Write-RddLog ("Scan summary: $($rogueDevices.Count) rogue, " +
                  "$($riskDevices.Count) risk$riskBreakdown, " +
                  "$($absentDevices.Count) absent, " +
                  "$($identityChanges.Count) hostname changes.")

    if ($rogueDevices.Count -gt 0 -or $riskDevices.Count -gt 0 -or $absentDevices.Count -gt 0) {
        if ($DryRun) {
            Write-RddLog "[DryRun] Skipping alert email; would have notified $($cfg.smtp.to)."
        } else {
            Send-RogueAlert -Devices $rogueDevices.ToArray() `
                -RiskDevices $riskDevices.ToArray() `
                -AbsentDevices $absentDevices `
                -IdentityChangeCount $identityChanges.Count `
                -Subnet $targetSubnet `
                -SeenRogues @($state.seenRogues) `
                -SmtpConfig $cfg.smtp
        }
    } else {
        Write-RddLog 'Scan complete - all devices are known.'
    }
}

# Exit code bitmask for RMM integration
#   0 = clean, 1 = rogue devices, 2 = high/critical risk, 4 = absent devices
$exitCode = 0
if ($rogueDevices.Count -gt 0) { $exitCode = $exitCode -bor 1 }
if ($riskDevices.Count -gt 0)  { $exitCode = $exitCode -bor 2 }
if ($absentDevices.Count -gt 0) { $exitCode = $exitCode -bor 4 }

} finally {
    Exit-ScanLock -LockStream $scanLock -StatePath $cfg.statePath
}
exit $exitCode
