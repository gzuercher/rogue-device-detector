# Test-Axfr.ps1 - operator-friendly AXFR diagnostic for the rogue-device-detector.
#
# Place next to rogue-device-detector.ps1 (or under tools/ alongside the main
# script) and run from PowerShell. Prints a short pass/fail summary plus an
# actionable verdict at the end:
#
#   - GREEN  -> AXFR works, no further action needed.
#   - YELLOW -> partial: server reachable but zone transfer denied / unsupported.
#   - RED    -> AXFR is not usable; the verdict line says exactly why.
#
# Default output is intentionally short. Pass -Verbose for the full
# diagnostic (hex dump of the response, parser internals, exception
# stack traces) - useful when filing a bug or asking for help.
#
# Usage:
#   .\Test-Axfr.ps1                                       # auto-discover server + zone
#   .\Test-Axfr.ps1 -Server 192.0.2.10 -Zone corp.example.com
#   .\Test-Axfr.ps1 -Verbose                              # everything

[CmdletBinding()]
param(
    [string]$Server = '',
    [string]$Zone   = ''
)

$ErrorActionPreference = 'Continue'

# Load helpers from the main script. The script's own guard prevents the
# main scan body from running during dot-source.
$mainScript = Join-Path $PSScriptRoot '..\rogue-device-detector.ps1'
if (-not (Test-Path $mainScript)) {
    $mainScript = Join-Path $PSScriptRoot 'rogue-device-detector.ps1'
}
if (-not (Test-Path $mainScript)) {
    Write-Host 'ERROR: rogue-device-detector.ps1 not found in current dir or parent.' -ForegroundColor Red
    exit 1
}
. $mainScript

if (-not $Server) { $Server = Get-LocalDnsServer }
if (-not $Zone)   { $Zone   = Get-LocalDnsSuffix }

if (-not $Server -or -not $Zone) {
    Write-Host ''
    Write-Host '[X] Could not auto-discover a DNS server or forward zone.' -ForegroundColor Red
    Write-Host '    Pass them explicitly:' -ForegroundColor Red
    Write-Host '    .\Test-Axfr.ps1 -Server <dns-ip> -Zone <forward-zone>' -ForegroundColor Red
    exit 2
}

Write-Host ''
Write-Host "AXFR diagnostic for zone '$Zone' via server $Server"
Write-Host ''

# Each step records: ok (bool), label, detail (optional human note).
$steps = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Step {
    param(
        [Parameter(Mandatory)][bool]$Ok,
        [Parameter(Mandatory)][string]$Label,
        [string]$Detail = ''
    )
    $marker = if ($Ok) { '[+]' } else { '[-]' }
    $color  = if ($Ok) { 'Green' } else { 'Yellow' }
    $text   = if ($Detail) { "$marker $Label - $Detail" } else { "$marker $Label" }
    Write-Host $text -ForegroundColor $color
    $steps.Add([PSCustomObject]@{ Ok = $Ok; Label = $Label; Detail = $Detail })
}

# ============================================================================
# Step 1: SOA via UDP - does the server know the zone?
# ============================================================================
$soaOk = $false
$soaDetail = ''
try {
    $soa = Resolve-DnsName -Server $Server -Name $Zone -Type SOA -ErrorAction Stop
    $soaOk = $true
    $soaDetail = "primary $($soa.PrimaryServer)"
    Write-Verbose "  Serial:  $($soa.SerialNumber)"
    Write-Verbose "  Refresh: $($soa.TimeToLive)s"
} catch {
    $soaDetail = $_.Exception.Message
}
Add-Step -Ok $soaOk -Label 'DNS server knows the zone (SOA via UDP)' -Detail $soaDetail

# ============================================================================
# Step 2: TCP/53 reachability
# ============================================================================
$tcpOk = $false
$tcpDetail = ''
$tcpProbe = $null
try {
    $tcpProbe = [System.Net.Sockets.TcpClient]::new()
    $task = $tcpProbe.ConnectAsync($Server, 53)
    if ($task.Wait(3000)) {
        $tcpOk = $true
    } else {
        $tcpDetail = 'connect timed out after 3s'
    }
} catch {
    $tcpDetail = $_.Exception.Message
} finally {
    if ($tcpProbe) { $tcpProbe.Close() }
}
Add-Step -Ok $tcpOk -Label 'TCP/53 reachable (AXFR transport)' -Detail $tcpDetail

# ============================================================================
# Step 3: Raw AXFR send + read - capture bytes for verbose output
# ============================================================================
$rawOk = $false
$rawDetail = ''
$rawBytes = 0
$buffer = New-Object 'byte[]' 16384
$rawError = $null

if ($tcpOk) {
    $tcp = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $task = $tcp.ConnectAsync($Server, 53)
        [void]$task.Wait(3000)
        $tcp.ReceiveTimeout = 5000
        $tcp.SendTimeout    = 5000
        $stream = $tcp.GetStream()

        $packet = New-DnsAxfrQueryPacket -Zone $Zone
        $hi = ($packet.Length -shr 8) -band 0xFF
        $lo = $packet.Length -band 0xFF
        $stream.WriteByte([byte]$hi)
        $stream.WriteByte([byte]$lo)
        $stream.Write($packet, 0, $packet.Length)
        $stream.Flush()

        try {
            $rawBytes = $stream.Read($buffer, 0, $buffer.Length)
            if ($rawBytes -eq 0) {
                $rawDetail = 'server closed without sending data'
            } else {
                $rawOk = $true
                $rawDetail = "$rawBytes bytes"
            }
        } catch {
            $rawError = $_
            $rawDetail = $_.Exception.Message
        }
    } catch {
        $rawError = $_
        $rawDetail = $_.Exception.Message
    } finally {
        if ($tcp) { $tcp.Close() }
    }
} else {
    $rawDetail = 'skipped (TCP unreachable)'
}
Add-Step -Ok $rawOk -Label 'AXFR query accepted by server' -Detail $rawDetail

# Verbose hex dump of the first 96 bytes for forensic analysis.
if ($PSBoundParameters['Verbose'] -and $rawBytes -gt 0) {
    $shown = [Math]::Min(96, $rawBytes)
    Write-Verbose ''
    Write-Verbose "First $shown bytes (hex):"
    $i = 0
    while ($i -lt $shown) {
        $end = [Math]::Min($i + 15, $shown - 1)
        $hex = ''
        for ($j = $i; $j -le $end; $j++) {
            $hex += '{0:X2} ' -f $buffer[$j]
        }
        Write-Verbose ('    {0:D4}: {1}' -f $i, $hex)
        $i += 16
    }
}

if ($PSBoundParameters['Verbose'] -and $rawError) {
    Write-Verbose ''
    Write-Verbose "Read error type: $($rawError.Exception.GetType().FullName)"
    if ($rawError.Exception.InnerException) {
        Write-Verbose "  Inner: $($rawError.Exception.InnerException.GetType().FullName): $($rawError.Exception.InnerException.Message)"
    }
}

# ============================================================================
# Step 4: Parse the captured response - does our parser handle the wire?
# ============================================================================
$parseOk    = $false
$parseDetail = ''
$rcode      = 0
$soaCount   = 0
$aRecords   = 0

if ($rawOk -and $rawBytes -ge 4) {
    $tcpLen = ([int]$buffer[0] -shl 8) -bor $buffer[1]
    $msgLen = [Math]::Min($tcpLen, $rawBytes - 2)
    if ($msgLen -gt 0) {
        $msgBuf = New-Object 'byte[]' $msgLen
        [Array]::Copy($buffer, 2, $msgBuf, 0, $msgLen)
        try {
            $parsed   = ConvertFrom-DnsAxfrMessage -Bytes $msgBuf
            $parseOk  = $true
            $rcode    = $parsed.Rcode
            $soaCount = $parsed.SoaCount
            $aRecords = @($parsed.ARecords).Count
            $parseDetail = "rcode $rcode, $aRecords A record(s), $soaCount SOA marker(s)"
        } catch {
            $parseDetail = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
            if ($PSBoundParameters['Verbose']) {
                Write-Verbose "  Stack:"
                $_.ScriptStackTrace -split "`n" | ForEach-Object { Write-Verbose "    $_" }
            }
        }
    } else {
        $parseDetail = 'no parseable bytes after TCP length prefix'
    }
} else {
    $parseDetail = 'skipped (no raw response to parse)'
}
Add-Step -Ok $parseOk -Label 'Response parses cleanly' -Detail $parseDetail

# ============================================================================
# Step 5: End-to-end via Invoke-DnsAxfr - the path the production scan uses
# ============================================================================
$prodOk = $false
$prodDetail = ''
$prodMap = @{}
$prodStatus = ''

if ($tcpOk) {
    $result = Invoke-DnsAxfr -Server $Server -Zone $Zone
    $prodStatus = $result.Status
    $prodMap    = $result.Map
    $prodDetail = "$($result.Status), $($prodMap.Count) host record(s) extracted"
    if ($result.Status -eq 'ok') { $prodOk = $true }
} else {
    $prodDetail = 'skipped (TCP unreachable)'
}
Add-Step -Ok $prodOk -Label 'Production-path Invoke-DnsAxfr' -Detail $prodDetail

if ($PSBoundParameters['Verbose'] -and $prodMap.Count -gt 0) {
    Write-Verbose ''
    Write-Verbose 'First 10 entries from the production-path map:'
    $shown = 0
    foreach ($pair in $prodMap.GetEnumerator()) {
        Write-Verbose ('    {0,-15} -> {1}' -f $pair.Key, $pair.Value)
        $shown++
        if ($shown -ge 10) { break }
    }
    if ($prodMap.Count -gt $shown) {
        Write-Verbose "    ... ($($prodMap.Count - $shown) more)"
    }
}

# ============================================================================
# Verdict - actionable summary
# ============================================================================
Write-Host ''
$bar = '=' * 64
Write-Host $bar

if ($prodOk) {
    Write-Host "  AXFR WORKS  ($($prodMap.Count) host records loaded from $Zone)" -ForegroundColor Green
    Write-Host '  No action needed. RDD will use AXFR to pre-fill hostnames.' -ForegroundColor Green
} elseif (-not $soaOk) {
    Write-Host '  AXFR NOT USABLE: the DNS server does not know the zone.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Fix one of the following:' -ForegroundColor Yellow
    Write-Host "    - Set dnsZoneTransfer.server in config.json to the authoritative" -ForegroundColor Yellow
    Write-Host "      DNS server for '$Zone' (e.g. your AD domain controller)." -ForegroundColor Yellow
    Write-Host "    - Or verify the zone name is correct."                       -ForegroundColor Yellow
    Write-Host "    - Or set dnsZoneTransfer.enabled to false to skip AXFR."     -ForegroundColor Yellow
} elseif (-not $tcpOk) {
    Write-Host '  AXFR NOT USABLE: TCP/53 is blocked or filtered.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Open TCP/53 from this host to the DNS server, or set'  -ForegroundColor Yellow
    Write-Host '  dnsZoneTransfer.enabled to false to skip AXFR.'         -ForegroundColor Yellow
} elseif (-not $rawOk) {
    Write-Host '  AXFR NOT USABLE: server refused the transfer.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Authorise this host on the DNS server:' -ForegroundColor Yellow
    Write-Host '    Windows DNS:  Set-DnsServerPrimaryZone -Name <zone>' -ForegroundColor Yellow
    Write-Host '                    -SecureSecondaries TransferToSecureServers' -ForegroundColor Yellow
    Write-Host '                    -SecondaryServers <this-host-ip>'    -ForegroundColor Yellow
    Write-Host '    BIND:         allow-transfer { <this-host-ip>; };'   -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Or set dnsZoneTransfer.enabled to false to skip AXFR.' -ForegroundColor Yellow
} elseif ($prodStatus -eq 'refused') {
    Write-Host "  AXFR REFUSED by server (rcode: $($prodMap.Count -eq 0 -and $rcode -gt 0))" -ForegroundColor Red
    Write-Host ''
    Write-Host '  The server replied REFUSED. Authorise this host on it (see' -ForegroundColor Yellow
    Write-Host '  README -> "AXFR pre-fill" section for Windows DNS / BIND snippets).' -ForegroundColor Yellow
} else {
    Write-Host "  AXFR PARTIALLY WORKING ($prodStatus)" -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Wire-level transfer succeeded, but parsing or the production' -ForegroundColor Yellow
    Write-Host '  path returned an unexpected status. Re-run with -Verbose and' -ForegroundColor Yellow
    Write-Host '  attach the output to a bug report.'                           -ForegroundColor Yellow
}

Write-Host $bar
Write-Host ''
