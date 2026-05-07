# Build-SampleReport.ps1 - regenerates docs/samples/sample-report.html from a
# fixed set of synthetic devices (RFC 5737 / RFC 1918 placeholders, no
# real hostnames or MACs from any production network). Run from the repo
# root after changes to Send-RogueAlert so the published sample stays
# representative.
#
# Usage:
#   pwsh -NoProfile -File tools/Build-SampleReport.ps1

. ./rogue-device-detector.ps1

# Intercept SMTP delivery and capture the rendered body instead of sending.
# Mirrors Send-MailMessage's signature so call-sites bind cleanly; most of
# the parameters are deliberately unused here, and the global cache is the
# whole point of the helper. Suppress the lint rules that fire on those
# patterns - this is an offline build helper, not production code.
function global:Send-MailMessage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Signature must match Send-MailMessage; unused params kept for binding.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
        Justification = 'Mock signature; no real credentials are processed.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '',
        Justification = 'Mock signature; no real credentials are processed.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
        Justification = 'Capturing the rendered body in a global is the helper''s only job.')]
    param([string]$From, [string]$To, [string]$Subject, $Body,
          [switch]$BodyAsHtml, [string]$SmtpServer, [int]$Port,
          [switch]$UseSsl, $Credential, $Attachments)
    $global:cap = @{ Subject = $Subject; Body = $Body }
}

# Synthetic devices - RFC 5737 (TEST-NET-1, 192.0.2.0/24)
$rogues = @(
    [PSCustomObject]@{
        mac='AA:BB:CC:00:11:22'; ip='192.0.2.45'; hostname='nb-laptop-99'
        hostnameSource='mdns'
        vendor='Apple, Inc.'; osGuess='macOS'; osLabel='macOS'
        httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo=''
        openPorts=@(); riskLevel='NONE'; riskReasons=@()
    }
    [PSCustomObject]@{
        mac='AA:BB:CC:00:33:44'; ip='192.0.2.50'; hostname='192.0.2.50'
        hostnameSource=''
        vendor='Tuya Smart Inc.'; osGuess=''; osLabel=''
        httpBanner='Title: Smart Plug v2'; sshBanner=''; telnetBanner=''
        upnpInfo='Smart Plug Living Room / Tuya UPnP/1.0'
        openPorts=@(80); riskLevel='LOW'
        riskReasons=@('Unencrypted web interface (port 80)')
    }
    [PSCustomObject]@{
        mac='AA:BB:CC:00:55:66'; ip='192.0.2.51'; hostname='192.0.2.51'
        hostnameSource=''
        label='Server room UPS'
        vendor='APC by Schneider Electric'; osGuess='Network device'
        osLabel='Network device'
        httpBanner=''; sshBanner=''
        telnetBanner='Welcome to APC Network Management'; upnpInfo=''
        openPorts=@(23,80); riskLevel='CRITICAL'
        riskReasons=@('Unencrypted remote access (Telnet) (port 23)','Unencrypted web interface (port 80)')
    }
)

$risks = @(
    [PSCustomObject]@{
        mac='11:22:33:44:55:66'; ip='192.0.2.10'; hostname='fileserver'
        hostnameSource='dns'; vendor='Dell Inc.'; osGuess='Windows'
        osLabel='Windows Server 2019'
        httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo=''
        openPorts=@(445,3389); riskLevel='HIGH'
        riskReasons=@('File sharing exposed (ransomware vector) (port 445)','Remote Desktop exposed (port 3389)')
    }
)

$absent = @(
    [PSCustomObject]@{ mac='77:88:99:AA:BB:CC'; label='Reception printer'; lastSeen='2026-04-12T08:00:00Z' }
)

$known = @(
    [PSCustomObject]@{ mac='11:22:33:44:55:66'; hostname='fileserver'; label='File server' }
    [PSCustomObject]@{ mac='AA:BB:CC:00:00:00'; hostname='nb-laptop-01'; label='Notebook 01' }
)

$seenRogues = @(
    [PSCustomObject]@{ mac='AA:BB:CC:00:11:22'; firstSeen='2026-05-01T08:00:00Z'; lastSeen='2026-05-07T08:00:00Z' }
)

$smtp = @{
    host='smtp.example.invalid'; port=587
    from='rdd@example.invalid'; to='helpdesk@example.invalid'
    user=''; password=''; useSsl=$true
}

Send-RogueAlert -Devices $rogues `
    -RiskDevices $risks `
    -AbsentDevices $absent `
    -IdentityChangeCount 1 `
    -Subnet '192.0.2.0/24' `
    -SeenRogues $seenRogues `
    -KnownDevices $known `
    -SmtpConfig $smtp

# Pull the captured body out of the global the mock writes into. The local
# alias keeps the lint rule that hates top-level globals quiet.
$capturedBody = (Get-Variable -Name 'cap' -Scope Global).Value.Body
$capturedBody | Set-Content -Path docs/samples/sample-report.html -Encoding UTF8
$len = (Get-Item docs/samples/sample-report.html).Length
Write-Host "Sample report written: $len bytes"
