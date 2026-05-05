#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
.SYNOPSIS
    Pester tests for the HTML alert email assembly. Mocks Send-MailMessage
    so the body / subject / attachments can be inspected without going on
    the wire.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
    Justification = 'Test capture pattern: cross-scope variable to inspect Mock parameters.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '',
    Justification = 'Mock signature mirrors Send-MailMessage param shape; not a real credential consumer.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
    Justification = 'Mock signature only - no password handling.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Mock signature mirrors Send-MailMessage; unused params are intentional.')]
param()

BeforeAll {
    $script:ScriptPath = Resolve-Path "$PSScriptRoot\..\rogue-device-detector.ps1"
    . $script:ScriptPath
}

Describe 'Send-RogueAlert HTML body' {
    BeforeAll {
        # Override Send-MailMessage in global scope - dot-sourced functions
        # resolve commands by global name, so this intercepts the call.
        function global:Send-MailMessage {
            [CmdletBinding()]
            param(
                [string]$From, [string]$To, [string]$Subject, $Body,
                [switch]$BodyAsHtml, [string]$SmtpServer, [int]$Port,
                [switch]$UseSsl, $Credential, $Attachments
            )
            $global:RDDTestCapture = @{
                From = $From; To = $To; Subject = $Subject; Body = $Body
                BodyAsHtml = [bool]$BodyAsHtml; UseSsl = [bool]$UseSsl
                Port = $Port; Attachments = $Attachments
                Invoked = $true
            }
        }
    }

    AfterAll {
        Remove-Item Function:\global:Send-MailMessage -ErrorAction SilentlyContinue
        Remove-Variable -Name RDDTestCapture -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $global:RDDTestCapture = @{ Invoked = $false }

        $script:smtp = @{
            host = 'smtp.example'; port = 25; from = 'a@b'; to = 'c@d'
            user = ''; password = ''; useSsl = $false
        }

        $script:rogueDevice = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:01'; ip='192.168.1.10'; hostname='unknown'
            vendor='Acme'; osGuess='Windows'; osLabel='Windows'
            httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo=''
            openPorts=@(); riskLevel='NONE'; riskReasons=@()
        }
    }

    It 'sends BodyAsHtml with a recognisable HTML envelope' {
        Send-RogueAlert -Devices @($script:rogueDevice) -SmtpConfig $script:smtp -Subnet '192.168.1.0/24'
        $global:RDDTestCapture.BodyAsHtml | Should -BeTrue
        $global:RDDTestCapture.Body       | Should -Match '<!DOCTYPE html>'
        $global:RDDTestCapture.Body       | Should -Match 'Rogue Device Detector'
    }

    It 'omits the rogue section when no rogues are passed' {
        $risk = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:02'; ip='192.168.1.20'; hostname='srv1'
            riskLevel='HIGH'; riskReasons=@('SSH (port 22)'); openPorts=@(22)
            httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo=''
        }
        Send-RogueAlert -Devices @() -RiskDevices @($risk) -SmtpConfig $script:smtp
        $global:RDDTestCapture.Body | Should -Not -Match 'Rogue Devices \('
        $global:RDDTestCapture.Body | Should -Match 'Risk Findings on Known Devices \(1\)'
    }

    It 'HTML-escapes hostnames containing angle brackets and ampersands' {
        $bad = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:03'; ip='192.168.1.30'
            hostname='host<X>&Y'; vendor='X'
            osGuess=''; httpBanner=''; upnpInfo=''
            openPorts=@(); riskLevel='NONE'; riskReasons=@()
        }
        Send-RogueAlert -Devices @($bad) -SmtpConfig $script:smtp
        $body = $global:RDDTestCapture.Body
        # Raw angle brackets must be escaped.
        $body | Should -Match 'host&lt;X&gt;&amp;Y'
        # Raw '<X>' must NOT appear in the rendered body.
        $body.Contains('host<X>') | Should -BeFalse
    }

    It 'action commands are Outlook-paste safe (no &amp; &quot; form)' {
        $d = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:04'; ip='192.168.1.40'; hostname='h'
            vendor='X'; osGuess=''; httpBanner=''; upnpInfo=''
            openPorts=@(); riskLevel='NONE'; riskReasons=@()
        }
        Send-RogueAlert -Devices @($d) -SmtpConfig $script:smtp
        $body = $global:RDDTestCapture.Body
        # No call-operator + double-quoted-path form.
        $body | Should -Not -Match '&amp; &quot;'
        # Single-quoted args appear (escaped to &#39;) in the action block.
        $body | Should -Match '&#39;&lt;MAC&gt;&#39;'
    }

    It 'subject lists each non-zero category' {
        $absent = [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:07'; label='old'; lastSeen='2026-04-01' }
        Send-RogueAlert -Devices @($script:rogueDevice) -AbsentDevices @($absent) -SmtpConfig $script:smtp
        $global:RDDTestCapture.Subject | Should -Match '1 rogue, 1 absent'
    }

    It 'honours smtp.useSsl from config' {
        $smtpTls = @{ host='s'; port=587; from='a@b'; to='c@d'; user=''; password=''; useSsl=$true }
        Send-RogueAlert -Devices @($script:rogueDevice) -SmtpConfig $smtpTls
        $global:RDDTestCapture.UseSsl | Should -BeTrue

        $smtpPlain = @{ host='s'; port=25; from='a@b'; to='c@d'; user=''; password=''; useSsl=$false }
        Send-RogueAlert -Devices @($script:rogueDevice) -SmtpConfig $smtpPlain
        $global:RDDTestCapture.UseSsl | Should -BeFalse
    }

    It 'short-circuits when no rogues, risks, or absents to report' {
        Send-RogueAlert -Devices @() -RiskDevices @() -AbsentDevices @() -SmtpConfig $script:smtp
        $global:RDDTestCapture.Invoked | Should -BeFalse
    }

    It 'emits a single generic command template, not one line per device' {
        $threeRogues = @(
            [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:10'; ip='192.168.1.10'; hostname='h1'; vendor='X'; osGuess=''; httpBanner=''; upnpInfo=''; openPorts=@(); riskLevel='NONE'; riskReasons=@() }
            [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:11'; ip='192.168.1.11'; hostname='h2'; vendor='X'; osGuess=''; httpBanner=''; upnpInfo=''; openPorts=@(); riskLevel='NONE'; riskReasons=@() }
            [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:12'; ip='192.168.1.12'; hostname='h3'; vendor='X'; osGuess=''; httpBanner=''; upnpInfo=''; openPorts=@(); riskLevel='NONE'; riskReasons=@() }
        )
        Send-RogueAlert -Devices $threeRogues -SmtpConfig $script:smtp
        $body = $global:RDDTestCapture.Body
        # No literal MAC inside the approve-command (placeholder used instead).
        $body | Should -Not -Match 'AA:BB:CC:DD:EE:10&#39; -Label'
        $body | Should -Match '-ApproveAllRogues'
        $body | Should -Match '-ApproveDevice &#39;&lt;MAC&gt;&#39;'
    }

    It 'risk section uses a single AllowPort template, not one per device' {
        $twoRisks = @(
            [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:20'; ip='1.1.1.20'; hostname='r1'; riskLevel='HIGH'; riskReasons=@('A (port 22)'); openPorts=@(22); httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo='' }
            [PSCustomObject]@{ mac='AA:BB:CC:DD:EE:21'; ip='1.1.1.21'; hostname='r2'; riskLevel='HIGH'; riskReasons=@('A (port 22)'); openPorts=@(22); httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo='' }
        )
        Send-RogueAlert -Devices @() -RiskDevices $twoRisks -SmtpConfig $script:smtp
        $body = $global:RDDTestCapture.Body
        $body | Should -Not -Match "On &#39;AA:BB:CC:DD:EE:20&#39;"
        $body | Should -Match '-AllowPort &lt;port&gt; -On &#39;&lt;MAC&gt;&#39;'
    }

    It 'shows "-" when hostname equals IP (unresolved)' {
        $unresolved = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:30'; ip='192.168.99.30'; hostname='192.168.99.30'
            vendor='X'; osGuess=''; httpBanner=''; upnpInfo=''
            openPorts=@(); riskLevel='NONE'; riskReasons=@()
        }
        Send-RogueAlert -Devices @($unresolved) -SmtpConfig $script:smtp
        # The hostname column for this row should render as the dash placeholder.
        # We assert the MAC appears alongside a `-` cell, not the IP repeated.
        $global:RDDTestCapture.Body | Should -Match 'AA:BB:CC:DD:EE:30(?s).*?<span style="color:#a0aec0;">-</span>'
    }

    It 'no longer attaches anything (audit CSV removed from email)' {
        Send-RogueAlert -Devices @($script:rogueDevice) -SmtpConfig $script:smtp
        $global:RDDTestCapture.Attachments | Should -Be $null
    }

    It 'rogue table headers no longer include Risk or Ports columns' {
        Send-RogueAlert -Devices @($script:rogueDevice) -SmtpConfig $script:smtp
        $body = $global:RDDTestCapture.Body
        # Locate the rogue table block.
        $rogueBlock = if ($body -match '(?s)Rogue Devices \(\d+\).*?</table>') { $Matches[0] } else { '' }
        $rogueBlock | Should -Not -BeNullOrEmpty
        $rogueBlock | Should -Not -Match '<th[^>]*>Risk</th>'
        $rogueBlock | Should -Not -Match '<th[^>]*>Ports</th>'
        $rogueBlock | Should -Match '<th[^>]*>First Seen</th>'
        $rogueBlock | Should -Match '<th[^>]*>Details</th>'
    }

    It 'risk table includes a Details column' {
        $risk = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:40'; ip='1.1.1.40'; hostname='srv'
            riskLevel='HIGH'; riskReasons=@('SSH (port 22)'); openPorts=@(22)
            httpBanner='nginx/1.24'; sshBanner='SSH-2.0-OpenSSH_9.6 Ubuntu'
            telnetBanner=''; upnpInfo=''
        }
        Send-RogueAlert -Devices @() -RiskDevices @($risk) -SmtpConfig $script:smtp
        $body = $global:RDDTestCapture.Body
        $body | Should -Match 'http: nginx/1.24'
        $body | Should -Match 'ssh: SSH-2.0-OpenSSH'
    }

    It 'rogue First Seen shows "today" for fresh rogues with no SeenRogues entry' {
        $fresh = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:50'; ip='1.1.1.50'; hostname='h'
            vendor='V'; osGuess='Linux/macOS'; osLabel='Linux/macOS'
            httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo=''
            openPorts=@(); riskLevel='NONE'; riskReasons=@()
        }
        Send-RogueAlert -Devices @($fresh) -SmtpConfig $script:smtp -SeenRogues @()
        # First Seen cell appears in the row.
        $global:RDDTestCapture.Body | Should -Match '>today<'
    }

    It 'rogue First Seen reflects relative age from SeenRogues' {
        $oldRogue = [PSCustomObject]@{
            mac='AA:BB:CC:DD:EE:51'; ip='1.1.1.51'; hostname='h'
            vendor='V'; osGuess='Linux/macOS'; osLabel='Linux/macOS'
            httpBanner=''; sshBanner=''; telnetBanner=''; upnpInfo=''
            openPorts=@(); riskLevel='NONE'; riskReasons=@()
        }
        $longAgo = [datetime]::UtcNow.AddDays(-7).ToString('o')
        $seen = @([PSCustomObject]@{ mac='AA:BB:CC:DD:EE:51'; firstSeen=$longAgo; lastSeen=$longAgo })
        Send-RogueAlert -Devices @($oldRogue) -SmtpConfig $script:smtp -SeenRogues $seen
        $global:RDDTestCapture.Body | Should -Match '\d+ days ago'
    }
}

Describe 'Audit log rotation' {
    BeforeEach {
        $script:tmpLog = Join-Path ([System.IO.Path]::GetTempPath()) "rdd-rotation-$([guid]::NewGuid()).csv"
    }
    AfterEach {
        $dir  = Split-Path $script:tmpLog -Parent
        $base = [System.IO.Path]::GetFileNameWithoutExtension($script:tmpLog)
        Get-ChildItem -Path $dir -Filter "$base*.csv" -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    It 'rotates the active file when it exceeds AUDIT_LOG_MAX_BYTES' {
        $oversize = [byte[]]::new($AUDIT_LOG_MAX_BYTES + 100)
        [System.IO.File]::WriteAllBytes($script:tmpLog, $oversize)

        Write-AuditLog -LogPath $script:tmpLog -EventName 'TEST'

        $dir  = Split-Path $script:tmpLog -Parent
        $base = [System.IO.Path]::GetFileNameWithoutExtension($script:tmpLog)
        $rotated = @(Get-ChildItem -Path $dir -Filter "$base.*.csv" -ErrorAction SilentlyContinue)
        $rotated.Count | Should -BeGreaterThan 0
        (Get-Item $script:tmpLog).Length | Should -BeLessThan 1KB
    }

    It 'does not rotate when the file is below the threshold' {
        Set-Content $script:tmpLog -Value 'small'

        Write-AuditLog -LogPath $script:tmpLog -EventName 'TEST'

        $dir  = Split-Path $script:tmpLog -Parent
        $base = [System.IO.Path]::GetFileNameWithoutExtension($script:tmpLog)
        $rotated = @(Get-ChildItem -Path $dir -Filter "$base.*.csv" -ErrorAction SilentlyContinue)
        $rotated.Count | Should -Be 0
    }
}
