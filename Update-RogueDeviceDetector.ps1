#Requires -Version 5.1
<#
.SYNOPSIS
    Installs or updates rogue-device-detector.ps1 from the latest GitHub Release.

.DESCRIPTION
    Downloads the latest version of rogue-device-detector.ps1 from GitHub Releases,
    verifies the SHA-256 hash, sets the PowerShell execution policy if needed,
    removes the Mark of the Web, and replaces the local script file.

    Designed to run via NinjaOne Script Library on managed endpoints.
    Safe to run repeatedly - exits cleanly if already up to date.

    On first run (ScriptPath does not exist), performs a fresh installation.
    On subsequent runs, updates if a newer version is available.

.PARAMETER ScriptPath
    Full path where rogue-device-detector.ps1 is installed (or should be installed).
    Defaults to C:\Scripts\rdd\rogue-device-detector.ps1.

.PARAMETER GitHubRepo
    GitHub repository in "owner/repo" format.
    Defaults to gzuercher/rogue-device-detector.

.PARAMETER GitHubToken
    Optional GitHub Personal Access Token for private repositories.
    Store as a NinjaOne Script Variable (Secret) - do not hardcode.

.PARAMETER Force
    Apply the update even if the installed version matches the latest release.
    Useful for repairing a corrupt installation.

.EXAMPLE
    .\Update-RogueDeviceDetector.ps1

.EXAMPLE
    .\Update-RogueDeviceDetector.ps1 -ScriptPath "C:\RMM\rdd\rogue-device-detector.ps1" -Force

.EXAMPLE
    .\Update-RogueDeviceDetector.ps1 -GitHubToken "github_pat_..."
#>
[CmdletBinding()]
param(
    [string]$ScriptPath  = 'C:\Scripts\rdd\rogue-device-detector.ps1',
    [string]$GitHubRepo  = 'gzuercher/rogue-device-detector',
    [string]$GitHubToken = '',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Helpers 

function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $prefix = switch ($Level) {
        'INFO'  { '[INFO] ' }
        'WARN'  { '[WARN] ' }
        'ERROR' { '[ERROR]' }
        'OK'    { '[OK]   ' }
    }
    $line = "$prefix $Message"
    if ($Level -eq 'ERROR') {
        [Console]::Error.WriteLine($line)
    } else {
        Write-Host $line
    }
}

function Get-InstalledVersion {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $content = Get-Content $Path -Raw -ErrorAction SilentlyContinue
    if ($content -match "\`$SCRIPT_VERSION\s*=\s*'([^']+)'") {
        return $Matches[1]
    }
    return $null
}

function Compare-SemVer {
    # Returns $true if $Remote is strictly newer than $Local.
    param([string]$Remote, [string]$Local)
    try {
        $r = [version]($Remote -replace '-.*$', '')
        $l = [version]($Local  -replace '-.*$', '')
        return $r -gt $l
    } catch {
        return $false
    }
}

function Build-ApiHeader {
    param([string]$Token)
    $headers = @{ 'User-Agent' = 'RDD-Updater/1.0' }
    if ($Token) { $headers['Authorization'] = "Bearer $Token" }
    return $headers
}

# -- Main 

Write-Status "Rogue Device Detector updater starting on $env:COMPUTERNAME"
Write-Status "Target path : $ScriptPath"
Write-Status "GitHub repo : $GitHubRepo"

# -- Step 1: Read installed version 

$installedVersion = Get-InstalledVersion -Path $ScriptPath
if ($installedVersion) {
    Write-Status "Installed   : v$installedVersion"
} else {
    Write-Status "Not installed at target path -will perform fresh installation."
}

# -- Step 2: Fetch latest release from GitHub API 

$apiUrl  = "https://api.github.com/repos/$GitHubRepo/releases/latest"
$headers = Build-ApiHeader -Token $GitHubToken

Write-Status "Checking GitHub releases..."
try {
    $response = Invoke-WebRequest -Uri $apiUrl -Headers $headers -UseBasicParsing `
        -TimeoutSec 15 -ErrorAction Stop
    $release = $response.Content | ConvertFrom-Json
} catch {
    $statusCode = $null
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }
    if ($statusCode -eq 404) {
        Write-Status "GitHub API returned 404 for '$GitHubRepo'. Possible causes:" -Level ERROR
        Write-Status "  - The repository has no published releases yet." -Level ERROR
        Write-Status "  - The repository is private and -GitHubToken was not supplied or is invalid." -Level ERROR
        Write-Status "  - The repository name '$GitHubRepo' is incorrect." -Level ERROR
    } elseif ($statusCode -eq 403) {
        Write-Status "GitHub API rate limit or permission error (HTTP 403). Supply a -GitHubToken to authenticate." -Level ERROR
    } else {
        Write-Status "Failed to fetch release info: $_" -Level ERROR
    }
    exit 1
}

$latestVersion = $release.tag_name -replace '^v', ''
Write-Status "Latest      : v$latestVersion"

# -- Step 3: Compare versions 

if ($installedVersion -and -not $Force) {
    $needsUpdate = Compare-SemVer -Remote $latestVersion -Local $installedVersion
    if (-not $needsUpdate) {
        Write-Status "Already up to date (v$installedVersion). Nothing to do." -Level OK
        exit 0
    }
}

$action = if ($installedVersion) { "Update v$installedVersion -> v$latestVersion" } else { "Install v$latestVersion" }
Write-Status "$action -proceeding..."

# -- Step 4: Locate release assets 

$scriptAsset = $release.assets | Where-Object { $_.name -eq 'rogue-device-detector.ps1' }
$hashAsset   = $release.assets | Where-Object { $_.name -eq 'rogue-device-detector.ps1.sha256' }

if (-not $scriptAsset) {
    Write-Status "Release v$latestVersion has no 'rogue-device-detector.ps1' asset." -Level ERROR
    exit 1
}
if (-not $hashAsset) {
    Write-Status "Release v$latestVersion has no 'rogue-device-detector.ps1.sha256' asset." -Level ERROR
    exit 1
}

# -- Step 5: Download SHA-256 hash 

Write-Status "Downloading SHA-256 manifest..."
try {
    $hashResponse = Invoke-WebRequest -Uri $hashAsset.browser_download_url -Headers $headers `
        -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
    $hashText = if ($hashResponse.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($hashResponse.Content)
    } else {
        $hashResponse.Content
    }
    $expectedHash = ($hashText.Trim() -split '\s+')[0].ToUpper()
} catch {
    Write-Status "Failed to download hash file: $_" -Level ERROR
    exit 1
}

# -- Step 6: Download script 

$tempPath = Join-Path $env:TEMP 'rdd-update.ps1'
Write-Status "Downloading script..."
try {
    Invoke-WebRequest -Uri $scriptAsset.browser_download_url -Headers $headers `
        -OutFile $tempPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
} catch {
    Write-Status "Failed to download script: $_" -Level ERROR
    exit 1
}

# -- Step 7: Verify SHA-256 

Write-Status "Verifying SHA-256..."
try {
    $actualHash = (Get-FileHash -Path $tempPath -Algorithm SHA256).Hash.ToUpper()
} catch {
    Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
    Write-Status "Failed to compute hash: $_" -Level ERROR
    exit 1
}

if ($actualHash -ne $expectedHash) {
    Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
    Write-Status "SHA-256 mismatch! Expected: $expectedHash  Got: $actualHash" -Level ERROR
    exit 1
}
Write-Status "Hash verified: $actualHash" -Level OK

# -- Step 8: Verify PowerShell syntax 

Write-Status "Checking syntax..."
try {
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $tempPath, [ref]$null, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count -gt 0) {
        throw "Parse error: $($parseErrors[0].Message) at line $($parseErrors[0].Extent.StartLineNumber)"
    }
} catch {
    Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
    Write-Status "Downloaded script has syntax errors: $_" -Level ERROR
    exit 1
}
Write-Status "Syntax OK" -Level OK

# -- Step 9: Create target directory 

$targetDir = Split-Path $ScriptPath -Parent
if (-not (Test-Path $targetDir)) {
    Write-Status "Creating directory: $targetDir"
    try {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    } catch {
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        Write-Status "Cannot create directory '$targetDir': $_" -Level ERROR
        exit 1
    }
}

# -- Step 9a: Set execution policy if needed 

try {
    $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
    if ($currentPolicy -in @('Restricted', 'AllSigned')) {
        Write-Status "ExecutionPolicy is '$currentPolicy' -setting to RemoteSigned (LocalMachine)..."
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
        Write-Status "[POLICY] ExecutionPolicy changed: $currentPolicy -> RemoteSigned on $env:COMPUTERNAME" -Level OK
    } else {
        Write-Status "ExecutionPolicy is '$currentPolicy' -no change needed."
    }
} catch {
    Write-Status "Could not read/set ExecutionPolicy (may lack admin rights): $_" -Level WARN
    # Non-fatal: NinjaOne runs as SYSTEM; if this fails there is a bigger issue
}

# -- Step 10: Backup existing script 

if (Test-Path $ScriptPath) {
    $backupPath = "$ScriptPath.backup"
    Write-Status "Creating backup: $backupPath"
    try {
        Copy-Item -Path $ScriptPath -Destination $backupPath -Force -ErrorAction Stop
    } catch {
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        Write-Status "Cannot create backup: $_" -Level ERROR
        exit 1
    }
}

# -- Step 11: Replace script 

Write-Status "Installing script to: $ScriptPath"
try {
    Copy-Item -Path $tempPath -Destination $ScriptPath -Force -ErrorAction Stop
    Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
} catch {
    # Attempt to restore backup
    if (Test-Path "$ScriptPath.backup") {
        try { Copy-Item -Path "$ScriptPath.backup" -Destination $ScriptPath -Force } catch { $null = $_ }
    }
    Write-Status "Cannot replace script file: $_" -Level ERROR
    exit 1
}

# -- Step 12: Remove Mark of the Web 

try {
    Unblock-File -Path $ScriptPath -ErrorAction Stop
    Write-Status "Mark of the Web removed (Zone.Identifier cleared)." -Level OK
} catch {
    Write-Status "Could not remove Mark of the Web: $_" -Level WARN
    # Non-fatal: script still works if NinjaOne/Task Scheduler uses -ExecutionPolicy Bypass
}

# -- Done 

Write-Status "$action completed successfully on $env:COMPUTERNAME" -Level OK
if (Test-Path "$ScriptPath.backup") {
    Write-Status "Backup retained at: $ScriptPath.backup"
}
exit 0
