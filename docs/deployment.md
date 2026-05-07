# Deployment

Everything you need to install RDD on a scanning host and keep it running.

## Requirements

- Windows with PowerShell 5.1 or later (pre-installed on Windows 10/11/Server 2016+).
- Network access to the target subnet from the scanning host (same Layer-2 segment — RDD relies on ARP, which routers do not forward).
- An SMTP server for email alerts (optional but recommended).

## Quick Start

```powershell
# 1. Copy the example config and fill in your SMTP settings.
Copy-Item config.example.json config.json
notepad config.json

# 2. Run in learning mode to build the baseline (no alerts sent).
.\rogue-device-detector.ps1 -LearningMode

# 3. Review the baseline; -RemoveDevice can be used to drop entries.
.\rogue-device-detector.ps1 -ListDevices

# 4. Schedule regular scans (see "Scheduling" below).
```

For unattended deployment via an RMM (NinjaOne / ConnectWise / Intune / generic), see [Unattended install (RMM)](#unattended-install-rmm) below.

## Unattended install (RMM)

Store the snippet below once as a PowerShell script in your RMM. It downloads the updater from the latest GitHub release, verifies its SHA-256, and runs it. Idempotent — safe to schedule. Updater bumps require zero RMM maintenance.

```powershell
$base    = 'https://github.com/gzuercher/rogue-device-detector/releases/latest/download'
$tmp     = Join-Path $env:TEMP "rdd-bootstrap-$([guid]::NewGuid()).ps1"
$tmpHash = "$tmp.sha256"
try {
    Invoke-WebRequest "$base/Update-RogueDeviceDetector.ps1"        -OutFile $tmp     -UseBasicParsing -ErrorAction Stop
    Invoke-WebRequest "$base/Update-RogueDeviceDetector.ps1.sha256" -OutFile $tmpHash -UseBasicParsing -ErrorAction Stop
    $exp = (Get-Content $tmpHash -Raw).Trim().Split()[0].ToLower()
    $act = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
    if ($act -ne $exp) { throw "Updater hash mismatch: expected $exp, got $act" }
    & $tmp
    exit $LASTEXITCODE
} finally {
    Remove-Item $tmp,$tmpHash -Force -ErrorAction SilentlyContinue
}
```

The updater installs to `C:\Scripts\RDD\` and writes a default `config.json` with `"configured": false` as a safety gate. The main script refuses to run a normal scan until you review the file (SMTP settings in particular) and flip the flag to `true`. `-LearningMode` and the device-management modes (`-ListDevices`, `-ApproveDevice`, etc.) work without the flag, so you can seed the baseline before going live.

Re-running the same snippet on an existing host updates the script in place to the latest release. The existing `config.json`, `state.json`, and audit log are left untouched.

## Scheduling

Recommended cadence: once per week (e.g. Monday at 02:00).

**Windows Task Scheduler:**

```
Action:    powershell.exe
Arguments: -NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\rdd\rogue-device-detector.ps1"
```

**Any RMM:** deploy as a scheduled script task with the same arguments.

**Intune:** deploy as a PowerShell script via Endpoint Manager.

**cron** (via WSL or Linux/macOS with pwsh):

```
0 2 * * 1 pwsh -NonInteractive -File /path/to/rogue-device-detector.ps1
```

## Migrating state to another host

`state.json` is a portable JSON file with a versioned schema (current: v5; see [architecture.md](architecture.md#state-file)). Copy it to the new host's configured `statePath` and the schema migrator brings older versions up to current on first read. No re-baselining required if the network is unchanged.
