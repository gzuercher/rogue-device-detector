# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Standalone PowerShell script that detects rogue/unauthorized devices on a network. Designed for MSP use but usable by anyone. No external dependencies, no cloud backend, no vendor lock-in.

See [ARCHITECTURE.md](ARCHITECTURE.md) for full technical design and data flow.

## Tech Stack

- **Language**: PowerShell (Windows, no installation required)
- **Config**: JSON config file + optional parameter overrides
- **Storage**: JSON state file (local, portable)
- **Alerts**: SMTP email (configurable, Azure ACS compatible)
- **Scheduling**: Any scheduler (Windows Task Scheduler, RMM, Intune, cron via WSL, etc.)

## Key Commands

```powershell
# Run scanner
.\rogue-device-detector.ps1

# First run: learning mode (baseline, no alerts)
.\rogue-device-detector.ps1 -LearningMode

# Use a specific config file
.\rogue-device-detector.ps1 -Config "C:\path\to\config.json"

# Override subnet
.\rogue-device-detector.ps1 -Subnet "192.168.1.0/24"
```

## Coding Conventions

- PowerShell strict mode (`Set-StrictMode -Version Latest`)
- All functions documented with comment-based help
- No hardcoded values – all config via parameters or config file
- Errors must surface explicitly – no silent `try/catch` swallowing
