# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MSP tool for detecting rogue/unauthorized devices on customer networks. Runs as a scheduled task via NinjaOne RMM. Fully integrated into NinjaOne – no separate backend or UI.

See [ARCHITECTURE.md](ARCHITECTURE.md) for full technical design and data flow.

## Tech Stack

- **Language**: PowerShell (Windows only, no installation required)
- **Deployment**: Via NinjaOne as scheduled task / script
- **Config**: NinjaOne Custom Fields and/or script parameters
- **Storage**: Local JSON file on the scanning device (portable)
- **Alerts**: SMTP email (Azure ACS, configurable)

## Deployment

No installer. Script is deployed and scheduled directly via NinjaOne. All configuration is done via NinjaOne Custom Fields or script parameters – no manual setup on the endpoint.

## Key Commands

```powershell
# Run scanner manually (when implemented)
.\rogue-device-detector.ps1

# Run in learning mode (baseline, no alerts)
.\rogue-device-detector.ps1 -LearningMode

# Override subnet (instead of auto-detect)
.\rogue-device-detector.ps1 -Subnet "192.168.1.0/24"
```

## NinjaOne API

Auth: OAuth 2.0 Client Credentials (`monitoring management` scopes). Token fetched at runtime, kept in memory only. See ARCHITECTURE.md for full auth flow and endpoint details.

Endpoints used:
- `GET /v2/devices` – known managed devices
- `GET /v2/devices/unmanaged` – known unmanaged devices
- `POST /v2/devices/unmanaged` – create newly discovered device

## Coding Conventions

- PowerShell strict mode (`Set-StrictMode -Version Latest`)
- All functions documented with comment-based help
- No hardcoded values – all config via parameters or constants at top of script
- Errors must surface explicitly – no silent `try/catch` swallowing
