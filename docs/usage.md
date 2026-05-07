# Usage

Day-to-day operation: every CLI parameter, the scan workflow, and copy-paste examples.

## How a scan works

1. ICMP ping sweep across the subnet to populate the ARP cache.
2. Read the ARP table for MAC + IP pairs.
3. Resolve hostnames in a layered cascade: AXFR pre-fill → DNS reverse → mDNS → LLMNR → NetBIOS. UPnP friendlyName is plugged in later as a final hostname fallback during enrichment. See [architecture.md](architecture.md#hostname-resolution) for the full breakdown.
4. Look up MAC vendors in the IEEE OUI database (cached locally).
5. Fingerprint the OS via ICMP TTL (Windows / Linux / macOS / network device).
6. Optional enrichment: TCP port scan, HTTP / SSH / Telnet banner, UPnP discovery, risk evaluation.
7. Compare found devices to the baseline (`state.json`).
8. Send alerts for rogue devices, risk findings, identity changes, and absent devices.

## Parameters

### Scanning

| Parameter | Type | Description |
|-----------|------|-------------|
| `-LearningMode` | Switch | Adds all found devices to the baseline without sending alerts. Use for initial setup or after adding known devices to the network. |
| `-Config "path"` | String | Path to `config.json`. Defaults to `config.json` in the script directory. |
| `-Subnet "cidr"` | String | CIDR subnet to scan (e.g. `192.168.1.0/24`). Overrides config file. Auto-detected from NIC if omitted. |

### Device management

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ApproveDevice "MAC"` | String | Add a device to the baseline by MAC address. Combine with `-Label` for a human-readable name. |
| `-Label "name"` | String | Human-readable name for the device (only with `-ApproveDevice`). When the resolver cascade returns nothing, the alert email falls back to the label in the hostname column with a `[label]` source tag — so a manual name on a silent device is still visible. |
| `-AliasOf "MAC"` | String | Attach the MAC being approved as an alias of an existing baseline device (only with `-ApproveDevice`). Use this for hardware with multiple network interfaces (e.g. a notebook's wired and WiFi MACs — same logical device, different MACs). The alert email suggests likely alias candidates for each rogue based on hostname similarity. |
| `-RemoveDevice "MAC"` | String | Remove a device from the baseline. |
| `-ListDevices` | Switch | Show all approved devices and exit. No scan is performed. |
| `-ApproveAllRogues` | Switch | Run a full scan and add every detected rogue to the baseline at once. Risk findings are NOT auto-allowed — risky open ports on the approved devices will be reported as RISK on the next scan. Use after acknowledging a batch of expected new devices. |

### Diagnostics

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Version` | Switch | Print the script version and exit. |
| `-TestSmtp` | Switch | Send a single test email using the configured SMTP settings, then exit. No scan, no state mutation. Use to validate config during initial setup. |
| `-DryRun` | Switch | (Combine with default scan mode.) Run a full scan but skip `state.json`, audit log, and email side effects. Useful for testing config changes without consequences. |
| `-Verbose` | Switch | Standard PowerShell switch — adds per-stage tracing: resolved config values, hostname-stage hits/misses with timings, AXFR send/receive details, SMTP connection params, full exception messages on every catch (including stack and inner). See [diagnostics.md](diagnostics.md). |
| `-Debug` | Switch | Standard PowerShell switch — same as `-Verbose` plus a hex dump of the first 64 bytes of any AXFR response. Inquire prompts are suppressed (output streams continuously). |
| `-?` / `Get-Help .\rogue-device-detector.ps1 -Full` | — | Built-in PowerShell help. Shows full parameter docs and usage examples. |

### Port allowlist

Known devices with open ports trigger risk warnings by default. If a port is intentional (e.g. RDP on a terminal server), allow it per device to suppress the warning:

| Parameter | Type | Description |
|-----------|------|-------------|
| `-AllowPort 3389,22` | Int[] | Allow one or more ports on a device. Must be used with `-On`. |
| `-BlockPort 3389` | Int[] | Revoke a port allowance. Must be used with `-On`. |
| `-On "MAC"` | String | Target device MAC for `-AllowPort` or `-BlockPort`. |

## Examples

```powershell
# --- Scanning ---

# Regular scan (typically run via scheduler)
.\rogue-device-detector.ps1

# Learning mode - baseline creation, no alerts
.\rogue-device-detector.ps1 -LearningMode

# Scan a specific subnet
.\rogue-device-detector.ps1 -Subnet "10.0.1.0/24"

# Use a config file from a different location
.\rogue-device-detector.ps1 -Config "C:\Scripts\rdd\config.json"


# --- Device management ---

# Approve a device that appeared in an alert (copy-paste from the email)
.\rogue-device-detector.ps1 -ApproveDevice "AA:BB:CC:DD:EE:FF" -Label "Reception printer"

# Attach a notebook's WiFi MAC as alias of its Ethernet MAC
.\rogue-device-detector.ps1 -ApproveDevice "AA:BB:CC:DD:EE:F1" -AliasOf "AA:BB:CC:DD:EE:F0"

# Remove a device that left the network
.\rogue-device-detector.ps1 -RemoveDevice "AA:BB:CC:DD:EE:FF"

# List all approved devices with their allowed ports and aliases
.\rogue-device-detector.ps1 -ListDevices

# Bulk-approve every currently-rogue device after a known network change
.\rogue-device-detector.ps1 -ApproveAllRogues


# --- Port allowlist ---

# Allow RDP and SSH on a known server (suppresses risk warnings for these ports)
.\rogue-device-detector.ps1 -AllowPort 3389,22 -On "AA:BB:CC:DD:EE:FF"

# Revoke a port allowance (port will trigger warnings again)
.\rogue-device-detector.ps1 -BlockPort 3389 -On "AA:BB:CC:DD:EE:FF"
```

## Typical workflow

1. **Deploy:** copy script + `config.json` to the target host (see [deployment.md](deployment.md)).
2. **Baseline:** run with `-LearningMode` to establish the known-device baseline.
3. **Review:** use `-ListDevices` to verify; use `-RemoveDevice` to drop anything suspicious.
4. **Schedule:** set up a weekly scan without `-LearningMode`.
5. **React to alerts:**
   - **Authorized device** (e.g. new laptop, printer): approve with `-ApproveDevice` (with `-Label` and optionally `-AliasOf` for second-NIC cases).
   - **Expected open port** (e.g. RDP on a server): allow with `-AllowPort … -On …`.
   - **Unauthorized device:** investigate and remove from the network.
6. **Re-baseline:** run `-LearningMode` again after deliberate network changes, or `-ApproveAllRogues` if everything currently rogue is legitimate.
