# Configuration

Reference for every key in `config.json`.

Copy `config.example.json` to `config.json` and adjust. The active `config.json` is excluded from git (contains SMTP credentials).

```json
{
  "subnet": "",
  "statePath": "C:\\temp\\state.json",
  "ouiPath": "C:\\temp\\oui.csv",
  "logPath": "C:\\temp\\rdd-audit.csv",
  "enrichment": true,
  "absentDays": 21,
  "summaryReport": false,
  "configured": true,
  "alertRiskLevel": "HIGH",
  "dnsZoneTransfer": {
    "enabled": true,
    "server": "",
    "zone": ""
  },
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "user": "alerts@example.com",
    "password": "your-smtp-password",
    "from": "rdd@example.com",
    "to": "helpdesk@example.com",
    "useSsl": true
  }
}
```

## Top-level fields

| Field | Default | Description |
|---|---|---|
| `subnet` | auto-detect | CIDR subnet to scan, e.g. `192.168.1.0/24`. Empty = detect from NIC. |
| `statePath` | `state.json` in script dir | Full path to the known-device state file. |
| `ouiPath` | `oui.csv` in script dir | Full path to the OUI vendor cache file. |
| `logPath` | `rdd-audit.csv` in script dir | Full path to the audit log CSV file. |
| `enrichment` | `true` | Set to `false` to skip port scan / banner / UPnP (faster scan). |
| `absentDays` | `21` | Days without a sighting before a device is flagged as absent. |
| `summaryReport` | `false` | Send a full network health report after every scan (not just rogue alerts). See [alerts.md](alerts.md#summary-report). |
| `configured` | `true` | Safety gate. The unattended installer writes `false`; normal scan mode refuses to run until you flip it to `true` after reviewing this file. `-LearningMode` and admin modes (`-ListDevices`, `-ApproveDevice`, …) bypass the gate. |
| `alertRiskLevel` | `HIGH` | Threshold for the Risk-Findings table / mail. `NONE` disables the section entirely; `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` is the lowest level reported. See [Risk-alert threshold](#risk-alert-threshold-alertrisklevel) below. |

## SMTP

| Field | Default | Description |
|---|---|---|
| `smtp.host` | – | SMTP server hostname. |
| `smtp.port` | `587` | SMTP port. |
| `smtp.user` | – | SMTP username. Optional; alerts skip silently if blank. |
| `smtp.password` | – | SMTP password. |
| `smtp.from` | – | Sender email address. |
| `smtp.to` | – | Alert recipient email address. |
| `smtp.useSsl` | port-derived | `true` enables TLS (587/465). When omitted, defaults to `false` for port 25 (typical local relay) and `true` otherwise. Explicit value always wins. |

All path values must include the full filename. Backslashes must be escaped as `\\` in JSON.

`state.json`, `oui.csv`, and `rdd-audit.csv` are also excluded from git.

## AXFR pre-fill (`dnsZoneTransfer`)

| Field | Default | Description |
|---|---|---|
| `dnsZoneTransfer.enabled` | `true` | If true, RDD attempts an AXFR (DNS zone transfer) at the start of every scan and uses the result as a hostname pre-fill. AXFR is denied by most DNS servers out of the box, so an unauthorised attempt costs only one WARN log line. |
| `dnsZoneTransfer.server` | auto-detect | DNS server to query (the authoritative server for the zone). Empty = first IPv4 DNS server of the active network adapter. |
| `dnsZoneTransfer.zone` | auto-detect | Forward zone to transfer (e.g. `corp.example.com`). Empty = `$env:USERDNSDOMAIN` (Windows AD), then DnsSuffix from the active interface. |

When enabled, RDD asks the configured (or auto-discovered) DNS server for the entire forward zone via AXFR at the start of every scan. Every A record returned becomes part of an in-memory IP→hostname map; matching IPs in the current ARP scan get their hostname set immediately and skip every later resolver stage. On a domain with hundreds of statically-assigned devices that don't speak mDNS/LLMNR/NetBIOS (switches, USVs, IoT with manual DNS records), this is by far the most effective hostname source.

AXFR is denied by default on every modern DNS server — that's intentional. To allow RDD's host:

**Windows DNS Server** (PowerShell, run as Administrator on the DNS server):

```powershell
# Allow only the RDD host(s) to transfer the zone
Set-DnsServerPrimaryZone -Name "corp.example.com" `
    -SecureSecondaries TransferToSecureServers `
    -SecondaryServers "192.168.1.50"
```

**BIND** (`named.conf`):

```
zone "corp.example.com" {
    type master;
    file "corp.example.com.zone";
    allow-transfer { 192.168.1.50; };   # RDD host(s)
};
```

If AXFR is denied, refused, or the server is unreachable, RDD logs a single WARN line (`AXFR for '<zone>' from <server> skipped (refused: REFUSED).`) and the hostname cascade falls through to DNS reverse / mDNS / LLMNR / NetBIOS exactly as before. Setting `dnsZoneTransfer.enabled` to `false` skips the attempt entirely.

To diagnose AXFR problems (transfer succeeds at the wire level but the alert still says `Map size: 0`, or a server replies with something unusual), see [diagnostics.md](diagnostics.md#axfr-specific-test-axfrps1).

## Risk-alert threshold (`alertRiskLevel`)

Controls how chatty the Risk-Findings table in the email is. The level a device is assigned comes from the worst port on that device (see the port→risk mapping in [architecture.md](architecture.md#security-ports-monitored)).

| Setting | Risk-Findings section behaviour | Typical noise level |
|---------|---------------------------------|---------------------|
| `NONE` | Section disabled. No risk row, no `RISK_FOUND` audit entry, no risk count in the subject. | Silent |
| `CRITICAL` | Telnet only (any other CRITICAL port additions live here too). | Very quiet |
| `HIGH` (default) | FTP, SMB, RDP, **+** CRITICAL. Sane default for most networks. | Quiet |
| `MEDIUM` | Adds exposed SMTP. | Moderate |
| `LOW` | Adds SSH and HTTP — every device with any monitored port shows up. | Chatty |

Invalid values fall back to `HIGH` with a WARN line in the console log. Rogues with a port at-or-above the threshold appear in **both** the Rogue table (identity view) and the Risk-Findings table (security view). Per-device port allowlisting via `-AllowPort` is applied before the threshold check, so an explicitly-allowed RDP on a known terminal server stays out.

## Audit log rotation

`rdd-audit.csv` is rotated automatically when its size exceeds 10 MB. The active file is renamed to `<base>.YYYY-MM-DD-HHmmss.csv` and a fresh CSV with the same header is started. Rotated files stay on disk for the operator to archive or prune.
