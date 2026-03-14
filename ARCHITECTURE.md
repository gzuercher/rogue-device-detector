# ARCHITECTURE.md

Technical design and decisions for the rogue-device-detector.

## Goal

Detect unknown (rogue) devices on customer networks as part of an MSP security offering. Integrates fully into NinjaOne RMM – no separate infrastructure required.

## Data Flow

```
NinjaOne Scheduled Task (per organization / site)
  └─ PowerShell Script
       ├─ 1. Read config (NinjaOne Custom Fields or parameters)
       ├─ 2. Determine subnet (auto-detect from NIC or config override)
       ├─ 3. Ping sweep → populate ARP cache
       ├─ 4. Read ARP table → list of MACs + IPs
       ├─ 5. Resolve hostnames (reverse DNS + NetBIOS)
       ├─ 6. Lookup MAC vendor (OUI, offline)
       ├─ 7. Query NinjaOne API → known MACs (managed + unmanaged)
       ├─ 8. Compare: found vs known
       ├─ 9a. Learning Mode ON  → write all found devices to state file, no alerts
       └─ 9b. Learning Mode OFF → delta (new MACs only):
                ├─ Create unmanaged device in NinjaOne (tag: "Unverified")
                └─ Send alert email via SMTP
```

## State File

Local JSON file on the scanning device. Path is configurable. Can be moved to another device to migrate state.

```json
{
  "lastScan": "2025-03-14T08:00:00Z",
  "knownDevices": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "ip": "192.168.1.42",
      "hostname": "LAPTOP-XYZ",
      "vendor": "Apple Inc.",
      "firstSeen": "2025-03-01T10:00:00Z",
      "lastSeen": "2025-03-14T08:00:00Z",
      "ninjaDeviceId": 12345
    }
  ]
}
```

## Configuration (NinjaOne Custom Fields)

| Field | Type | Description |
|---|---|---|
| `rdd_subnet` | String | Subnet to scan (e.g. `192.168.1.0/24`). Empty = auto-detect. |
| `rdd_learning_mode` | Checkbox | If enabled, run in learning mode (no alerts). |
| `rdd_smtp_host` | String | SMTP server hostname |
| `rdd_smtp_port` | Integer | SMTP port (default: 587) |
| `rdd_smtp_user` | String | SMTP username |
| `rdd_smtp_password` | Secure | SMTP password |
| `rdd_alert_to` | String | Alert recipient email address |
| `rdd_alert_from` | String | Sender email address |
| `rdd_state_path` | String | Path to state JSON file. Default: script directory. |
| `rdd_ninja_client_id` | String | NinjaOne OAuth2 Client ID |
| `rdd_ninja_client_secret` | Secure | NinjaOne OAuth2 Client Secret (shown once – store immediately) |
| `rdd_ninja_token_url` | String | OAuth token endpoint URL (region-dependent) |
| `rdd_ninja_org_id` | Integer | NinjaOne organization ID for this customer |

## Features

### Included

- **Ping sweep + ARP scan** – Pure PowerShell, no external tools or installation
- **Auto-subnet detection** – Reads own NIC config; Custom Field overrides if needed
- **Hostname resolution** – Reverse DNS first, NetBIOS fallback
- **MAC vendor lookup** – Offline OUI database (IEEE), bundled with script
- **NinjaOne integration**:
  - Query managed + unmanaged devices as known-device source
  - Auto-create newly discovered devices as unmanaged (tag: "Unverified")
- **Learning mode** – First run baseline; all found devices written to state, zero alerts
- **SMTP alert** – Configurable, Azure ACS compatible (STARTTLS on port 587)
- **Portable state file** – JSON, path configurable, easy to migrate

### Explicitly Out of Scope

- Disappeared / offline device detection (too many false positives: holidays, device replacement)
- Weekly summary report
- SNMP ARP-table query
- Vulnerability scanning (separate tool / separate concern)
- Web UI or dashboard
- Cloud backend

## NinjaOne API Reference

Docs: https://app.ninjarmm.com/apidocs-beta/

### Authentication – OAuth 2.0 Client Credentials

Machine-to-machine flow. No user interaction required.

**Setup in NinjaOne:** Administration → Apps → API → Client app IDs → Add client app → Platform: "API Services (machine-to-machine)"

**Required scopes:**
| Scope | Why |
|---|---|
| `Monitoring` | Read managed + unmanaged devices |
| `Management` | Create unmanaged devices |
| `Control` | Not needed |

**Token endpoint** (region-dependent – configure via Custom Field):
- EU: `https://eu.ninjarmm.com/ws/oauth/token`
- US/Global: `https://app.ninjarmm.com/ws/oauth/token`

**Token request:**
```
POST /ws/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<CLIENT_ID>
&client_secret=<CLIENT_SECRET>
&scope=monitoring management
```

Token is short-lived (~1h). Script fetches a fresh token at runtime start; token is kept in memory only, never written to disk or state file. Client Secret is shown only once in NinjaOne – store immediately in Secure Custom Field.

### Endpoints Used

| Endpoint | Scope | Usage |
|---|---|---|
| `GET /v2/devices` | Monitoring | Fetch all managed devices (MACs) |
| `GET /v2/devices/unmanaged` | Monitoring | Fetch all unmanaged devices (MACs) |
| `POST /v2/devices/unmanaged` | Management | Create newly discovered rogue device |

## Deployment

1. Upload script to NinjaOne script library
2. Set Custom Fields at organization level
3. Schedule script as recurring task (recommended: every 4–6 hours)
4. First run: enable learning mode → review state file → disable learning mode

## Security Considerations

- NinjaOne API token and SMTP credentials stored as NinjaOne Secure Custom Fields (not in script)
- State file contains MAC addresses and hostnames – no credentials or personal data
- Script runs under NinjaOne agent user context (typically SYSTEM)
