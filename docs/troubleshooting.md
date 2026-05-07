# Troubleshooting

Common failure modes and their root causes. For deeper traces see [diagnostics.md](diagnostics.md).

## No devices found / ARP table empty

- The scanning host must be on the same Layer-2 network as the target subnet. Scanning across routers or VLANs does not work (routers don't forward broadcast traffic).
- Windows Firewall may block outbound ICMP (ping). Verify with `ping 192.168.1.1`.
- Run `arp -a` manually to check if the ARP cache is populated.

## OUI database download fails

- The script downloads from `https://standards-oui.ieee.org/oui/oui.csv`. Verify the host can reach this URL.
- If a proxy is required, the script uses the default system proxy settings.
- The scan continues without vendor names. Delete the cached `oui.csv` to force a fresh download.

## SMTP alerts not sending

- Check `config.json` for correct `smtp.host`, `smtp.port`, `smtp.from`, and `smtp.to`. Alerts skip silently if any of those three are blank.
- TLS error like *"Das Remotezertifikat ist laut Validierungsverfahren ungültig"*: set `smtp.useSsl: false` for plain SMTP (typical for port 25 local relays). When omitted, `useSsl` is auto-derived from the port (false for 25, true otherwise) — explicit values always win.
- Port 587 (STARTTLS) is the typical authenticated submission port. Port 465 (implicit TLS) is not supported by `Send-MailMessage`.
- Verify connectivity: `Test-NetConnection -ComputerName smtp.example.com -Port 587`.
- Azure Communication Services SMTP requires the full connection string as username.
- For full SMTP exception details: `.\rogue-device-detector.ps1 -TestSmtp -Verbose *>&1 | Tee-Object smtp.log` — see [diagnostics.md](diagnostics.md).

## AXFR fails with "malformed: …" or empty map

See [diagnostics.md → Test-Axfr.ps1](diagnostics.md#axfr-specific-test-axfrps1). The most common causes are:

- The auto-discovered DNS server doesn't host the target zone (e.g. an upstream resolver, not the authoritative server). Set `dnsZoneTransfer.server` explicitly.
- AXFR is denied by the server. Authorise the RDD host (see [configuration.md → AXFR pre-fill](configuration.md#axfr-pre-fill-dnszonetransfer)).
- The server hard-closes the TCP connection mid-stream instead of returning REFUSED. Common with non-authoritative DNS proxies (Synology DSM, dnsmasq).

## Scan takes too long

- Large subnets (e.g. /16 = 65k hosts) will be slow. Narrow the subnet or set `"enrichment": false`.
- Port scan and banner grab add time per device. Enrichment is most useful for /24 subnets.
- The NetBIOS hostname stage is sequential (~1.5s per unresolved host). On a /24 with many silent devices this can add a minute. AXFR pre-fill (when authorised) eliminates most of those queries.

## False positives (known devices reported as rogue)

- Devices with MAC randomization (e.g. phones) appear as new devices each time. Approve the new MAC or disable MAC randomization on the device.
- DHCP lease changes don't cause false positives — the baseline tracks MAC addresses, not IPs.
- A notebook with both Ethernet and WiFi has two MACs. Approve one normally with `-ApproveDevice -Label ...`, then attach the second with `-ApproveDevice "<wifi-mac>" -AliasOf "<ethernet-mac>"`. The alert email suggests these matches automatically.

## Permission errors on state/log files

- The script needs write access to `state.json`, `rdd-audit.csv`, and `oui.csv`.
- When running as a scheduled task, ensure the task's user account has write access.
- Avoid placing files in `C:\Program Files` or other protected directories.
