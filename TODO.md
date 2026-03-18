# RDD v1.3.0 — Planned Features

## To Implement

- [x] **State-File Versionierung** — `schemaVersion` Feld in state.json, automatische Migration bei Upgrades
- [x] **Pfad-Validierung vor Scan** — Prüfe statePath, logPath, ouiPath auf Schreibbarkeit bevor der Scan startet
- [x] **Concurrent DNS statt seriell** — Resolve-Hostname wartet aktuell sequenziell pro Host; alle Tasks parallel awaiten
- [x] **NetBIOS/mDNS als DNS-Fallback** — Wenn reverse DNS scheitert, versuche NetBIOS (Port 137) oder mDNS als Fallback
- [x] **/32 und /31 Edge Cases fixen** — Get-SubnetInfo gibt HostCount -1 für /32 und 0 für /31 zurück; sauber behandeln
- [x] **Concurrent Scan Guard** — Lock-File verhindern dass zwei Scans gleichzeitig state.json korrumpieren

## Future Ideas (nicht priorisiert)

- Suppress-Liste für bekannte "Rogues" (acknowledged but not approved)
- MAC-Randomization-Erkennung (gleicher Hostname, unterschiedliche MAC)
- Bulk-Import / Export von Baselines (CSV)
- Scan-Heartbeat (Monitoring ob RDD überhaupt noch läuft)
- SSH/RDP/SMB Banner Grabs für tiefere Analyse
- Multi-Subnet Support
- Teams/Slack Webhook-Alerts
- NinjaRMM API Integration (Managed vs. Unmanaged Detection)
