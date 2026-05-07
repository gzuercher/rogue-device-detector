# Diagnostics

When something does not behave as expected — AXFR refused, hostnames not resolving, SMTP not sending — re-run the scan with PowerShell's standard tracing switches and pipe **all six streams** into a log file:

```powershell
# Per-stage tracing: hostname stage hits/misses with timings, full
# exception messages on every catch, AXFR send/receive trace, SMTP
# connection params. Captures everything except the AXFR hex dump.
.\rogue-device-detector.ps1 -Verbose *>&1 | Tee-Object scan.log

# Same as -Verbose plus a hex dump of the first 64 bytes of any AXFR
# response. The hex dump is what you need when reporting an unparseable
# AXFR reply.
.\rogue-device-detector.ps1 -Debug *>&1 | Tee-Object debug.log
```

> **Important:** use `*>&1`, not `2>&1`. PowerShell has six output streams (Output / Error / Warning / Verbose / Debug / Information); `2>&1` only redirects errors, so `Tee-Object` would miss everything `Write-Verbose` and `Write-Debug` produce — exactly the diagnostic detail you wanted to capture. `*>&1` redirects all streams.

The output of `-Debug` is what to attach to a bug report.

## What `-Verbose` adds, by stage

| Stage | What gets logged |
|---|---|
| Config load | Resolved subnet, paths, SMTP, AXFR settings; parse exception on failure. |
| Ping sweep | Total duration; per-IP exception messages on ping failure. |
| AXFR pre-fill | Connect target/timeout, sent bytes, message-by-message parse (rcode/SOA/A counts). |
| DNS / mDNS / LLMNR / NetBIOS | Per-IP resolved/no-answer/exception; per-stage hits/total/duration. |
| UPnP discovery | Discovery duration + announcer count. |
| Port scan | Per-IP open ports list. |
| Enrichment | Total duration. |
| State load | File path, JSON parse exception. |
| State save | Known-device + seenRogues counts written. |
| SMTP send | Host/port/SSL/auth params; full exception incl. inner on failure. |
| Audit log rotation | Rotation-failure reason. |

`-Debug` adds a hex dump of the first 64 bytes of any AXFR response — needed when the parser disagrees with what the wire actually delivered.

## AXFR-specific: `Test-Axfr.ps1`

For AXFR-specific issues (the production scan reports `malformed`, an unfamiliar status, or `Map size: 0` despite a healthy DNS server), the focused diagnostic helper covers SOA → TCP/53 → raw send + receive → parse → production-path call side-by-side and ends with a colour-coded verdict.

Download it next to `rogue-device-detector.ps1` and run:

```powershell
$url = 'https://raw.githubusercontent.com/gzuercher/rogue-device-detector/main/tools/Test-Axfr.ps1'
Invoke-WebRequest $url -OutFile .\Test-Axfr.ps1 -UseBasicParsing
.\Test-Axfr.ps1 -Verbose *>&1 | Tee-Object axfr.log
```

It dot-sources the main script for the same wire-format helpers, prints a compact pass/fail per step, and ends with an actionable verdict (e.g. "AXFR REFUSED — authorise this host" with the `Set-DnsServerPrimaryZone` / BIND `allow-transfer` snippet inline). With `-Verbose` it adds the full hex dump and exception stack — that's the form to attach when the production scan reports an AXFR error you can't pin down.
