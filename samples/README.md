# Samples

Static artefacts checked into the repo so prospective users can see what RDD output looks like without installing it.

## `sample-report.html`

A rendered example of the alert email RDD sends when a scan finds rogue devices, risk findings, and absent baseline entries. Open it in a browser.

The fixture covers the sections an operator is most likely to see:

- **Rogue Devices** — three new MACs, one with an mDNS hostname (`[mdns]` source tag), one with no resolver answer at all, one with no resolver answer but an operator-set label that falls back into the hostname column with a `[label]` tag.
- **Risk Findings on Known Devices** — a baseline entry whose open SMB + RDP ports cross the default `HIGH` threshold.
- **Absent Devices** — a known device that has not been seen for longer than `absentDays`.
- **Alias-match candidates** — a rogue whose hostname is similar to a baseline device, with a copy-paste `-AliasOf` snippet underneath.

All MACs, IPs, and hostnames are synthetic. IPs use RFC 5737 (`192.0.2.0/24`, the documentation range); SMTP fields use the `.invalid` TLD per RFC 2606.

## Regenerating

After changes to `Send-RogueAlert`, re-render the sample so it stays representative:

```powershell
# From the repo root
pwsh -NoProfile -File tools/Build-SampleReport.ps1
```

The script intercepts `Send-MailMessage`, captures the rendered HTML body, and writes it to `samples/sample-report.html`. No network traffic.
