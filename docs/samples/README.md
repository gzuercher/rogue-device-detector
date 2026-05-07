# Samples

Static artefacts checked into the repo so prospective users can see what RDD output looks like without installing it.

## `sample-report.html`

Rendered HTML of the alert email RDD sends when a scan finds rogue devices, risk findings, and absent baseline entries. Open in a browser, or view via the htmlpreview-link from the top-level [README](../../README.md).

## `sample-report.png`

A flat screenshot of the same artefact, embedded in the top-level README for visitors who don't want to click through. Regenerated the same way the HTML is, plus one Chrome-headless step.

## What the fixture covers

- **Rogue Devices** — three new MACs: one with an mDNS hostname (`[mdns]` source tag), one with no resolver answer at all, one with no resolver answer but an operator-set label that falls back into the hostname column with a `[label]` tag.
- **Risk Findings on Known Devices** — a baseline entry whose open SMB + RDP ports cross the default `HIGH` threshold.
- **Absent Devices** — a known device that has not been seen for longer than `absentDays`.
- **Alias-match candidates** — a rogue whose hostname is similar to a baseline device, with a copy-paste `-AliasOf` snippet underneath.

All MACs, IPs, and hostnames are synthetic. IPs use RFC 5737 (`192.0.2.0/24`, the documentation range); SMTP fields use the `.invalid` TLD per RFC 2606.

## Regenerating

After changes to `Send-RogueAlert`, re-render both artefacts. From the repo root:

```powershell
# 1. Rebuild the HTML from synthetic fixtures (no network traffic).
pwsh -NoProfile -File tools/Build-SampleReport.ps1

# 2. Render the HTML to PNG with Chrome headless (macOS path shown;
#    use `chrome` on Linux or the chrome.exe path on Windows).
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" `
    --headless --disable-gpu --no-sandbox --hide-scrollbars `
    --window-size=900,1400 `
    --screenshot=docs/samples/sample-report.png `
    "file://$PWD/docs/samples/sample-report.html"
```

The PNG step is manual on purpose — embedding a headless-browser dependency in the build script is more friction than the value of an auto-regenerated screenshot.
