# Roadmap

Tracked-but-not-scheduled work. Items are removed when shipped or dropped.

## Security

- **Code-sign `Update-RogueDeviceDetector.ps1`** so endpoints fetching it via
  the RMM bootstrap one-liner can verify provenance against a pinned
  publisher cert before execution. Mitigates the residual repo-compromise
  risk the SHA-256 transit check does not cover.
  - Requires: code-signing cert (~$200/yr), CI signing step with secret
    storage, and a verification step in the bootstrap snippet
    (`Get-AuthenticodeSignature`).
  - Open question: also sign `rogue-device-detector.ps1` itself, or only
    the updater?

- **Sign main script** (`rogue-device-detector.ps1`) once the updater is
  signed — protects against tampering between updater download and main-script
  download even if attacker controls only the network path.

## UX

- **True one-liner bootstrap**: publish `bootstrap.ps1` as a release asset so
  the RMM snippet collapses to `iex (iwr <url>).Content`. Currently the
  recommended RMM body is a ~10-line script that does its own hash
  verification. Trade-off: an extra HTTP round-trip and an extra layer the
  operator can't audit at install time.
