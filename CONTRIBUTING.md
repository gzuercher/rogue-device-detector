# Contributing

Thanks for considering a contribution. The project is intentionally small — a
single PowerShell script plus an updater — so most changes are localised and
fast to review.

## Setup

Requirements on the dev machine:

- PowerShell 7+ (`pwsh`). Linux/macOS/Windows all fine. PowerShell 5.1 also
  works for running but tests and lint require 7+.
- Pester 5: `Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser`
- PSScriptAnalyzer: `Install-Module PSScriptAnalyzer -Scope CurrentUser`

Clone:

```bash
git clone https://github.com/gzuercher/rogue-device-detector.git
cd rogue-device-detector
```

## Run the test suite

```powershell
Invoke-Pester ./tests/ -Output Detailed
```

All tests must pass. CI runs Pester + PSScriptAnalyzer on every push.

## Lint

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error,Warning `
    -ExcludeRule PSAvoidUsingWriteHost `
    -CustomRulePath ./rules/ -RecurseCustomRulePath -IncludeDefaultRules
```

The project also ships a Claude Code hook (`.claude/hooks/lint-ps1.sh`) that
runs PSScriptAnalyzer on every `Edit`/`Write`. Optional but convenient.

## Code style

- `Set-StrictMode -Version Latest` is on; `.Count` on a possibly-null value
  must be wrapped in `@(...)`. The custom analyzer rule
  `Measure-UnsafeCountAccess` enforces this.
- Functions documented with comment-based help.
- No silent `try/catch` swallowing — surface errors. Exception: `$null = $_`
  in catch blocks where the failure is genuinely non-fatal (clean-up paths).
- No backslash-quoting paths shown to end users; prefer the
  `single-quoted-args / no call-operator` form so Outlook copy-paste survives.

## Releases

Don't bump `$SCRIPT_VERSION` manually — open a PR with the change and the
maintainer bumps + merges. The release workflow (tag + GitHub release with
SHA-256 sidecars) fires automatically on PR merge to `main`.

For RFC-style discussion of larger changes, open an issue first.
