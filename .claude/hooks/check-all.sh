#!/usr/bin/env bash
# Claude Code Stop hook: runs PSScriptAnalyzer + Pester before Claude finishes.
# If either check fails, Claude is notified and must fix the issues.
#
# Requires PowerShell 7+ (pwsh) on the local machine:
#   macOS:   brew install --cask powershell
#   Windows: winget install Microsoft.PowerShell

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v pwsh &>/dev/null; then
  echo "SKIP: pwsh not found — install PowerShell 7 to enable local quality checks."
  exit 0
fi

echo "=== Quality gate: PSScriptAnalyzer + Pester ==="
echo ""

output=$(pwsh -NoProfile -NonInteractive -Command "
  Set-Location '$REPO_ROOT'

  # ── PSScriptAnalyzer ──────────────────────────────────────────────────────
  if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Host 'Installing PSScriptAnalyzer...'
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module PSScriptAnalyzer -Force -Scope CurrentUser
  }

  Write-Host '--- PSScriptAnalyzer ---'
  \$securityRules = @(
    'PSAvoidUsingInvokeExpression',
    'PSAvoidUsingPlainTextForPassword',
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    'PSAvoidUsingUsernameAndPasswordParams',
    'PSUsePSCredentialType'
  )
  \$quality  = Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error,Warning \`
                -ExcludeRule PSAvoidUsingWriteHost
  \$security = Invoke-ScriptAnalyzer -Path . -Recurse -IncludeRule \$securityRules
  \$all = @(\$quality) + @(\$security) | Sort-Object ScriptName, Line | Get-Unique -AsString

  if (\$all.Count -gt 0) {
    \$all | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize
    Write-Host \"PSScriptAnalyzer: \$(\$all.Count) issue(s) found.\"
    exit 1
  }
  Write-Host 'PSScriptAnalyzer: OK'

  # ── Pester ────────────────────────────────────────────────────────────────
  Write-Host ''
  Write-Host '--- Pester ---'
  if (-not (Get-Module -ListAvailable -Name Pester | Where-Object { \$_.Version -ge '5.0' })) {
    Write-Host 'Installing Pester 5...'
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser
  }

  \$config = New-PesterConfiguration
  \$config.Run.Path             = './tests'
  \$config.Output.Verbosity     = 'Minimal'
  \$config.TestResult.Enabled   = \$false
  \$result = Invoke-Pester -Configuration \$config

  if (\$result.FailedCount -gt 0) {
    Write-Host \"Pester: \$(\$result.FailedCount) test(s) failed.\"
    exit 1
  }
  Write-Host \"Pester: \$(\$result.PassedCount) test(s) passed.\"
" 2>&1)
exit_code=$?

if [ $exit_code -ne 0 ]; then
  echo "$output" >&2
  exit 1
fi

echo "$output"
