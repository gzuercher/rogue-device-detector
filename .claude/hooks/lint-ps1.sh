#!/usr/bin/env bash
# Claude Code PostToolUse hook: runs PSScriptAnalyzer on edited .ps1 files.
# Requires PowerShell 7+ (pwsh) and PSScriptAnalyzer to be installed.
#
# Install on macOS:
#   brew install --cask powershell
#   pwsh -Command "Install-Module PSScriptAnalyzer -Force -Scope CurrentUser"

set -euo pipefail

# Parse file path from hook JSON input
INPUT=$(cat)
FILE=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('tool_input', {}).get('file_path', ''))
" 2>/dev/null || echo "")

# Only lint PowerShell files
[[ "$FILE" != *.ps1 ]] && exit 0

# Skip if pwsh is not available
if ! command -v pwsh &>/dev/null; then
  echo "PSScriptAnalyzer: pwsh not found — install PowerShell 7 to enable local linting." >&2
  exit 0
fi

echo "PSScriptAnalyzer: checking $FILE ..."

export PS1_FILE="$FILE"
pwsh -NoProfile -NonInteractive -Command '
  $file = $env:PS1_FILE

  # Install PSScriptAnalyzer if missing
  if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Host "Installing PSScriptAnalyzer..."
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module PSScriptAnalyzer -Force -Scope CurrentUser
  }

  # Quality check
  $repoRoot = & git -C (Split-Path -Parent $file) rev-parse --show-toplevel 2>$null
  $rulesPath = if ($repoRoot) { Join-Path $repoRoot "rules" } else { $null }
  $qualityParams = @{
    Path        = $file
    Severity    = @("Error", "Warning")
    ExcludeRule = "PSAvoidUsingWriteHost"
  }
  if ($rulesPath -and (Test-Path $rulesPath)) {
    $qualityParams["CustomRulePath"] = $rulesPath
    $qualityParams["RecurseCustomRulePath"] = $true
    $qualityParams["IncludeDefaultRules"] = $true
  }
  $quality = Invoke-ScriptAnalyzer @qualityParams

  # Security check (always run, regardless of severity)
  $securityRules = @(
    "PSAvoidUsingInvokeExpression",
    "PSAvoidUsingPlainTextForPassword",
    "PSAvoidUsingConvertToSecureStringWithPlainText",
    "PSAvoidUsingUsernameAndPasswordParams",
    "PSUsePSCredentialType"
  )
  $security = Invoke-ScriptAnalyzer -Path $file -IncludeRule $securityRules

  $all = @($quality) + @($security) | Sort-Object Line -Unique

  if ($all.Count -gt 0) {
    $all | Format-Table RuleName, Severity, Line, Message -AutoSize
    Write-Host ""
    Write-Host "Fix the issues above before committing."
    exit 1
  }

  Write-Host "OK — no issues found."
'
