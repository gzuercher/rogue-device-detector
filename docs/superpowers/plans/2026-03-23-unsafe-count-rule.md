# Measure-UnsafeCountAccess Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a PSScriptAnalyzer custom rule that detects `.Count` accesses on variables not provably backed by an array or typed collection, preventing StrictMode crashes.

**Architecture:** A single `.psm1` module exporting one function (`Measure-UnsafeCountAccess`) that uses PowerShell AST to find `MemberExpressionAst` nodes accessing `.Count`, then checks if the expression is protected (wrapped in `@()`, typed as collection, etc.). Integrated into existing CI and local hook.

**Tech Stack:** PowerShell, PSScriptAnalyzer custom rules API, Pester 5 (for rule tests), GitHub Actions CI

**Spec:** `docs/superpowers/specs/2026-03-23-unsafe-count-access-rule-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `rules/Measure-UnsafeCountAccess.psm1` | Create | The custom rule module |
| `tests/Measure-UnsafeCountAccess.Tests.ps1` | Create | Pester tests for the rule |
| `.github/workflows/test.yml` (line 25) | Modify | Add `-CustomRulePath ./rules/` to quality check |
| `.claude/hooks/lint-ps1.sh` (line 42) | Modify | Add `-CustomRulePath` to quality check |

---

### Task 1: Create rule skeleton and failing tests

**Files:**
- Create: `rules/Measure-UnsafeCountAccess.psm1` (minimal skeleton)
- Create: `tests/Measure-UnsafeCountAccess.Tests.ps1`

- [ ] **Step 1: Create `rules/` directory and minimal rule skeleton**

The skeleton exports the function but always returns empty (no detection yet). This allows tests to import and call it.

```powershell
# rules/Measure-UnsafeCountAccess.psm1

function Measure-UnsafeCountAccess {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    # TODO: implement detection
    return @()
}

Export-ModuleMember -Function Measure-UnsafeCountAccess
```

- [ ] **Step 2: Create test file covering all safe and unsafe patterns from the spec**

```powershell
# tests/Measure-UnsafeCountAccess.Tests.ps1

BeforeAll {
    Import-Module "$PSScriptRoot/../rules/Measure-UnsafeCountAccess.psm1" -Force
}

Describe 'Measure-UnsafeCountAccess' {

    function Invoke-Rule {
        param([string]$Code)
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$null, [ref]$null)
        Measure-UnsafeCountAccess -ScriptBlockAst $ast
    }

    Context 'SAFE patterns — should produce no warnings' {

        It 'allows @(...).Count (ArrayExpressionAst)' {
            $results = Invoke-Rule '@($items | Where-Object { $_ }).Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows $var.Count when $var = @(...)' {
            $results = Invoke-Rule '$devices = @(Get-Something); $devices.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows $var.Count when $var = @{}' {
            $results = Invoke-Rule '$db = @{}; $db.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows .ToArray().Count' {
            $results = Invoke-Rule '$list.ToArray().Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows @{}.Count directly' {
            $results = Invoke-Rule '@{}.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows @((Get-Something)).Count — parenthesized command inside @()' {
            $results = Invoke-Rule '@((Get-ChildItem)).Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows [array] typed parameter' {
            $results = Invoke-Rule 'param([array]$Devices) $Devices.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows typed array parameter like [PSCustomObject[]]' {
            $results = Invoke-Rule 'param([PSCustomObject[]]$Items) $Items.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows [hashtable] typed parameter' {
            $results = Invoke-Rule 'param([hashtable]$Config) $Config.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows [System.Collections.Generic.List[PSCustomObject]] typed parameter' {
            $results = Invoke-Rule 'param([System.Collections.Generic.List[PSCustomObject]]$Items) $Items.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows [System.Collections.Generic.Dictionary[string,object]] typed parameter' {
            $results = Invoke-Rule 'param([System.Collections.Generic.Dictionary[string,object]]$Map) $Map.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows [System.Collections.Generic.List[PSCustomObject]]::new() assignment' {
            $results = Invoke-Rule '$list = [System.Collections.Generic.List[PSCustomObject]]::new(); $list.Count'
            $results | Should -BeNullOrEmpty
        }

        It 'allows [System.Collections.Generic.List[int]]::new() assignment' {
            $results = Invoke-Rule '$open = [System.Collections.Generic.List[int]]::new(); $open.Count'
            $results | Should -BeNullOrEmpty
        }
    }

    Context 'UNSAFE patterns — should produce warnings' {

        It 'flags $var.Count from pipeline assignment' {
            $code = '$devices = Get-Something | ForEach-Object { $_ }; $devices.Count'
            $results = Invoke-Rule $code
            $results | Should -HaveCount 1
            $results[0].RuleName | Should -Be 'Measure-UnsafeCountAccess'
            $results[0].Severity | Should -Be 'Warning'
        }

        It 'flags $var.Count from function call assignment' {
            $code = '$entries = Get-ArpEntry -SubnetInfo $info; $entries.Count'
            $results = Invoke-Rule $code
            $results | Should -HaveCount 1
        }

        It 'flags $var.Count with no visible assignment' {
            $results = Invoke-Rule '$unknown.Count'
            $results | Should -HaveCount 1
        }

        It 'flags (Get-Something).Count without @() wrap' {
            $results = Invoke-Rule '(Get-ChildItem).Count'
            $results | Should -HaveCount 1
        }
    }

    Context 'Scope boundary — assignment tracing does not cross functions' {

        It 'flags $var.Count inside nested function even if $var = @() in outer scope' {
            $code = @'
$items = @(1, 2, 3)
function Test-Inner {
    $items.Count
}
'@
            $results = Invoke-Rule $code
            # The .Count inside the function body should be flagged because
            # the @() assignment is in the outer scope, not the function scope.
            $results | Should -HaveCount 1
        }
    }

    Context 'Warning message format' {

        It 'includes variable name and fix suggestion' {
            $code = '$items = Get-Items; $items.Count'
            $results = Invoke-Rule $code
            $results[0].Message | Should -BeLike '*items*'
            $results[0].Message | Should -BeLike '*@(*'
        }
    }

    Context 'Real-world script validation' {

        It 'produces no warnings on rogue-device-detector.ps1' {
            $scriptPath = "$PSScriptRoot/../rogue-device-detector.ps1"
            if (-not (Test-Path $scriptPath)) {
                Set-ItResult -Skipped -Because 'Main script not found'
                return
            }
            $ast = [System.Management.Automation.Language.Parser]::ParseInput(
                (Get-Content $scriptPath -Raw), [ref]$null, [ref]$null
            )
            $results = Measure-UnsafeCountAccess -ScriptBlockAst $ast
            $results | Should -BeNullOrEmpty
        }
    }
}
```

- [ ] **Step 3: Run tests — UNSAFE tests should fail (skeleton returns empty)**

Run: `pwsh -NoProfile -Command "Invoke-Pester ./tests/Measure-UnsafeCountAccess.Tests.ps1 -Output Detailed"`

Expected: SAFE tests pass (empty result matches expectation), UNSAFE tests **fail** (expected 1 warning, got 0). This confirms the tests are correctly written and the skeleton needs implementation.

- [ ] **Step 4: Commit skeleton and tests**

```bash
git add rules/Measure-UnsafeCountAccess.psm1 tests/Measure-UnsafeCountAccess.Tests.ps1
git commit -m "test: add Pester tests for Measure-UnsafeCountAccess rule (red phase)

Tests cover all safe/unsafe patterns from the spec. UNSAFE tests
intentionally fail against the skeleton — implementation follows."
```

---

### Task 2: Implement the rule to make all tests pass

**Files:**
- Modify: `rules/Measure-UnsafeCountAccess.psm1`

- [ ] **Step 1: Replace skeleton with full implementation**

Replace the entire content of `rules/Measure-UnsafeCountAccess.psm1` with:

```powershell
# rules/Measure-UnsafeCountAccess.psm1
#
# PSScriptAnalyzer custom rule: detects .Count access on variables not provably
# backed by an array or typed collection. Under Set-StrictMode -Version Latest,
# .Count on a single object or $null throws PropertyNotFoundException.

function Measure-UnsafeCountAccess {
    <#
    .SYNOPSIS
        Detects .Count access on variables not provably backed by an array or typed collection.
    .DESCRIPTION
        PSScriptAnalyzer custom rule. Finds MemberExpressionAst nodes accessing .Count
        and checks whether the expression is protected:
        - Wrapped in @() (ArrayExpressionAst)
        - Variable typed as [array], [T[]], [List[T]], [hashtable], [Dictionary[K,V]], [ArrayList]
        - Result of .ToArray() call
        - Assigned from @(), @{}, or [SafeType]::new() in same scope
    #>
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    $results = [System.Collections.Generic.List[Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord]]::new()

    # Find all .Count member accesses
    $countAccesses = $ScriptBlockAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.MemberExpressionAst] -and
        $ast.Member.Value -eq 'Count' -and
        -not $ast.Static
    }, $true)

    foreach ($access in $countAccesses) {
        $expr = $access.Expression

        # SAFE: @(...).Count — ArrayExpressionAst
        if ($expr -is [System.Management.Automation.Language.ArrayExpressionAst]) {
            continue
        }

        # SAFE: something.ToArray().Count — InvokeMemberExpressionAst calling ToArray
        if ($expr -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $expr.Member.Value -eq 'ToArray') {
            continue
        }

        # SAFE: @{}.Count — HashtableLiteral
        if ($expr -is [System.Management.Automation.Language.HashtableAst]) {
            continue
        }

        # For variable accesses, check type constraints and assignments in same scope
        if ($expr -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $varName = $expr.VariablePath.UserPath

            # Find the enclosing scope (nearest ScriptBlockAst parent)
            $scope = Get-EnclosingScope -Ast $access -RootAst $ScriptBlockAst

            if (Test-VariableSafe -VariableName $varName -ScopeAst $scope -AccessAst $access) {
                continue
            }
        }

        # Not proven safe — emit warning
        $results.Add([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord]@{
            Message  = ".Count access on '$($access.Expression.Extent.Text)' may fail under StrictMode if the value is not an array. Wrap in @(): @($($access.Expression.Extent.Text)).Count"
            Extent   = $access.Extent
            RuleName = 'Measure-UnsafeCountAccess'
            Severity = 'Warning'
        })
    }

    return $results.ToArray()
}

function Get-EnclosingScope {
    <#
    .SYNOPSIS
        Walks up the AST from a node to find its nearest enclosing ScriptBlockAst
        (function body, scriptblock, or the root). This defines the scope for
        variable assignment tracing.
    #>
    param(
        [System.Management.Automation.Language.Ast]$Ast,
        [System.Management.Automation.Language.ScriptBlockAst]$RootAst
    )

    $current = $Ast.Parent
    while ($null -ne $current) {
        if ($current -is [System.Management.Automation.Language.ScriptBlockAst] -and
            $current -ne $RootAst) {
            return $current
        }
        $current = $current.Parent
    }
    return $RootAst
}

function Test-VariableSafe {
    <#
    .SYNOPSIS
        Checks if a variable is provably safe for .Count access by examining
        type constraints in parameters and assignments in the enclosing scope.
    #>
    param(
        [string]$VariableName,
        [System.Management.Automation.Language.ScriptBlockAst]$ScopeAst,
        [System.Management.Automation.Language.Ast]$AccessAst
    )

    $safeTypePatterns = @(
        '^\[?array\]?$',
        '\[\]$',                                          # any typed array like [PSCustomObject[]]
        'System\.Collections\.Generic\.List\[',           # List<T>
        'System\.Collections\.Generic\.Dictionary\[',     # Dictionary<K,V>
        '^\[?hashtable\]?$',
        'System\.Collections\.ArrayList'
    )

    # Check param blocks within this scope for type constraints
    $allParams = $ScopeAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.ParameterAst] -and
        $ast.Name.VariablePath.UserPath -eq $VariableName
    }, $true)

    foreach ($param in $allParams) {
        foreach ($attr in $param.Attributes) {
            if ($attr -is [System.Management.Automation.Language.TypeConstraintAst]) {
                $typeName = $attr.TypeName.FullName
                foreach ($pattern in $safeTypePatterns) {
                    if ($typeName -match $pattern) { return $true }
                }
            }
        }
    }

    # Check assignments in same scope: $var = @(...), $var = @{}, $var = [SafeType]::new()
    $assignments = $ScopeAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $ast.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $ast.Left.VariablePath.UserPath -eq $VariableName
    }, $true)

    foreach ($assignment in $assignments) {
        # Only consider assignments before the .Count access
        if ($assignment.Extent.StartOffset -gt $AccessAst.Extent.StartOffset) {
            continue
        }

        $rhs = $assignment.Right

        # $var = @(...)
        if ($rhs -is [System.Management.Automation.Language.ArrayExpressionAst]) {
            return $true
        }

        # $var = @{}
        if ($rhs -is [System.Management.Automation.Language.HashtableAst]) {
            return $true
        }

        # $var = [SafeType]::new() — unwrap pipeline wrapper
        if ($rhs -is [System.Management.Automation.Language.PipelineAst]) {
            $cmdExpr = $rhs.PipelineElements[0]
            if ($cmdExpr -is [System.Management.Automation.Language.CommandExpressionAst]) {
                $innerExpr = $cmdExpr.Expression
                if ($innerExpr -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                    $innerExpr.Static -and
                    $innerExpr.Member.Value -eq 'new' -and
                    $innerExpr.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
                    $typeName = $innerExpr.Expression.TypeName.FullName
                    foreach ($pattern in $safeTypePatterns) {
                        if ($typeName -match $pattern) { return $true }
                    }
                }
            }
        }
    }

    return $false
}

Export-ModuleMember -Function Measure-UnsafeCountAccess
```

- [ ] **Step 2: Run all tests**

Run: `pwsh -NoProfile -Command "Invoke-Pester ./tests/Measure-UnsafeCountAccess.Tests.ps1 -Output Detailed"`

Expected: All tests pass — SAFE patterns produce no warnings, UNSAFE patterns produce exactly 1 warning each, scope boundary test passes, real-world script validation passes.

If the real-world test fails with false positives on `rogue-device-detector.ps1`, fix the rule (add the missing safe pattern), do NOT suppress. Re-run tests until green.

- [ ] **Step 3: Commit**

```bash
git add rules/Measure-UnsafeCountAccess.psm1
git commit -m "feat: implement Measure-UnsafeCountAccess detection logic

Detects .Count on unprotected variables via AST analysis. Safe patterns:
@() wrap, typed params, List/Dictionary/hashtable, .ToArray(), [Type]::new().
Assignment tracing is scoped to enclosing function/scriptblock."
```

---

### Task 3: Integrate into CI and local hook

**Files:**
- Modify: `.github/workflows/test.yml` (line 25-26)
- Modify: `.claude/hooks/lint-ps1.sh` (line 42)

- [ ] **Step 1: Add `-CustomRulePath` to CI quality check**

In `.github/workflows/test.yml`, change:

```yaml
          $results = Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error,Warning `
            -ExcludeRule PSAvoidUsingWriteHost
```

to:

```yaml
          $results = Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error,Warning `
            -ExcludeRule PSAvoidUsingWriteHost `
            -CustomRulePath ./rules/
```

- [ ] **Step 2: Add `-CustomRulePath` to local hook quality check**

In `.claude/hooks/lint-ps1.sh`, change line 42:

```bash
  $quality = Invoke-ScriptAnalyzer -Path $file -Severity Error,Warning -ExcludeRule PSAvoidUsingWriteHost
```

to:

```bash
  $repoRoot = & git -C (Split-Path -Parent $file) rev-parse --show-toplevel 2>$null
  $rulesPath = if ($repoRoot) { Join-Path $repoRoot "rules" } else { $null }
  $qualityParams = @{
    Path        = $file
    Severity    = @("Error", "Warning")
    ExcludeRule = "PSAvoidUsingWriteHost"
  }
  if ($rulesPath -and (Test-Path $rulesPath)) { $qualityParams["CustomRulePath"] = $rulesPath }
  $quality = Invoke-ScriptAnalyzer @qualityParams
```

Uses `git rev-parse --show-toplevel` to reliably find the repo root regardless of the `.ps1` file's depth. Falls back gracefully if not in a git repo.

- [ ] **Step 3: Verify locally — run PSScriptAnalyzer with custom rule**

Run: `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./rogue-device-detector.ps1 -Severity Error,Warning -ExcludeRule PSAvoidUsingWriteHost -CustomRulePath ./rules/ | Format-Table RuleName, Line, Message -AutoSize"`

Expected: No output (zero violations on the main script).

- [ ] **Step 4: Run full Pester suite to ensure nothing is broken**

Run: `pwsh -NoProfile -Command "Invoke-Pester ./tests/ -Output Detailed"`

Expected: All tests pass (both existing tests and new rule tests).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/test.yml .claude/hooks/lint-ps1.sh
git commit -m "ci: integrate Measure-UnsafeCountAccess into quality checks

Adds -CustomRulePath ./rules/ to CI workflow and local lint hook
so unsafe .Count accesses are caught in PRs and during editing."
```
