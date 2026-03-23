# PSScriptAnalyzer Custom Rule: Measure-UnsafeCountAccess

## Problem

PowerShell with `Set-StrictMode -Version Latest` throws `PropertyNotFoundException` when `.Count` is accessed on a variable that holds a single object or `$null` instead of an array. This happens because PowerShell's pipeline unrolls single-element arrays when returning from functions or pipeline expressions.

Example:

```powershell
$devices = Get-Something | ForEach-Object { ... }
# If pipeline returns exactly 1 result, $devices is a single object, not an array.
$devices.Count  # Throws under StrictMode
```

Fix: wrap in `@()` to guarantee an array:

```powershell
$devices = @(Get-Something | ForEach-Object { ... })
$devices.Count  # Always works
```

## Solution

A PSScriptAnalyzer custom rule that statically detects unprotected `.Count` accesses via AST analysis.

## Scope

- Detects `.Count` member access on variables not provably backed by an array or typed collection.
- Does NOT cover `.Length`, indexing (`[0]`), or other array-only operations (can be extended later).
- Does NOT detect `.Count` on scalar-typed variables (`[int]`, `[string]`) — that is a logic error, not the pipeline-unrolling problem this rule targets.

## Rule Function Signature

The rule follows the PSScriptAnalyzer custom rule convention:

```powershell
function Measure-UnsafeCountAccess {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )
    # ...
}
```

Uses `$ScriptBlockAst.FindAll()` to locate all `MemberExpressionAst` nodes where the member is `Count`.

## Detection Logic

For every `MemberExpressionAst` where the member name is `Count`:

### Classified as SAFE (no warning):

| Pattern | Reason |
|---------|--------|
| `@(...).Count` | `ArrayExpressionAst` always produces array |
| `$var.Count` where `$var` is declared `[array]` in param block | Type constraint guarantees array |
| `$var.Count` where `$var` is declared `[PSCustomObject[]]` or any `[]` type | Typed array |
| `$var.Count` where `$var` is `[System.Collections.Generic.List[...]]` | Generic List has `.Count` |
| `$var.Count` where `$var` is `[hashtable]` or `[System.Collections.Generic.Dictionary[...]]` | Hashtable/Dictionary has `.Count` |
| `$var.ToArray().Count` | `.ToArray()` returns typed array |
| `$hashtable.Count` where `$hashtable = @{}` | Hashtable literal |
| `$var.Count` where `$var = @(...)` in same scope | Assignment wrapped in `@()` — trace within same function/script scope |
| `(Get-Something).Count` inside `@(...)` | Wrapped in array subexpression |

### Classified as UNSAFE (emits warning):

| Pattern | Reason |
|---------|--------|
| `$var.Count` where `$var = ... \| ForEach-Object { }` (no `@()` wrap) | Pipeline can unroll to single object |
| `$var.Count` where `$var = SomeFunction ...` (no `@()` wrap) | Function return can unroll |
| `(Get-Something).Count` without `@()` wrap | Parenthesized pipeline, same unrolling risk |
| `$var.Count` where origin cannot be determined as safe | Conservative — flag for review |

### Assignment Tracing

The rule traces variable assignments within the same scope (function body or script block) to check if the variable was assigned with `@()`. It does NOT trace across function boundaries or dynamic reassignment.

Example — detected as safe:
```powershell
$devices = @(Get-ArpEntry -SubnetInfo $subnetInfo)
# ... later ...
$devices.Count   # Safe: assignment was wrapped in @()
```

### Suppression

Use standard PSScriptAnalyzer suppression for intentional exceptions:

```powershell
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('Measure-UnsafeCountAccess', '')]
```

## File Structure

```
rules/
  Measure-UnsafeCountAccess.psm1    # Custom rule module
```

## Integration

### CI (`.github/workflows/test.yml`)

Add `-CustomRulePath ./rules/` to the **quality check** step (the one with `-Severity Error,Warning`). The rule emits Warnings, which are already caught by that severity filter. Not needed on the security-rules step.

### Local Hook (`.claude/hooks/lint-ps1.sh`)

Add `-CustomRulePath ./rules/` to the **quality check** `Invoke-ScriptAnalyzer` call (first invocation). Not needed on the security-rules call.

### Severity

**Warning** — matches the existing `-Severity Error,Warning` filter in CI, so violations will break CI. Use `[SuppressMessage]` for intentional exceptions.

## Output Format

```
WARNING: rogue-device-detector.ps1:1388 - .Count access on '$arpEntries' may fail
under StrictMode if the value is not an array. Wrap in @(): @($arpEntries).Count
```

## Existing Violations

All known unsafe `.Count` accesses in `rogue-device-detector.ps1` have already been fixed by wrapping in `@()`. The rule should produce zero warnings on the current codebase. If it does produce false positives on initial run, suppress them with `[SuppressMessage]`.

## Limitations

- AST analysis is static: assignment tracing works within the same scope but cannot follow variable assignments across function boundaries or dynamic reassignment. The rule is conservative — it may produce false positives that should be suppressed with `[SuppressMessage]`.
- Only checks `.Count`. Other strict-mode-sensitive patterns (`.Length`, indexing) are out of scope for this iteration.
- Collection types beyond `List`, `Dictionary`, `hashtable`, and typed arrays (`[]`) are not explicitly recognized. They will be flagged conservatively. Add more types to the safe list as needed.
