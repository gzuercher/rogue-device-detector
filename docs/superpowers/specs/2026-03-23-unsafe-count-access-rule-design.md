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

### Classified as UNSAFE (emits warning):

| Pattern | Reason |
|---------|--------|
| `$var.Count` where `$var = ... \| ForEach-Object { }` | Pipeline can unroll to single object |
| `$var.Count` where `$var = SomeFunction ...` | Function return can unroll |
| `$var.Count` where origin cannot be determined as safe | Conservative — flag for review |

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

Add `-CustomRulePath ./rules/` to existing `Invoke-ScriptAnalyzer` calls.

### Local Hook (`.claude/hooks/lint-ps1.sh`)

Add `-CustomRulePath ./rules/` to existing `Invoke-ScriptAnalyzer` call.

### Severity

**Warning** — allows `[SuppressMessage]` for intentional exceptions. Does not break CI unless combined with `-WarningAction Stop`.

## Output Format

```
WARNING: rogue-device-detector.ps1:1388 - .Count access on '$arpEntries' may fail
under StrictMode if the value is not an array. Wrap in @(): @($arpEntries).Count
```

## Limitations

- AST analysis is static: it cannot trace variable assignments across function boundaries or dynamic reassignment. The rule is conservative — it may produce false positives that should be suppressed with `[SuppressMessage]`.
- Only checks `.Count`. Other strict-mode-sensitive patterns (`.Length`, indexing) are out of scope for this iteration.
