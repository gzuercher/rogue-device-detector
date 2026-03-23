# rules/Measure-UnsafeCountAccess.psm1
#
# PSScriptAnalyzer custom rule: detects .Count access on variables not provably
# backed by an array or typed collection. Under Set-StrictMode -Version Latest,
# .Count on a single object or $null throws PropertyNotFoundException.

# Ensure PSScriptAnalyzer types are available (needed in test contexts)
if (-not ('Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord' -as [type])) {
    try { Import-Module PSScriptAnalyzer -ErrorAction SilentlyContinue } catch { $null = $_ }
}

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

        # SAFE (untrackable): property access like $obj.Property.Count or $obj.Method().Count
        # We can only trace simple variable assignments; member accesses are beyond our scope.
        # Only flag VariableExpressionAst (bare $var.Count) and ParenExpressionAst ((cmd).Count).
        if ($expr -isnot [System.Management.Automation.Language.VariableExpressionAst] -and
            $expr -isnot [System.Management.Automation.Language.ParenExpressionAst]) {
            continue
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

$script:safeTypePatterns = @(
    '^\[?array\]?$',
    '\[\]$',                                          # any typed array like [PSCustomObject[]]
    'System\.Collections\.Generic\.List\[',           # List<T>
    'System\.Collections\.Generic\.Dictionary\[',     # Dictionary<K,V>
    '^\[?hashtable\]?$',
    'System\.Collections\.ArrayList'
)

function Test-VariableSafe {
    <#
    .SYNOPSIS
        Checks if a variable is provably safe for .Count access by examining
        type constraints in parameters and assignments in the enclosing scope.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'VariableName',
        Justification = 'VariableName is used inside ScriptBlock closures passed to FindAll, which PSScriptAnalyzer cannot trace.')]
    param(
        [string]$VariableName,
        [System.Management.Automation.Language.ScriptBlockAst]$ScopeAst,
        [System.Management.Automation.Language.Ast]$AccessAst
    )

    # Check if variable is bound by a foreach statement (loop variable iterating over a collection)
    # We cannot trace the element type, so we treat foreach variables as safe to avoid false positives
    # on property accesses like $g.Count where Count is an object property, not array length.
    $foreachBindings = $ScopeAst.FindAll({
        param($ast)
        $ast -is [System.Management.Automation.Language.ForEachStatementAst] -and
        $ast.Variable.VariablePath.UserPath -eq $VariableName
    }, $true)

    foreach ($fe in $foreachBindings) {
        if ($fe.Extent.StartOffset -lt $AccessAst.Extent.StartOffset -and
            $AccessAst.Extent.StartOffset -lt $fe.Extent.EndOffset) {
            return $true
        }
    }

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
                foreach ($pattern in $script:safeTypePatterns) {
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

    # Track the safety of the last assignment before the .Count access
    $lastAssignmentSafe = $null

    foreach ($assignment in $assignments) {
        # Only consider assignments before the .Count access
        if ($assignment.Extent.StartOffset -gt $AccessAst.Extent.StartOffset) {
            continue
        }

        # Skip compound assignments like += which preserve the collection type
        if ($assignment.Operator -ne [System.Management.Automation.Language.TokenKind]::Equals) {
            continue
        }

        $rhs = $assignment.Right

        # Unwrap CommandExpressionAst wrapper to get the actual expression
        $innerRhs = $rhs
        if ($rhs -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $innerRhs = $rhs.Expression
        }

        # Assume unsafe unless proven otherwise
        $thisSafe = $false

        # $var = @(...)
        if ($innerRhs -is [System.Management.Automation.Language.ArrayExpressionAst]) {
            $thisSafe = $true
        }

        # $var = @{}
        if ($innerRhs -is [System.Management.Automation.Language.HashtableAst]) {
            $thisSafe = $true
        }

        # $var = $x -split '...' — -split always returns an array
        if ($innerRhs -is [System.Management.Automation.Language.BinaryExpressionAst] -and
            $innerRhs.Operator -eq [System.Management.Automation.Language.TokenKind]::Isplit) {
            $thisSafe = $true
        }

        # $var = [SafeType]::new()
        if ($innerRhs -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $innerRhs.Static -and
            $innerRhs.Member.Value -eq 'new' -and
            $innerRhs.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
            $typeName = $innerRhs.Expression.TypeName.FullName
            foreach ($pattern in $script:safeTypePatterns) {
                if ($typeName -match $pattern) { $thisSafe = $true; break }
            }
        }

        $lastAssignmentSafe = $thisSafe
    }

    if ($null -ne $lastAssignmentSafe) {
        return $lastAssignmentSafe
    }

    return $false
}

Export-ModuleMember -Function Measure-UnsafeCountAccess
