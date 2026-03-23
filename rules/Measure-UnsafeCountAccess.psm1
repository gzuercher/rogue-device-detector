# Ensure the DiagnosticRecord type is available (PSScriptAnalyzer may not be loaded in test contexts)
if (-not ('Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord' -as [type])) {
    try { Import-Module PSScriptAnalyzer -ErrorAction SilentlyContinue } catch { }
}

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
