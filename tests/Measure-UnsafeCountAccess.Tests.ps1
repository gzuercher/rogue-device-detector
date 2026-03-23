BeforeAll {
    Import-Module "$PSScriptRoot/../rules/Measure-UnsafeCountAccess.psm1" -Force
}

Describe 'Measure-UnsafeCountAccess' {

    BeforeAll {
        function Invoke-Rule {
            param([string]$Code)
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$null, [ref]$null)
            Measure-UnsafeCountAccess -ScriptBlockAst $ast
        }
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
