#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
.SYNOPSIS
    Pester tests for Update-RogueDeviceDetector.ps1 helpers.
#>

BeforeAll {
    $script:UpdaterPath = Resolve-Path "$PSScriptRoot\..\Update-RogueDeviceDetector.ps1"
    . $script:UpdaterPath
}

Describe 'Compare-SemVer' {
    It 'returns true when remote is strictly newer (patch)' {
        Compare-SemVer -Remote '1.2.4' -Local '1.2.3' | Should -BeTrue
    }
    It 'returns true when remote is strictly newer (minor)' {
        Compare-SemVer -Remote '1.3.0' -Local '1.2.99' | Should -BeTrue
    }
    It 'returns true when remote is strictly newer (major)' {
        Compare-SemVer -Remote '2.0.0' -Local '1.99.99' | Should -BeTrue
    }
    It 'returns false when versions are equal' {
        Compare-SemVer -Remote '1.4.0' -Local '1.4.0' | Should -BeFalse
    }
    It 'returns false when remote is older' {
        Compare-SemVer -Remote '1.2.3' -Local '1.4.0' | Should -BeFalse
    }
    It 'handles two-digit minor correctly (1.10 > 1.9)' {
        Compare-SemVer -Remote '1.10.0' -Local '1.9.5' | Should -BeTrue
    }
    It 'returns false on parse error rather than throwing' {
        Compare-SemVer -Remote 'not-a-version' -Local '1.0.0' | Should -BeFalse
    }
    It 'strips pre-release suffix before comparing' {
        Compare-SemVer -Remote '1.5.0-rc1' -Local '1.4.9' | Should -BeTrue
    }
}

Describe 'Build-ApiHeader' {
    It 'returns User-Agent without Authorization when no token given' {
        $headers = Build-ApiHeader -Token ''
        $headers['User-Agent'] | Should -Match '^RDD-Updater/'
        $headers.ContainsKey('Authorization') | Should -BeFalse
    }
    It 'adds Bearer Authorization header when token given' {
        $headers = Build-ApiHeader -Token 'github_pat_xyz'
        $headers['Authorization'] | Should -Be 'Bearer github_pat_xyz'
    }
}

Describe 'Get-DefaultGateway' {
    It 'returns empty string on platforms without Get-NetRoute' {
        # On non-Windows pwsh hosts (e.g. CI macOS/Linux when run locally),
        # Get-NetRoute is unavailable. The helper must swallow the error
        # and return '' rather than crashing the install flow.
        if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
            Set-ItResult -Skipped -Because 'Get-NetRoute exists on this host; behaviour test is OS-specific.'
            return
        }
        Get-DefaultGateway | Should -Be ''
    }
}

Describe 'Write-RddConfigFile' {
    BeforeEach {
        $script:tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:tmpDir -Force | Out-Null
        $script:cfgPath = Join-Path $script:tmpDir 'config.json'
        $script:dataDir = Join-Path $script:tmpDir 'var'
    }
    AfterEach {
        if (Test-Path $script:tmpDir) { Remove-Item $script:tmpDir -Recurse -Force }
    }

    It 'writes a config with the expected schema fields' {
        Write-RddConfigFile -Path $script:cfgPath -DataDir $script:dataDir `
            -SmtpHost '10.0.0.1' -SmtpPort 25 -SmtpFrom 'a@x' -SmtpTo 'b@y'

        $cfg = Get-Content $script:cfgPath -Raw | ConvertFrom-Json
        $cfg.statePath | Should -Match 'state\.json$'
        $cfg.ouiPath   | Should -Match 'oui\.csv$'
        $cfg.logPath   | Should -Match 'rdd-audit\.csv$'
        $cfg.enrichment    | Should -BeTrue
        $cfg.absentDays    | Should -Be 21
        $cfg.summaryReport | Should -BeFalse
        $cfg.configured    | Should -BeFalse
        $cfg.smtp.host     | Should -Be '10.0.0.1'
        $cfg.smtp.port     | Should -Be 25
        $cfg.smtp.from     | Should -Be 'a@x'
        $cfg.smtp.to       | Should -Be 'b@y'
        $cfg.smtp.useSsl   | Should -BeFalse
    }

    It 'creates the DataDir when it does not exist' {
        (Test-Path $script:dataDir) | Should -BeFalse
        Write-RddConfigFile -Path $script:cfgPath -DataDir $script:dataDir
        (Test-Path $script:dataDir) | Should -BeTrue
    }

    It 'is idempotent: never overwrites an existing config' {
        # First write
        Write-RddConfigFile -Path $script:cfgPath -DataDir $script:dataDir -SmtpHost 'first'
        $original = Get-Content $script:cfgPath -Raw

        # Second write with different params should be a no-op
        Write-RddConfigFile -Path $script:cfgPath -DataDir $script:dataDir -SmtpHost 'second'
        $afterRerun = Get-Content $script:cfgPath -Raw

        $afterRerun | Should -Be $original
    }

    It 'produces parseable JSON' {
        Write-RddConfigFile -Path $script:cfgPath -DataDir $script:dataDir
        { Get-Content $script:cfgPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }
}
