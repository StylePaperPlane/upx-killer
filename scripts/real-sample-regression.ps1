[CmdletBinding()]
param(
    [string]$SampleRoot = 'D:\Users\31007\Desktop\TXHook.Server',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$testExecutable = Join-Path $repositoryRoot "upx-killer-engine-tests\x64\$Configuration\upx-killer-engine-tests.exe"
$expected = [ordered]@{
    'Math.exe' = '421814C185D116E57DFC9D76520DD00B4A6FB2FEE9D655DF5704DB29BB03BE26'
    'nizhou.exe' = '126C022D3AD16C018F78262573652E25542F25B6FBA1FE640A5441E04BD068F3'
    'TXHook.exe' = 'FF6F767D7BA0C5EDC7F0816CF7386AD06CECD69FF3AC033E47B6A0103987CCB9'
    'xy_quiz.exe' = 'AF3BA833233A4F1B9BB6CA88C2837CAE7345B309D5D362B3354551E9D0D25EA8'
    'main\Server.dll' = '4200CA27A4D742DC1CDC05442B505D442B2AA632F17E68D9DBD5C9AEA8E289A3'
    'main\zlib.dll' = 'DFEED6848C1CC1F46493960B2C83E0B557BE1793962326E5E3CEAB201CFED96B'
}

function Assert-SampleManifest {
    param([string]$Root)

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Real-sample root was not found: $Root"
    }
    foreach ($entry in $expected.GetEnumerator()) {
        $path = Join-Path $Root $entry.Key
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required real sample was not found: $path"
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($actual -ne $entry.Value) {
            throw "Real-sample hash mismatch for $($entry.Key): expected $($entry.Value), found $actual"
        }
    }
}

function Invoke-HostValidation {
    param([string]$Target)

    $lines = @(& $testExecutable --validate-host $Target 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
    $values = @{}
    foreach ($line in $lines) {
        if ($line -match '^([^=]+)=(.*)$') {
            $values[$matches[1]] = $matches[2]
        }
    }
    if ($exitCode -ne 0 -or
        $values['protocol_succeeded'] -ne '1' -or
        $values['outcome'] -ne '0' -or
        $values['error'] -ne '0' -or
        $values['native_error'] -ne '0' -or
        $values['loader_mappable'] -ne '1' -or
        -not $values.ContainsKey('artifact')) {
        throw "Engine Host validation failed for $Target`n$($lines -join [Environment]::NewLine)"
    }
    $artifact = [System.IO.Path]::GetFullPath($values['artifact'])
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "Engine Host reported a missing artifact: $artifact"
    }
    return $artifact
}

function Invoke-CapturedProcess {
    param(
        [string]$Path,
        [int]$TimeoutMilliseconds,
        [bool]$CaptureOutput
    )

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Path
    $start.WorkingDirectory = Split-Path -Parent $Path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $CaptureOutput
    $start.RedirectStandardError = $CaptureOutput
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "Failed to start process: $Path"
    }
    $stdout = ''
    $stderr = ''
    if ($CaptureOutput) {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
    }
    $completed = $process.WaitForExit($TimeoutMilliseconds)
    if (-not $completed) {
        $process.Kill($true)
        $process.WaitForExit()
    }
    if ($CaptureOutput) {
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
    }
    $exitCode = if ($completed) { [uint32]$process.ExitCode } else { $null }
    $process.Dispose()
    return [pscustomobject]@{
        Completed = $completed
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
    }
}

if (-not (Test-Path -LiteralPath $testExecutable -PathType Leaf)) {
    throw "Native test executable was not found; build $Configuration|x64 first: $testExecutable"
}

Assert-SampleManifest -Root $SampleRoot
$temporaryParent = Join-Path ([System.IO.Path]::GetTempPath()) 'upx-killer-real-samples'
$temporaryRoot = Join-Path $temporaryParent ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
$copyRoot = Join-Path $temporaryRoot 'TXHook.Server'
Copy-Item -LiteralPath $SampleRoot -Destination $copyRoot -Recurse

$artifacts = @{}
try {
    foreach ($relativePath in $expected.Keys) {
        $target = Join-Path $copyRoot $relativePath
        $artifacts[$relativePath] = Invoke-HostValidation -Target $target
        Write-Host "PASS host: $relativePath"
    }

    $mathSource = Invoke-CapturedProcess -Path (Join-Path $copyRoot 'Math.exe') `
        -TimeoutMilliseconds 10000 -CaptureOutput $true
    $mathArtifact = Invoke-CapturedProcess -Path $artifacts['Math.exe'] `
        -TimeoutMilliseconds 10000 -CaptureOutput $true
    if (-not $mathSource.Completed -or -not $mathArtifact.Completed -or
        $mathSource.ExitCode -ne $mathArtifact.ExitCode -or
        $mathSource.Stdout -cne $mathArtifact.Stdout -or
        $mathSource.Stderr -cne $mathArtifact.Stderr) {
        throw 'Math.exe source and repaired process behavior differ'
    }
    Write-Host 'PASS behavior: Math.exe output, error stream, and exit code match'

    $quiz = Invoke-CapturedProcess -Path $artifacts['xy_quiz.exe'] `
        -TimeoutMilliseconds 3000 -CaptureOutput $false
    if ($quiz.Completed -and $quiz.ExitCode -eq 0xC0000005) {
        throw 'xy_quiz.exe repaired process exited with 0xC0000005'
    }
    Write-Host 'PASS behavior: xy_quiz.exe has no 0xC0000005 regression'

    $txHookPath = Join-Path $copyRoot 'TXHook.exe'
    $beforeReplacement = Invoke-CapturedProcess -Path $txHookPath `
        -TimeoutMilliseconds 3000 -CaptureOutput $false
    Copy-Item -LiteralPath $artifacts['main\Server.dll'] `
        -Destination (Join-Path $copyRoot 'main\Server.dll') -Force
    $afterReplacement = Invoke-CapturedProcess -Path $txHookPath `
        -TimeoutMilliseconds 3000 -CaptureOutput $false
    if ((-not $beforeReplacement.Completed -and $afterReplacement.Completed) -or
        ($beforeReplacement.Completed -and $afterReplacement.Completed -and
         $beforeReplacement.ExitCode -ne $afterReplacement.ExitCode)) {
        throw 'TXHook.exe behavior regressed after replacing Server.dll'
    }
    Write-Host 'PASS behavior: Server.dll replacement preserves bounded TXHook.exe behavior'

    Write-Host 'All six real-sample regressions passed.'
} finally {
    foreach ($artifact in $artifacts.Values) {
        Remove-Item -LiteralPath $artifact -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
