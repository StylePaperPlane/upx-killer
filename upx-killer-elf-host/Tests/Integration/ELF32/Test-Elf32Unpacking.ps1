param(
    [string]$Distribution = "kali-linux",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$repository = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$wsl = Join-Path $env:SystemRoot "System32\wsl.exe"
$buildScript = Join-Path $repository "upx-killer-elf-host\Build-ElfHost.ps1"
$testClient = Join-Path $repository "upx-killer-engine-tests\x64\$Configuration\upx-killer-engine-tests.exe"
$sessionName = "upx-killer-elf32-acceptance-$([Guid]::NewGuid().ToString('N'))"
$linuxSession = "/tmp/$sessionName"
$windowsSession = Join-Path ([System.IO.Path]::GetTempPath()) $sessionName
$normalizedRepository = $repository.Replace('\', '/')
$drive = $normalizedRepository.Substring(0, 1).ToLowerInvariant()
$linuxRepository = "/mnt/$drive" + $normalizedRepository.Substring(2)
$verificationScript = "$linuxRepository/upx-killer-elf-host/Tests/Integration/ELF32/VerifyBehavior.sh"

& $buildScript -Distribution $Distribution -Configuration $Configuration -RunTests
if ($LASTEXITCODE -ne 0) { throw "ELF Host tests failed." }
if (-not (Test-Path -LiteralPath $testClient)) {
    throw "Build the native Release|x64 tests before running ELF32 acceptance."
}

New-Item -ItemType Directory -Force -Path $windowsSession | Out-Null
try {
    $prepare = @"
set -euo pipefail
mkdir -p '$linuxSession'
cp /tmp/upx-killer-elf-host-$($Configuration.ToLowerInvariant())/upx_killer_elf_behavior_x86 '$linuxSession/original-exec'
upx -q -o '$linuxSession/packed-exec-default' '$linuxSession/original-exec'
upx -q --lzma -o '$linuxSession/packed-exec-lzma' '$linuxSession/original-exec'
"@
    & $wsl -d $Distribution -- bash -lc $prepare
    if ($LASTEXITCODE -ne 0) { throw "Unable to create UPX ELF32 fixtures." }

    foreach ($variant in @("default", "lzma")) {
        $caseName = "exec-$variant"
        $packedWindows = Join-Path $windowsSession "packed-$caseName"
        $outputWindows = Join-Path $windowsSession "unpacked-$caseName"
        Copy-Item -LiteralPath "\\wsl.localhost\$Distribution\tmp\$sessionName\packed-$caseName" -Destination $packedWindows -Force
        $env:UPX_KILLER_WSL_DISTRIBUTION = $Distribution
        & $testClient --validate-elf-host $packedWindows $outputWindows
        if ($LASTEXITCODE -ne 0) { throw "ELF32 $caseName unpacking failed." }
        Copy-Item -LiteralPath $outputWindows -Destination "\\wsl.localhost\$Distribution\tmp\$sessionName\unpacked-$caseName" -Force
    }

    & $wsl -d $Distribution -- bash $verificationScript $linuxSession
    if ($LASTEXITCODE -ne 0) { throw "ELF32 behaviour comparison failed." }
    Write-Output "ELF32 ET_EXEC default/LZMA acceptance passed."
}
finally {
    & $wsl -d $Distribution -- bash -lc "rm -rf '$linuxSession'" 2>$null
    if (Test-Path -LiteralPath $windowsSession) {
        [System.IO.Directory]::Delete($windowsSession, $true)
    }
}
