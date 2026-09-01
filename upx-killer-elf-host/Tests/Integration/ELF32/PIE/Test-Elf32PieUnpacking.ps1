param(
    [string]$Distribution = "kali-linux",
    [string]$Configuration = "Release",
    [string]$UpxPath = ""
)

$ErrorActionPreference = "Stop"
$repository = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..\..")).Path
$wsl = Join-Path $env:SystemRoot "System32\wsl.exe"
$buildScript = Join-Path $repository "upx-killer-elf-host\Build-ElfHost.ps1"
$testClient = Join-Path $repository "upx-killer-engine-tests\x64\$Configuration\upx-killer-engine-tests.exe"
$sessionName = "upx-killer-elf32-pie-$([Guid]::NewGuid().ToString('N'))"
$linuxSession = "/tmp/$sessionName"
$windowsSession = Join-Path ([System.IO.Path]::GetTempPath()) $sessionName
$normalizedRepository = $repository.Replace('\', '/')
$drive = $normalizedRepository.Substring(0, 1).ToLowerInvariant()
$linuxRepository = "/mnt/$drive" + $normalizedRepository.Substring(2)
$verificationScript = "$linuxRepository/upx-killer-elf-host/Tests/Integration/ELF32/PIE/VerifyPieBehavior.sh"

if (-not $UpxPath) {
    $upxCommand = Get-Command upx.exe -ErrorAction Stop
    $UpxPath = $upxCommand.Source
}
$upxVersion = (& $UpxPath --version | Select-Object -First 1)
if ($upxVersion -notmatch '^upx 5\.2\.0\b') {
    throw "ELF32 PIE acceptance requires UPX 5.2.0; found '$upxVersion'."
}

& $buildScript -Distribution $Distribution -Configuration $Configuration -RunTests
if ($LASTEXITCODE -ne 0) { throw "ELF Host tests failed." }
if (-not (Test-Path -LiteralPath $testClient)) {
    throw "Build the native Release|x64 tests before running ELF32 PIE acceptance."
}

New-Item -ItemType Directory -Force -Path $windowsSession | Out-Null
try {
    & $wsl -d $Distribution -- bash -lc "set -euo pipefail; mkdir -p '$linuxSession'"
    if ($LASTEXITCODE -ne 0) { throw "Unable to create the WSL test workspace." }

    $buildDirectory = "/tmp/upx-killer-elf-host-$($Configuration.ToLowerInvariant())"
    foreach ($kind in @("dynamic", "static")) {
        $fixtureName = "upx_killer_elf_${kind}_pie_x86"
        $originalWindows = Join-Path $windowsSession "original-$kind"
        Copy-Item -LiteralPath "\\wsl.localhost\$Distribution$buildDirectory\$fixtureName" -Destination $originalWindows -Force
        foreach ($variant in @("default", "lzma")) {
            $packedWindows = Join-Path $windowsSession "packed-$kind-$variant"
            $arguments = @("-q")
            if ($variant -eq "lzma") { $arguments += "--lzma" }
            $arguments += @("-o", $packedWindows, $originalWindows)
            & $UpxPath @arguments
            if ($LASTEXITCODE -ne 0) { throw "UPX failed for $kind PIE ($variant)." }
        }
    }

    foreach ($file in Get-ChildItem -LiteralPath $windowsSession -File) {
        Copy-Item -LiteralPath $file.FullName -Destination "\\wsl.localhost\$Distribution\tmp\$sessionName\$($file.Name)" -Force
    }
    & $wsl -d $Distribution -- bash $verificationScript $linuxSession packed
    if ($LASTEXITCODE -ne 0) { throw "A packed ELF32 PIE fixture changed behaviour." }

    foreach ($kind in @("dynamic", "static")) {
        foreach ($variant in @("default", "lzma")) {
            $caseName = "$kind-$variant"
            $packedWindows = Join-Path $windowsSession "packed-$caseName"
            $outputWindows = Join-Path $windowsSession "unpacked-$caseName"
            $env:UPX_KILLER_WSL_DISTRIBUTION = $Distribution
            & $testClient --validate-elf-host $packedWindows $outputWindows
            if ($LASTEXITCODE -ne 0) { throw "ELF32 PIE $caseName unpacking failed." }
            Copy-Item -LiteralPath $outputWindows -Destination "\\wsl.localhost\$Distribution\tmp\$sessionName\unpacked-$caseName" -Force
        }
    }

    & $wsl -d $Distribution -- bash $verificationScript $linuxSession all
    if ($LASTEXITCODE -ne 0) { throw "ELF32 PIE repaired-image verification failed." }
    Write-Output "ELF32 dynamic/static PIE default/LZMA acceptance passed with UPX 5.2.0."
}
finally {
    Remove-Item Env:UPX_KILLER_WSL_DISTRIBUTION -ErrorAction SilentlyContinue
    & $wsl -d $Distribution -- bash -lc "rm -rf '$linuxSession'" 2>$null
    if (Test-Path -LiteralPath $windowsSession) {
        [System.IO.Directory]::Delete($windowsSession, $true)
    }
}
