param(
    [string]$Distribution = "kali-linux",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$wslExecutable = Join-Path $env:SystemRoot "System32\wsl.exe"
if (-not (Test-Path -LiteralPath $wslExecutable)) {
    $wslExecutable = Join-Path $env:SystemRoot "Sysnative\wsl.exe"
}
if (-not (Test-Path -LiteralPath $wslExecutable)) {
    throw "wsl.exe was not found."
}
$projectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryDirectory = Split-Path -Parent $projectDirectory
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryDirectory "upx-killer\x64\$Configuration\upx-killer"
}
$normalizedProject = $projectDirectory.Replace('\', '/')
$drive = $normalizedProject.Substring(0, 1).ToLowerInvariant()
$linuxProject = "/mnt/$drive" + $normalizedProject.Substring(2)
$buildDirectory = "/tmp/upx-killer-elf-host-$($Configuration.ToLowerInvariant())"
$buildType = if ($Configuration -eq "Release") { "Release" } else { "Debug" }

& $wslExecutable -d $Distribution -- bash -lc "set -euo pipefail; rm -rf '$buildDirectory'; cmake -S '$linuxProject' -B '$buildDirectory' -DCMAKE_BUILD_TYPE=$buildType; cmake --build '$buildDirectory' --parallel"
if ($LASTEXITCODE -ne 0) { throw "ELF Host build failed with exit code $LASTEXITCODE." }

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$source = "\\wsl.localhost\$Distribution$buildDirectory\upx_killer_elf_host"
Copy-Item -LiteralPath $source -Destination (Join-Path $OutputDirectory "upx_killer_elf_host") -Force
