param(
    [string]$Distribution = "",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$OutputDirectory = "",
    [switch]$RunTests,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $projectDirectory 'Resolve-WslDistribution.ps1')
$wslExecutable = Get-WslExecutable
$Distribution = Resolve-WslDistribution -RequestedName $Distribution
$repositoryDirectory = Split-Path -Parent $projectDirectory
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryDirectory "upx-killer\x64\$Configuration\upx-killer"
}
$normalizedProject = $projectDirectory.Replace('\', '/')
$drive = $normalizedProject.Substring(0, 1).ToLowerInvariant()
$linuxProject = "/mnt/$drive" + $normalizedProject.Substring(2)
$buildDirectory = "/tmp/upx-killer-elf-host-$($Configuration.ToLowerInvariant())"
if ($Clean) {
    & $wslExecutable -d $Distribution -- rm -rf -- $buildDirectory
    if ($LASTEXITCODE -ne 0) { throw "ELF Host clean failed with exit code $LASTEXITCODE." }
    return
}
$buildType = if ($Configuration -eq "Release") { "Release" } else { "Debug" }
$testOption = if ($RunTests) { "ON" } else { "OFF" }

& $wslExecutable -d $Distribution -- bash -lc "set -euo pipefail; rm -rf '$buildDirectory'; cmake -S '$linuxProject' -B '$buildDirectory' -DCMAKE_BUILD_TYPE=$buildType -DUPX_KILLER_BUILD_ELF_TESTS=$testOption; cmake --build '$buildDirectory' --parallel; if [ '$testOption' = 'ON' ]; then ctest --test-dir '$buildDirectory' --output-on-failure; fi"
if ($LASTEXITCODE -ne 0) { throw "ELF Host build failed with exit code $LASTEXITCODE." }

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$source = "\\wsl.localhost\$Distribution$buildDirectory\upx_killer_elf_host"
Copy-Item -LiteralPath $source -Destination (Join-Path $OutputDirectory "upx_killer_elf_host") -Force
foreach ($loader in @("upx_killer_elf_so_loader_x86", "upx_killer_elf_so_loader_x64")) {
    $loaderSource = "\\wsl.localhost\$Distribution$buildDirectory\$loader"
    Copy-Item -LiteralPath $loaderSource -Destination (Join-Path $OutputDirectory $loader) -Force
}
