[CmdletBinding()]
param(
    [ValidateSet('Release')]
    [string]$Configuration = 'Release',
    [ValidateSet('x64')]
    [string]$Platform = 'x64',
    [string]$Distribution = 'kali-linux',
    [string]$UpxPath = '',
    [string]$SharedObjectFixtureDirectory =
        'D:\Users\31007\Desktop\TXHook.Server\elf-shared-object-fixtures',
    [string]$WinApp = 'C:\Users\31007\AppData\Local\Microsoft\WindowsApps\winapp.exe',
    [switch]$SkipUi
)

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repository 'upx-killer.slnx'
$releaseDirectory = Join-Path $repository "upx-killer\$Platform\$Configuration\upx-killer"
$application = Join-Path $releaseDirectory 'upx_killer.exe'

function Assert-ExitCode {
    param(
        [Parameter(Mandatory)][string]$Step,
        [Parameter(Mandatory)][int]$ExitCode
    )
    if ($ExitCode -ne 0) {
        throw "$Step failed with exit code $ExitCode."
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Host "`n== $Name =="
    & $Action
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "vswhere.exe was not found: $vswhere"
}
$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
    -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'MSBuild.exe was not found.' }

if (-not $UpxPath) {
    $UpxPath = (Get-Command upx.exe -ErrorAction Stop).Source
}
if (-not $SkipUi -and -not (Test-Path -LiteralPath $WinApp -PathType Leaf)) {
    $WinApp = (Get-Command winapp.exe -ErrorAction Stop).Source
}

Invoke-Step 'Release solution build' {
    & $msbuild $solution /m /restore "/p:Configuration=$Configuration" `
        "/p:Platform=$Platform" /p:TreatWarningsAsErrors=true /nologo /v:minimal
    Assert-ExitCode -Step 'Release solution build' -ExitCode $LASTEXITCODE
}

$nativeTests = Join-Path $repository `
    "upx-killer-engine-tests\$Platform\$Configuration\upx-killer-engine-tests.exe"
Invoke-Step 'Native engine and architecture tests' {
    & $nativeTests
    Assert-ExitCode -Step 'Native engine and architecture tests' `
        -ExitCode $LASTEXITCODE
}

Invoke-Step 'Project and Filter audit' {
    & (Join-Path $PSScriptRoot 'audit-project-filters.ps1')
}

Invoke-Step 'ELF32 PIE CMake, CTest, default and LZMA acceptance' {
    & (Join-Path $repository `
        'upx-killer-elf-host\Tests\Integration\ELF32\PIE\Test-Elf32PieUnpacking.ps1') `
        -Distribution $Distribution -Configuration $Configuration -UpxPath $UpxPath
}

Invoke-Step 'ELF32 and ELF64 shared-object acceptance' {
    & (Join-Path $repository `
        'upx-killer-elf-host\Tests\Integration\ELF\SharedObject\Test-ElfSharedObjectUnpacking.ps1') `
        -Distribution $Distribution -Configuration $Configuration `
        -FixtureDirectory $SharedObjectFixtureDirectory
}

$requiredFiles = @(
    'upx_killer.exe',
    'upx_killer_engine_host.exe',
    'upx_killer_elf_host',
    'upx_killer_elf_so_loader_x86',
    'upx_killer_elf_so_loader_x64',
    'upx_killer_dll_loader_x86.exe',
    'upx_killer_dll_loader_x64.exe'
)
foreach ($file in $requiredFiles) {
    $path = Join-Path $releaseDirectory $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required release file is missing: $path"
    }
}

$sourceLanguages = @(Get-ChildItem -LiteralPath `
        (Join-Path $repository 'upx-killer\Strings') -Directory |
    Select-Object -ExpandProperty Name | Sort-Object)
if (($sourceLanguages -join ',') -cne 'en-US,zh-CN') {
    throw "Unexpected source languages: $($sourceLanguages -join ', ')"
}
$muiLanguages = @(Get-ChildItem -LiteralPath $releaseDirectory -Recurse `
        -File -Filter '*.mui' |
    ForEach-Object { Split-Path $_.DirectoryName -Leaf } | Sort-Object -Unique)
if (($muiLanguages -join ',') -cne 'en-us,zh-CN') {
    throw "Unexpected release MUI languages: $($muiLanguages -join ', ')"
}
$packages = @(Get-ChildItem -LiteralPath $releaseDirectory -Recurse -File |
    Where-Object { $_.Extension -in @('.appx', '.msix', '.msixbundle', '.appxbundle') })
if ($packages.Count -ne 0) {
    throw "Package artifacts were produced: $($packages.FullName -join ', ')"
}

Write-Host "`n== Unpackaged direct launch and WinUI regression =="
$process = Start-Process -FilePath $application -PassThru
try {
    Start-Sleep -Milliseconds 1500
    if ($process.HasExited) {
        throw "The unpackaged application exited early with code $($process.ExitCode)."
    }
    if (-not $SkipUi) {
        & (Join-Path $PSScriptRoot 'ui-tests.ps1') -AppPid $process.Id -WinApp $WinApp
        Assert-ExitCode -Step 'WinUI regression' -ExitCode $LASTEXITCODE
    }
}
finally {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}

Write-Host "`nStabilization regression passed."
Write-Host "Release: $releaseDirectory"
Write-Host "Languages: $($muiLanguages -join ', ')"
Write-Host "WinUI: $(if ($SkipUi) { 'skipped explicitly' } else { 'passed' })"
