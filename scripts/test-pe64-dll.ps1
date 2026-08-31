[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$fixtureRoot = Join-Path $repositoryRoot "upx-killer-engine-tests\x64\$Configuration\Fixtures\x64"
$testExecutable = Join-Path $repositoryRoot "upx-killer-engine-tests\x64\$Configuration\upx-killer-engine-tests.exe"
$upx = (Get-Command upx.exe -ErrorAction Stop).Source
$version = & $upx --version | Select-Object -First 1
if ($version -notmatch '^upx 5\.2\.0$') {
    throw "UPX 5.2.0 is required for the PE64 DLL acceptance set; found: $version"
}

$required = @(
    'upx_killer_engine_dll_fixture.dll',
    'upx_killer_engine_noentry_dll_fixture.dll',
    'upx_killer_fixture_dependency.dll'
)
foreach ($file in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $fixtureRoot $file) -PathType Leaf)) {
        throw "Fixture was not built: $file"
    }
}
if (-not (Test-Path -LiteralPath $testExecutable -PathType Leaf)) {
    throw "Engine tests were not built: $testExecutable"
}

function Rename-PeSections {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $ntOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    $sectionCount = [BitConverter]::ToUInt16($bytes, $ntOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $ntOffset + 20)
    $sectionTable = $ntOffset + 24 + $optionalSize
    for ($index = 0; $index -lt $sectionCount; $index++) {
        $offset = $sectionTable + ($index * 40)
        if ($offset -lt 0 -or $offset + 8 -gt $bytes.Length) {
            throw 'Invalid PE section table while creating the renamed fixture.'
        }
        for ($byte = 0; $byte -lt 8; $byte++) { $bytes[$offset + $byte] = 0 }
        $name = [Text.Encoding]::ASCII.GetBytes(('S{0:X2}' -f $index))
        [Array]::Copy($name, 0, $bytes, $offset, $name.Length)
    }
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

$workspace = Join-Path ([System.IO.Path]::GetTempPath()) ('upx-killer-pe64-dll-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $fixtureRoot 'upx_killer_engine_dll_fixture.dll') -Destination (Join-Path $workspace 'original-entry.dll')
    Copy-Item -LiteralPath (Join-Path $fixtureRoot 'upx_killer_engine_noentry_dll_fixture.dll') -Destination (Join-Path $workspace 'original-noentry.dll')
    Copy-Item -LiteralPath (Join-Path $fixtureRoot 'upx_killer_fixture_dependency.dll') -Destination $workspace
    foreach ($name in @('entry-default.dll', 'entry-lzma.dll', 'entry-renamed.dll')) {
        Copy-Item -LiteralPath (Join-Path $workspace 'original-entry.dll') -Destination (Join-Path $workspace $name)
    }
    foreach ($name in @('noentry-default.dll', 'noentry-lzma.dll')) {
        Copy-Item -LiteralPath (Join-Path $workspace 'original-noentry.dll') -Destination (Join-Path $workspace $name)
    }

    & $upx --force (Join-Path $workspace 'entry-default.dll')
    if ($LASTEXITCODE -ne 0) { throw 'UPX default PE64 DLL packing failed.' }
    & $upx --force --lzma (Join-Path $workspace 'entry-lzma.dll')
    if ($LASTEXITCODE -ne 0) { throw 'UPX LZMA PE64 DLL packing failed.' }
    & $upx --force (Join-Path $workspace 'entry-renamed.dll')
    if ($LASTEXITCODE -ne 0) { throw 'UPX renamed PE64 DLL packing failed.' }
    Rename-PeSections -Path (Join-Path $workspace 'entry-renamed.dll')
    & $upx --force (Join-Path $workspace 'noentry-default.dll')
    if ($LASTEXITCODE -ne 0) { throw 'UPX default PE64 /NOENTRY packing failed.' }
    & $upx --force --lzma (Join-Path $workspace 'noentry-lzma.dll')
    if ($LASTEXITCODE -ne 0) { throw 'UPX LZMA PE64 /NOENTRY packing failed.' }

    & $testExecutable --validate-pe64-dll-fixtures $workspace
    if ($LASTEXITCODE -ne 0) { throw 'PE64 DLL integration acceptance failed.' }
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}

Write-Host 'PE64 DLL explicit OEP, default, LZMA, renamed-section, and /NOENTRY acceptance passed.'
