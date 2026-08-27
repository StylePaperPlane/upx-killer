[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [ValidateSet('x64')]
    [string]$Platform = 'x64',
    [string]$Destination = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist')
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sourceDirectory = Join-Path $repositoryRoot "upx-killer\$Platform\$Configuration\upx-killer"
$sourceDirectory = [System.IO.Path]::GetFullPath($sourceDirectory)
$destinationDirectory = [System.IO.Path]::GetFullPath($Destination)
$payloadDirectory = Join-Path $destinationDirectory 'upx-killer'

$repositoryRootFull = [System.IO.Path]::GetFullPath($repositoryRoot).TrimEnd('\')
$destinationTrimmed = $destinationDirectory.TrimEnd('\')
$sourceTrimmed = $sourceDirectory.TrimEnd('\')
if ($destinationTrimmed -eq $repositoryRootFull -or
    [System.IO.Path]::GetPathRoot($destinationDirectory).TrimEnd('\') -eq $destinationTrimmed -or
    $destinationTrimmed -eq $sourceTrimmed -or
    $destinationTrimmed.StartsWith($sourceTrimmed + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
    $sourceTrimmed.StartsWith($destinationTrimmed + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Destination must be a separate child directory, not the repository root or build source: $destinationDirectory"
}

if (-not (Test-Path -LiteralPath $sourceDirectory -PathType Container)) {
    throw "Build output was not found: $sourceDirectory"
}

$requiredFiles = @(
    'upx_killer.exe',
    'upx_killer_engine_host.exe',
    'upx_killer.pri',
    'App.xbf',
    'UI\Pages\Overview\OverviewPage.xbf',
    'UI\Windows\MainWindow\MainWindow.xbf'
)
foreach ($relativePath in $requiredFiles) {
    $requiredPath = Join-Path $sourceDirectory $relativePath
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required runtime file was not found: $requiredPath"
    }
}

if (Test-Path -LiteralPath $destinationDirectory) {
    Remove-Item -LiteralPath $destinationDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $payloadDirectory -Force | Out-Null

$excludedExtensions = @('.pdb', '.ilk', '.lib', '.exp', '.recipe', '.tlog', '.log', '.lastbuildstate')
Get-ChildItem -LiteralPath $sourceDirectory -Recurse -File |
    Where-Object { $excludedExtensions -notcontains $_.Extension.ToLowerInvariant() } |
    ForEach-Object {
        $relativePath = $_.FullName.Substring($sourceDirectory.Length).TrimStart('\')
        $targetPath = Join-Path $payloadDirectory $relativePath
        $targetParent = Split-Path -Parent $targetPath
        New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $targetPath -Force
    }

$runScript = @'
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Argument
)

$ErrorActionPreference = 'Stop'
$distributionDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'upx-killer'))
$applicationPath = Join-Path $distributionDirectory 'upx_killer.exe'

if (-not (Test-Path -LiteralPath $applicationPath -PathType Leaf)) {
    throw "upx_killer.exe was not found in the upx-killer payload directory: $applicationPath"
}

$process = Start-Process -FilePath $applicationPath `
    -WorkingDirectory $distributionDirectory `
    -ArgumentList $Argument `
    -PassThru `
    -Wait
exit $process.ExitCode
'@
Set-Content -LiteralPath (Join-Path $destinationDirectory 'run.ps1') -Value $runScript -Encoding utf8NoBOM

$allowedSatelliteDirectories = @('en-us', 'zh-CN')
$satelliteDirectories = Get-ChildItem -LiteralPath $payloadDirectory -Directory |
    Where-Object { $_.Name -match '^[A-Za-z]{2,3}[-_][A-Za-z0-9]{2,4}$' }
foreach ($directory in $satelliteDirectories) {
    if ($allowedSatelliteDirectories -notcontains $directory.Name) {
        throw "Unsupported language directory in distribution: $($directory.Name)"
    }
}
foreach ($language in $allowedSatelliteDirectories) {
    $languagePath = Join-Path $payloadDirectory $language
    if (-not (Test-Path -LiteralPath $languagePath -PathType Container)) {
        throw "Required language directory was not found: $languagePath"
    }
}

$forbiddenArtifacts = Get-ChildItem -LiteralPath $destinationDirectory -Recurse -File |
    Where-Object { $excludedExtensions -contains $_.Extension.ToLowerInvariant() }
if ($forbiddenArtifacts) {
    throw "Development artifacts remain in distribution: $($forbiddenArtifacts.FullName -join ', ')"
}

Write-Host "Created clean distribution: $destinationDirectory"
Write-Host "Files: $((Get-ChildItem -LiteralPath $destinationDirectory -Recurse -File).Count)"
