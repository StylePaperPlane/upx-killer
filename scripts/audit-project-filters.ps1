[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$itemTypes = @(
    'ClCompile', 'ClInclude', 'Page', 'Midl', 'Manifest', 'AppxManifest',
    'Text', 'Image', 'PRIResource', 'None', 'Natvis'
)
$failures = [System.Collections.Generic.List[string]]::new()

function Get-ProjectItems {
    param([xml]$Xml)
    $namespace = [System.Xml.XmlNamespaceManager]::new($Xml.NameTable)
    $namespace.AddNamespace('msb', 'http://schemas.microsoft.com/developer/msbuild/2003')
    foreach ($type in $itemTypes) {
        foreach ($node in $Xml.SelectNodes("//msb:$type[@Include]", $namespace)) {
            if ([string]$node.Include -like '$(*') { continue }
            [pscustomobject]@{
                Key = "$type|$($node.Include)"
                Type = $type
                Include = [string]$node.Include
                Filter = if ($node.Filter) { [string]$node.Filter } else { $null }
            }
        }
    }
}

$projects = Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.vcxproj' -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\(x64|Debug|Release|Intermediate|Generated Files|packages|\.vs)\\' }

foreach ($project in $projects) {
    $filterPath = "$($project.FullName).filters"
    if (-not (Test-Path -LiteralPath $filterPath -PathType Leaf)) {
        $failures.Add("Missing filters file: $($project.FullName)")
        continue
    }
    [xml]$projectXml = Get-Content -LiteralPath $project.FullName -Raw
    [xml]$filterXml = Get-Content -LiteralPath $filterPath -Raw
    $projectItems = @(Get-ProjectItems $projectXml)
    $filterItems = @(Get-ProjectItems $filterXml)

    foreach ($group in $projectItems | Group-Object Key) {
        if ($group.Count -ne 1) {
            $failures.Add("Duplicate project item in $($project.Name): $($group.Name)")
        }
        $matches = @($filterItems | Where-Object Key -eq $group.Name)
        if ($matches.Count -ne 1 -or [string]::IsNullOrWhiteSpace($matches[0].Filter)) {
            $failures.Add("Project item needs exactly one Filter in $($project.Name): $($group.Name)")
        }
    }
    foreach ($group in $filterItems | Group-Object Key) {
        if ($group.Count -ne 1 -or -not ($projectItems.Key -contains $group.Name)) {
            $failures.Add("Orphan or duplicate filter item in $($project.Name): $($group.Name)")
        }
    }

    $namespace = [System.Xml.XmlNamespaceManager]::new($filterXml.NameTable)
    $namespace.AddNamespace('msb', 'http://schemas.microsoft.com/developer/msbuild/2003')
    $defined = @($filterXml.SelectNodes('//msb:Filter[@Include]', $namespace) |
        ForEach-Object { [string]$_.Include })
    foreach ($item in $filterItems) {
        if ($defined -notcontains $item.Filter) {
            $failures.Add("Undefined Filter in $($project.Name): $($item.Filter) for $($item.Key)")
        }
    }
    foreach ($filter in $defined) {
        $segments = $filter -split '\\'
        for ($index = 1; $index -lt $segments.Count; $index++) {
            $parent = ($segments[0..($index - 1)] -join '\')
            if ($defined -notcontains $parent) {
                $failures.Add("Missing parent Filter in $($project.Name): $parent (required by $filter)")
            }
        }
        if ($filter -eq 'Generated' -or $filter.StartsWith('Generated\', [StringComparison]::Ordinal)) {
            continue
        }
        $hasItem = $filterItems.Filter -contains $filter
        $hasChild = @($defined | Where-Object { $_.StartsWith("$filter\", [StringComparison]::Ordinal) }).Count -gt 0
        if (-not $hasItem -and -not $hasChild) {
            $failures.Add("Empty leaf Filter in $($project.Name): $filter")
        }
    }
}

if ($failures.Count -ne 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "Project/Filter audit passed for $($projects.Count) projects."
