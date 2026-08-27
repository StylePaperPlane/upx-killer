param(
    [Parameter(Mandatory)]
    [int]$AppPid,
    [string]$WinApp = 'winapp'
)

$ErrorActionPreference = 'Stop'
$results = @()
$passed = 0
$failed = 0

function Test-Ui {
    param([string]$Name, [scriptblock]$Action)
    try {
        & $Action | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "winapp exited with $LASTEXITCODE" }
        $script:passed++
        $script:results += @{ name = $Name; status = 'PASS' }
    }
    catch {
        $script:failed++
        $script:results += @{ name = $Name; status = 'FAIL'; detail = "$_" }
    }
}

Test-Ui 'Navigation shell exists' { & $WinApp ui wait-for RootNavigationView -a $AppPid -t 3000 }
Test-Ui 'Overview navigation item exists' { & $WinApp ui wait-for OverviewNavigationItem -a $AppPid -t 3000 }
Test-Ui 'Overview route is loaded' { & $WinApp ui wait-for TargetPathTextBox -a $AppPid -t 3000 }
Test-Ui 'Start is initially disabled' { & $WinApp ui wait-for StartUnpackButton -a $AppPid -p IsEnabled --value False -t 3000 }
Test-Ui 'Export is initially disabled' { & $WinApp ui wait-for ExportFileButton -a $AppPid -p IsEnabled --value False -t 3000 }
Test-Ui 'Status bar is present' { & $WinApp ui wait-for StatusText -a $AppPid -t 3000 }

$inspection = & $WinApp ui inspect -a $AppPid --interactive --json 2>$null | ConvertFrom-Json
$elements = @($inspection.windows | ForEach-Object { $_.elements })
$missing = @($elements | Where-Object {
    $_.type -match 'Button|TextBox|Edit|NavigationViewItem' -and
    $_.name -notmatch 'Minimize|Maximize|Close|System|最小化|最大化|关闭|系统' -and
    -not $_.automationId
})
if ($missing.Count -eq 0) {
    $passed++
    $results += @{ name = 'Interactive controls have AutomationId'; status = 'PASS' }
}
else {
    $failed++
    $results += @{ name = 'Interactive controls have AutomationId'; status = 'FAIL'; detail = ($missing.name -join ', ') }
}

$artifactDirectory = Join-Path $PSScriptRoot '..\artifacts\ui-tests'
New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null
& $WinApp ui screenshot -a $AppPid -o (Join-Path $artifactDirectory 'overview-initial.png') | Out-Null
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $artifactDirectory 'results.json')
Write-Host "Passed: $passed | Failed: $failed"
if ($failed -ne 0) { exit 1 }
