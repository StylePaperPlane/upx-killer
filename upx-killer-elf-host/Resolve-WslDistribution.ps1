function Get-WslExecutable {
    foreach ($directory in @('System32', 'Sysnative')) {
        $candidate = Join-Path $env:SystemRoot "$directory\wsl.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw 'wsl.exe was not found.'
}

function Resolve-WslDistribution {
    param([string]$RequestedName = '')

    # WSL may print a networking warning on stderr while returning success.
    $ErrorActionPreference = 'Continue'
    $wsl = Get-WslExecutable
    $installed = @(& $wsl --list --quiet 2>$null) |
        ForEach-Object { ($_ -replace [char]0, '').Trim() } |
        Where-Object { $_ -and $_ -notmatch '^docker-desktop(?:-data)?$' }
    if ($LASTEXITCODE -ne 0 -or -not $installed) {
        throw 'No WSL distribution is available for the ELF Host build.'
    }

    if ($RequestedName) {
        $candidates = @($installed | Where-Object { $_ -eq $RequestedName })
        if (-not $candidates) {
            throw "WSL distribution '$RequestedName' is not installed. Available: $($installed -join ', ')."
        }
    } else {
        $candidates = @($installed)
    }

    foreach ($name in $candidates) {
        & $wsl -d $name -- bash -lc 'command -v cmake >/dev/null && command -v cc >/dev/null && command -v c++ >/dev/null' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return $name }
    }
    throw "No selected WSL distribution has bash, CMake, and C/C++ compilers. Checked: $($candidates -join ', ')."
}
