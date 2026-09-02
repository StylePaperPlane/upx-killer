param(
    [string]$Distribution = "kali-linux",
    [string]$Configuration = "Release",
    [string]$FixtureDirectory = "D:\Users\31007\Desktop\TXHook.Server\elf-shared-object-fixtures"
)

$ErrorActionPreference = "Stop"
$repository = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..\..")).Path
$buildScript = Join-Path $repository "upx-killer-elf-host\Build-ElfHost.ps1"
$testClient = Join-Path $repository "upx-killer-engine-tests\x64\$Configuration\upx-killer-engine-tests.exe"
$wsl = Join-Path $env:SystemRoot "System32\wsl.exe"
$sessionName = "upx-killer-elf-so-$([Guid]::NewGuid().ToString('N'))"
$windowsSession = Join-Path ([System.IO.Path]::GetTempPath()) $sessionName
$linuxSession = "/tmp/$sessionName"

$expectedHashes = @{
    "fixture32.so" = "36865B6A17320758827FE2F7399DE7FAE3DE787D491F5AC9A9C9DC56E7382D1B"
    "fixture32.upx.so" = "EA536DBBB099CDDFF9205D53BC3E4D81C9A185EB91912513D297645A30126391"
    "fixture64.so" = "E713829979953987F570051099BCA3B05CFEDA40D7F51189BC0B6EBB0E96AE21"
    "fixture64.upx.so" = "2E5672D5121F7615668CD3485E25A72490480A79020D317D7B9E4C800C9237FF"
}

foreach ($entry in $expectedHashes.GetEnumerator()) {
    $path = Join-Path $FixtureDirectory $entry.Key
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing SO fixture: $path" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($actual -ne $entry.Value) { throw "SO fixture hash changed: $($entry.Key)" }
}

& $buildScript -Distribution $Distribution -Configuration $Configuration -RunTests
if ($LASTEXITCODE -ne 0) { throw "ELF Host tests failed." }
if (-not (Test-Path -LiteralPath $testClient)) {
    throw "Build the native Release|x64 tests before running SO acceptance."
}

New-Item -ItemType Directory -Force -Path $windowsSession | Out-Null
try {
    $env:UPX_KILLER_WSL_DISTRIBUTION = $Distribution
    foreach ($bits in @(32, 64)) {
        $packed = Join-Path $FixtureDirectory "fixture$bits.upx.so"
        $output = Join-Path $windowsSession "fixture$bits.repaired.so"
        & $testClient --validate-elf-host $packed $output
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) {
            throw "ELF$bits shared-object unpacking failed."
        }
    }

    & $wsl -d $Distribution -- bash -lc "set -euo pipefail; rm -rf '$linuxSession'; mkdir -p '$linuxSession'"
    if ($LASTEXITCODE -ne 0) { throw "Unable to create WSL SO workspace." }
    foreach ($file in Get-ChildItem -LiteralPath $FixtureDirectory -File) {
        Copy-Item -LiteralPath $file.FullName -Destination "\\wsl.localhost\$Distribution\tmp\$sessionName\$($file.Name)" -Force
    }
    foreach ($file in Get-ChildItem -LiteralPath $windowsSession -File) {
        Copy-Item -LiteralPath $file.FullName -Destination "\\wsl.localhost\$Distribution\tmp\$sessionName\$($file.Name)" -Force
    }
    & $wsl -d $Distribution -- chmod 700 "$linuxSession/loader32" "$linuxSession/loader64"
    if ($LASTEXITCODE -ne 0) { throw "Unable to prepare SO behavior loaders." }

    $verification = @'
set -euo pipefail
root="$1"
for image in fixture64.so fixture64.upx.so fixture64.repaired.so; do
  "$root/loader64" "$root/$image"
done
for image in fixture32.so fixture32.upx.so fixture32.repaired.so; do
  cp "$root/$image" "$root/fixture32.active.so"
  (cd "$root"; cp fixture32.active.so fixture32.so; ./loader32)
done
for bits in 32 64; do
  image="$root/fixture${bits}.repaired.so"
  expected_class=1
  entry_width=4
  if [ "$bits" = 64 ]; then expected_class=2; entry_width=8; fi
  [ "$(od -An -tu1 -j4 -N1 "$image" | tr -d ' ')" = "$expected_class" ]
  [ "$(od -An -tx1 -j16 -N2 "$image" | tr -d ' \n')" = "0300" ]
  [ "$(od -An -tu1 -j24 -N"$entry_width" "$image" | tr -d ' 0\n')" = "" ]
  readelf -d "$image" | grep '(SONAME)' >/dev/null
  readelf -d "$image" | grep '(INIT).*0x1000' >/dev/null
  readelf -Ws "$image" | grep 'upx_fixture_value' >/dev/null
  if grep -a 'UPX!' "$image" >/dev/null; then
    echo "UPX stub marker remains in repaired ELF${bits} SO" >&2
    exit 1
  fi
done
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($verification))
    & $wsl -d $Distribution -- bash -lc "echo '$encoded' | base64 -d | bash -s -- '$linuxSession'"
    if ($LASTEXITCODE -ne 0) { throw "SO behavior or structure verification failed." }
    Write-Output "ELF32/ELF64 shared-object unpacking acceptance passed."
}
finally {
    Remove-Item Env:UPX_KILLER_WSL_DISTRIBUTION -ErrorAction SilentlyContinue
    & $wsl -d $Distribution -- bash -lc "rm -rf '$linuxSession'" 2>$null
    if (Test-Path -LiteralPath $windowsSession) {
        [System.IO.Directory]::Delete($windowsSession, $true)
    }
}
