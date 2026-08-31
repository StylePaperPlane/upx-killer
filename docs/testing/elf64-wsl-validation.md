# ELF64 WSL2 validation record

## Environment

- Windows Engine Host: `Release|x64`
- WSL distribution: `kali-linux`, WSL2
- Linux Host: CMake `Release`, launched through `WslLaunch`
- Validation date: 2026-08-31

All samples are generated in `/tmp/upx-killer-elf-plan` and are not committed to the repository. Windows-to-WSL jobs use copies under the current user's temporary directory.

## End-to-end matrix

| Packed target | Format | Engine result | Original/dumped stdout | Original/dumped exit | Loader validation |
|---|---|---|---|---|---|
| `packed-exec` | ELF64 x86-64 `ET_EXEC`, dynamic | `Completed`, native code `0` | `elf-plan:7` / identical | `0` / `0` | Passed |
| `packed-pie` | ELF64 x86-64 executable `ET_DYN`, dynamic | `Completed`, native code `0` | `elf-plan:7` / identical | `0` / `0` | Passed |
| `packed-static` | ELF64 x86-64 `ET_EXEC`, static | `Completed`, native code `0` | `elf-static` / identical | `0` / `0` | Passed |
| `packed-static-pie` | ELF64 x86-64 executable `ET_DYN`, static PIE | `Completed`, native code `0` | `elf-static-pie` / identical | `0` / `0` | Passed |

Dynamic outputs expose `.dynamic`, `.dynstr`, `.dynsym`, `.rela.dyn`, and `.rela.plt` when present. All four outputs expose semantic load-region sections, pass isolated Linux loader-acceptance validation, and are then executed separately for stdout and exit-code comparison.

## Commands

The Windows integration entry is:

```powershell
$env:UPX_KILLER_WSL_DISTRIBUTION = 'kali-linux'
upx-killer-engine-tests.exe --validate-elf-host <packed-target> <output>
```

The validation entry sends a normal version-6 `ExecuteJob` request to `upx_killer_engine_host.exe`; it does not invoke the Linux Host directly.

## Real sample acceptance

- Source: `D:\Users\31007\Desktop\TXHook.Server\distorted`
- SHA-256: `2D5971C61B62D40FA69EA068A0169973532AF793AC5E6DE05F9B0C9D1E515947`
- Source format: ELF64 x86-64 PIE, UPX 4.22, no section table
- Result: `Completed`, `ErrorCategory::None`, native code `0`, Loader verification passed
- Behaviour: the original and repaired files both exited with code `0`; stdout and stderr were byte-for-byte identical under the same WSL2 network/PID-isolated execution and 10-second timeout.
- Repaired structure: loader-valid dynamic PIE with 13 section headers, including `.text`, `.rodata`, `.data`, `.dynamic`, `.dynstr`, `.dynsym`, `.rela.dyn`, and `.rela.plt`.

The acceptance run used temporary copies only and did not modify the source sample.
