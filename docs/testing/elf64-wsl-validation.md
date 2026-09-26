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

## Editor configuration for the Linux Host

The Linux Host sources are compiled by GCC inside WSL, so `upx-killer-elf-host` is an NMake project whose only build step is `Build-ElfHost.ps1`. Nothing in the project otherwise tells the Microsoft compiler where those sources or the Linux C library live, which leaves every `#include` in the target unresolved in the editor. The project configures IntelliSense explicitly:

- `NMakeIncludeSearchPath` is prepended to `IncludePath` by `Microsoft.Cpp.DesignTime.targets`, so it carries the repository headers together with `UpxKillerElfHostLinuxArchIncludePath`, which defaults to `<distribution include path>\x86_64-linux-gnu`. That multiarch directory owns the Linux `sys/`, `bits/` and `gnu/` headers and must come before the Microsoft ones, or the Linux types they declare are replaced by the incompatible Microsoft equivalents.
- `UpxKillerElfHostLinuxIncludePath` points at the distribution's own `/usr/include` and is appended after the Microsoft headers. It cannot be prepended: it also holds `stdio.h`, `stdint.h` and the rest, and letting those shadow the Microsoft headers breaks the Microsoft standard library.
- `NMakePreprocessorDefinitions` sets `_GNU_SOURCE` and the Linux target macros, so the C library headers select their 64-bit branches such as `gnu/stubs-64.h`.

Both paths are empty by default, because a WSL distribution is a machine-local dependency; set them through the environment or the NMake property page. Validation used `\\wsl.localhost\Kali\usr\include`. None of this affects the build, which still runs CMake and GCC inside WSL.

Two classes of editor diagnostics remain and are not configuration defects:

- The C library and the Microsoft C runtime disagree about `time_t` and `int64_t`, so a translation unit that sees both reports a redefinition.
- Kali installs several kernel UAPI headers as symlinks into `/usr/lib/linux/uapi`, and Windows cannot follow Linux symlinks across the WSL share, so `asm/...` stays unresolved. Adding `\\wsl.localhost\<distribution>\usr\lib\linux\uapi\x86` to `UpxKillerElfHostLinuxArchIncludePath` recovers those on Kali.