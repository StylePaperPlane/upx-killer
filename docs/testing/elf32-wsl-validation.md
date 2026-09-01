# ELF32 WSL2 validation record

## Environment

- WSL2 distribution: `kali-linux`
- Packer: UPX 4.2.4
- Production target: little-endian ELF32/I386 `ET_EXEC`
- Windows build: `Release|x64`

## Synthetic acceptance

The repository fixture is assembled and linked with `as --32` and `ld -m
elf_i386`, so no 32-bit libc development package is required. The PowerShell
acceptance runner creates default and LZMA UPX variants in a unique WSL `/tmp`
directory and passes them through the real Windows Engine Host and Linux ELF
Host.

| Variant | Outcome | Native code | Loader validation | Observable behavior |
|---|---:|---:|---:|---|
| UPX default | `Completed` | `0` | Passed | `elf32-plan:7`, exit `7` |
| UPX LZMA | `Completed` | `0` | Passed | `elf32-plan:7`, exit `7` |

Command:

```powershell
.\upx-killer-elf-host\Tests\Integration\ELF32\Test-Elf32Unpacking.ps1 -Distribution kali-linux -Configuration Release
```

## Real-sample acceptance

- Path: `D:\Users\31007\Desktop\TXHook.Server\check_input_elf32`
- SHA-256: `6FE3FB8EE28727846755288A3AC3EFCF9969E5808F571E00BBF545781C1ADB64`
- Input: sectionless, static ELF32/I386 `ET_EXEC`, packed by UPX 4.2.4
- Result: `Completed`, `ErrorCategory::None`, native code `0`, Loader verified
- Repaired entry point: `0x08049000`
- Repaired semantic sections: `.rodata`, `.text`, `.data`, `.bss`, `.shstrtab`
- Behavior without stdin: original and repaired both write `Input key: Wrong!`,
  produce no stderr, and exit with code `1`

The original sample is never modified. Validation copies input and output into a
unique temporary WSL directory and compares stdout, stderr, and exit code.

## Regression

The existing ELF64 real sample `distorted` (SHA-256
`2D5971C61B62D40FA69EA068A0169973532AF793AC5E6DE05F9B0C9D1E515947`)
continues to complete with Loader verification; original and repaired behavior
remain identical with exit code `0`.

## PIE acceptance

- Packer: UPX 5.2.0 for Windows, used only in a unique temporary test directory
- Targets: ELF32/I386 dynamically linked PIE and static PIE
- Variants: default and `--lzma` for each target
- Result for all four: `Completed`, `ErrorCategory::None`, native code `0`, Loader verified
- Dynamic behavior: `elf32-pie-dynamic:13`, exit `13`
- Static behavior: `elf32-pie-static:9`, exit `9`

The runner verifies the packed image before invoking the engine, then compares
original, packed, and repaired stdout, stderr, and exit code byte for byte. The
repaired entry RVA remains unchanged and each artifact runs three additional
times under normal ASLR. Dynamic PIE validation requires `/lib/ld-linux.so.2`,
`libc.so.6`, `.interp`, `.dynamic`, `.dynstr`, `.dynsym`, `.rel.dyn`,
`.rel.plt`, `R_386_RELATIVE`, and `R_386_JUMP_SLOT`. Static PIE validation
requires no interpreter and no `DT_NEEDED`; its minimal self-relocation dynamic
table is preserved rather than fabricated or removed.

Command:

```powershell
.\upx-killer-elf-host\Tests\Integration\ELF32\PIE\Test-Elf32PieUnpacking.ps1 -Distribution kali-linux -Configuration Release -UpxPath C:\Users\31007\scoop\shims\upx.exe
```

The available UPX 4.2.4 build produces ELF32 PIE files that exit `127` before
the engine runs, so those outputs are not accepted as engine evidence. The
engine itself does not reject targets by UPX version.
