# ELF shared-object validation record

## Environment and inputs

- WSL2 distribution: `kali-linux`
- Windows build: `Release|x64`
- Fixture directory:
  `D:\Users\31007\Desktop\TXHook.Server\elf-shared-object-fixtures`
- Test isolation: unique Windows and WSL temporary directories; source
  fixtures are hash-checked and never modified.

| File | SHA-256 |
|---|---|
| `fixture32.so` | `36865B6A17320758827FE2F7399DE7FAE3DE787D491F5AC9A9C9DC56E7382D1B` |
| `fixture32.upx.so` | `EA536DBBB099CDDFF9205D53BC3E4D81C9A185EB91912513D297645A30126391` |
| `fixture64.so` | `E713829979953987F570051099BCA3B05CFEDA40D7F51189BC0B6EBB0E96AE21` |
| `fixture64.upx.so` | `2E5672D5121F7615668CD3485E25A72490480A79020D317D7B9E4C800C9237FF` |

## End-to-end result

Both packed targets complete through the real Windows Engine Host, WSL bridge,
Linux ELF Host, isolated same-class Loader, ELF backend, reconstruction, and
artifact publication path:

| Target | Outcome | Native code | Loader validation | Original / packed / repaired behavior |
|---|---:|---:|---:|---|
| ELF32/I386 shared object | `Completed` | `0` | Passed | loader returns `0` for all three |
| ELF64/x86-64 shared object | `Completed` | `0` | Passed | loader returns `0` for all three |

Each repaired artifact is `ET_DYN`, has entry point zero, retains `DT_SONAME`,
restores `DT_INIT` to `0x1000`, exports `upx_fixture_value`, and contains no
`UPX!` marker. The fixture loaders verify the known export behavior
`upx_fixture_value(5) == 22`.

Command:

```powershell
.\upx-killer-elf-host\Tests\Integration\ELF\SharedObject\Test-ElfSharedObjectUnpacking.ps1 -Distribution kali-linux -Configuration Release
```

The runner rebuilds the Linux targets, runs CTest, invokes the real Host for
both classes, checks behavior and ELF structure, and deletes all temporary
copies on completion.

## Current boundary

These fixtures contain no runtime relocation records, so this acceptance proves
class-neutral loading, layout recovery, dynamic-pointer normalization, exports,
constructor metadata, publication, and isolated load/unload behavior. It does
not by itself prove reversal of arbitrary already-applied `REL`/`RELA` slots in
more complex shared objects. Targets whose recovered layout or dynamic metadata
cannot be validated fail closed rather than being reported as a successful
artifact.
