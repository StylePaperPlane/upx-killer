# ELF32 x86 vertical-slice plan

## Goal

Add Linux ELF32 x86 executable unpacking without changing Coordinator, Host protocol, WinUI support rules, artifact publication, or the existing ELF64 behaviour.

## Implementation status

- The public ELF model now carries neutral `ElfClass` and `ElfMachine` values.
- `ElfParser` dispatches once through the internal `ElfClassTraits` strategy and parses bounded ELF32/I386 and ELF64/x86-64 headers into the same widened model.
- Native `Elf32_*`/`Elf64_*` structures and the internal traits are not exposed to Application, Infrastructure, or UI.
- Linux ptrace register access now crosses one class-neutral `ThreadControlContext` interface. `PTRACE_GETREGSET`/`PTRACE_SETREGSET`, `eip/esp`, and `rip/rsp` remain private to the Linux adapter, and software-breakpoint recovery is shared by both classes.
- Linux integration tests now exercise 64-bit and IA32 context round trips plus timeout cleanup, early `SIGSEGV`, forwarded exceptional signals, and clone events. The IA32 fixture is linked directly with `as`/`ld`, so the test does not require a 32-bit libc development package.
- Dynamic metadata analysis and image reconstruction now use the same internal Traits for 32/64-bit dynamic entries, symbols, `REL`/`RELA`, section headers, alignment, and address-width overflow checks. Synthetic ELF32 reconstruction passes the shared Parser and Validator.
- Backend capability selection now resolves descriptors from one registered capability table. ELF32 is representable end to end without a second hard-coded descriptor path, but is not yet registered.
- Production capability remains intentionally restricted to ELF64 until ELF32 OEP discovery, compat thread context, reconstruction, and loader validation all pass.
- The next vertical slice is real UPX x86 capture/loader validation and capability enablement.

## Existing seams to retain

- `TargetDescriptor` already represents `ELF + Bits32 + X86 + Executable`.
- `UnpackCoordinator` selects capabilities without format-specific branches.
- `ElfUnpackBackend` coordinates preparation, capture, reconstruction, and publication through their existing interfaces.
- `IElfSnapshotCapture` keeps `ptrace` and `/proc` details outside Application and Core.
- WSL discovery, file staging, pipes, and output promotion are independent of ELF class.
- CMake target ownership mirrors the source layers: ELF32 Core sources extend `upx_killer::elf_core`, Application sources extend `upx_killer::elf_application`, and Linux adapters extend `upx_killer::elf_linux`; the Host target only links them.

## Required vertical slice

1. **Core format strategy**
   - Introduce an internal ELF class strategy selected once by the Parser.
   - Keep addresses in the neutral 64-bit value objects while decoding ELF32 headers, program headers, dynamic entries, symbols, section headers, and relocation records with 32-bit field widths.
   - Do not expose templates or native `Elf32_*` structures across module interfaces.

2. **Parsing and OEP discovery**
   - Accept only little-endian `ELFCLASS32`, `EM_386`, executable `ET_EXEC`/`ET_DYN` targets.
   - Add UPX x86 structural evidence and recovered-header validation without weakening ELF64 evidence.
   - Reject shared objects until a separate ELF32 shared-object slice exists.

3. **Linux capture adapter**
   - [Implemented] Add an internal compat-thread-context adapter for instruction and stack pointers.
   - Reuse process lifetime, mappings, bounded memory reads, recovered-image location, and software-breakpoint modules.
   - Validate WSL kernel IA32 execution support before advertising the capability.

   Integration tests must cover:
   - timeout while the tracee remains inside the packer stub;
   - target exit or access violation before reaching an OEP candidate;
   - a secondary thread receiving signals while only the initial thread is eligible to resolve OEP;
   - handled and unhandled `SIGSEGV`, `SIGILL`, `SIGTRAP`, and termination signals;
   - deterministic tracee and descendant cleanup after every result.

   Run the current Linux integration suite with:

   ```powershell
   .\upx-killer-elf-host\Build-ElfHost.ps1 -Configuration Release -RunTests
   ```

4. **Dynamic metadata and reconstruction**
   - [Implemented] Decode 8-byte `Elf32_Dyn`, 16-byte `Elf32_Sym`, `REL`/`RELA`, 32-bit section headers, and 4-byte alignment through the selected strategy.
   - [Implemented] Preserve the existing loader-oriented program-header layout and synthesize non-overflowing ELF32 semantic sections.

5. **Capability and UI enablement**
   - Register `ELF + Bits32 + X86 + Executable` only after parser, capture, reconstruction, Loader validation, and real behaviour tests pass.
   - Let the existing capability query enable the Overview action; do not add ELF32 checks to ViewModel or XAML.

## Verification gate

- UPX default/LZMA fixtures for dynamic `ET_EXEC`, PIE, static executable, and static PIE.
- Original/repaired stdout, stderr, and exit code equality.
- `readelf`/Loader validation of headers, entry point, dynamic metadata, symbols, and relocations.
- Cancellation, timeout, malformed headers, unsupported machine, and missing IA32 runtime tests.
- Full regression of ELF64 and all PE capabilities before capability registration.
- Project/Filter audit must keep new files under `Core\ELF\...`, `Infrastructure\Linux\Debugging\ThreadContext`, `Tests\Unit\ELF32`, and `Tests\Integration\ELF32`.
