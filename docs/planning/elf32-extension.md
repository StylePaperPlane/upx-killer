# ELF32 x86 vertical-slice plan

## Goal

Add Linux ELF32 x86 executable unpacking without changing Coordinator, Host protocol, WinUI support rules, artifact publication, or the existing ELF64 behaviour.

## Implementation status

- The public ELF model now carries neutral `ElfClass` and `ElfMachine` values.
- `ElfParser` dispatches once through the internal `ElfClassTraits` strategy and parses bounded ELF32/I386 and ELF64/x86-64 headers into the same widened model.
- Native `Elf32_*`/`Elf64_*` structures and the internal traits are not exposed to Application, Infrastructure, or UI.
- Linux ptrace register access now crosses one class-neutral `ThreadControlContext` interface. `PTRACE_GETREGSET`/`PTRACE_SETREGSET`, `eip/esp`, and `rip/rsp` remain private to the Linux adapter. The execution-breakpoint module hides software and hardware breakpoint strategies from the capture state machine.
- Linux integration tests now exercise 64-bit and IA32 context round trips plus timeout cleanup, early `SIGSEGV`, forwarded exceptional signals, and clone events. The IA32 fixture is linked directly with `as`/`ld`, so the test does not require a 32-bit libc development package.
- Dynamic metadata analysis and image reconstruction now use the same internal Traits for 32/64-bit dynamic entries, symbols, `REL`/`RELA`, section headers, alignment, and address-width overflow checks. Synthetic ELF32 reconstruction passes the shared Parser and Validator.
- Backend capability selection resolves descriptors from one registered capability table. `ELF + Bits32 + X86 + Executable` is now registered for production.
- Production ELF32 support includes little-endian x86 `ET_EXEC`, dynamically linked PIE, and static PIE. ELF32 shared objects remain recognized but unsupported.
- UPX default and LZMA fixtures, ptrace IA32 context, recovered-entry capture, reconstruction, Loader validation, and the real sectionless `ET_EXEC` sample all pass. PIE acceptance is pinned to UPX 5.2.0 because the available UPX 4.2.4 build emits ELF32 PIE files that fail before the engine runs.

## Existing seams to retain

- `TargetDescriptor` already represents `ELF + Bits32 + X86 + Executable`.
- `UnpackCoordinator` selects capabilities without format-specific branches.
- `ElfUnpackBackend` coordinates preparation, capture, reconstruction, and publication through their existing interfaces.
- `IElfSnapshotCapture` keeps `ptrace` and `/proc` details outside Application and Core.
- WSL discovery, file staging, pipes, and output promotion are independent of ELF class.
- CMake target ownership mirrors the source layers: ELF32 Core sources extend `upx_killer::elf_core`, Application sources extend `upx_killer::elf_application`, and Linux adapters extend `upx_killer::elf_linux`; the Host target only links them.

## Completed vertical slice

1. **Core format strategy**
   - Introduce an internal ELF class strategy selected once by the Parser.
   - Keep addresses in the neutral 64-bit value objects while decoding ELF32 headers, program headers, dynamic entries, symbols, section headers, and relocation records with 32-bit field widths.
   - Do not expose templates or native `Elf32_*` structures across module interfaces.

2. **Parsing and OEP discovery**
   - Accept little-endian `ELFCLASS32`, `EM_386`, executable `ET_EXEC` and `ET_DYN` targets in the production Backend.
   - Parse entryless `ET_DYN` images as SharedObject and reject them through the capability table.
   - Reuse UPX structural evidence and recovered-header validation without weakening ELF64 evidence.

3. **Linux capture adapter**
   - [Implemented] Add an internal compat-thread-context adapter for instruction and stack pointers.
   - Reuse process lifetime, mappings, bounded memory reads, recovered-image location, and execution-breakpoint modules. Read-only shared UPX `memfd` code mappings use a hidden hardware-breakpoint fallback.
   - Exercise IA32 execution through the selected WSL2 distribution before accepting a real job; an unavailable compatibility runtime fails in the Linux Host without weakening other capabilities.

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
   - `ELF + Bits32 + X86 + Executable` is registered after Parser, capture, reconstruction, Loader validation, and behavior tests pass.
   - The existing capability query enables the Overview action; ViewModel and XAML contain no ELF32 support matrix.

## Verification evidence

- UPX 4.2.4 default/LZMA static `ET_EXEC` fixtures produce `Completed`, native code `0`, and Loader-verified artifacts.
- UPX 5.2.0 default/LZMA dynamic and static PIE fixtures produce `Completed`, native code `0`, and Loader-verified artifacts; repaired stdout, stderr, exit code, entry RVA, imports/REL/PLT, and repeated ASLR runs match their source semantics.
- Fixture original, packed, and repaired stdout, stderr, and exit code are identical (`elf32-plan:7`, exit `7`).
- Real sample `D:\Users\31007\Desktop\TXHook.Server\check_input_elf32` with SHA-256 `6FE3FB8EE28727846755288A3AC3EFCF9969E5808F571E00BBF545781C1ADB64` produces `Completed`; original and repaired output `Input key: Wrong!` and exit `1` are identical.
- The repaired real sample is a Loader-verified ELF32/I386 `ET_EXEC` with semantic `.rodata`, `.text`, `.data`, `.bss`, and `.shstrtab` sections.
- Cancellation, timeout, malformed headers, unsupported machine, and missing IA32 runtime tests.
- ELF64 `distorted` continues to produce `Completed`, Loader verification, identical stdout/stderr, and exit `0`.
- Project/Filter audit keeps new files under `Core\ELF\...`, `Infrastructure\Linux\Debugging\Breakpoints`, `Tests\Unit\ELF32`, `Tests\Fixtures\ELF32\PIE`, and `Tests\Integration\ELF32\PIE`.
