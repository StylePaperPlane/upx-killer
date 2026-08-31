# ADR 0006: PE64 DLL vertical slice

## Status

Accepted on 2026-08-31.

## Context

PE64 DLL support combines two existing dimensions: PE64 EXE already supplies
AMD64 parsing, native thread context, 64-bit thunks, TLS, and DIR64 relocation
handling; PE32 DLL already supplies isolated loading, `LOAD_DLL_DEBUG_EVENT`
target identification, exports, dependency directories, and source-ASLR
fidelity. Duplicating either path would make bitness and image-kind behavior
drift.

A DLL entry invocation also has different calling conventions. PE32 passes the
three `DllMain` arguments on the stack, while PE64 passes them in `RCX`, `RDX`,
and `R8`. The debugger must validate `DLL_PROCESS_ATTACH` without embedding
these format details in its event state machine.

## Decision

Build the x86 and x64 DLL Loader executables from one width-neutral source and
select the adjacent executable through `DllLoaderCatalog`. Keep each Loader as
an isolated process so loading an unknown DLL cannot corrupt the Engine Host.
The x86 image stays at `0x00200000`; the x64 image uses the fixed base
`0x100000000`, outside the controlled PE64 snapshot bases and representable
without a 32-bit linker-address truncation.

Expose a format-neutral `DllEntryInvocation` from Thread Context adapters.
PE32 and PE64 decode their own ABI, while `WindowsDebugSession` validates only
the invocation reason. Analyze UPX tail transfers in an OEP-internal module:
PE64 DllMain uses the established direct `E9 rel32` path, and a PE64 no-entry
DLL uses the validated `push 1; pop rax; ret` return tail and resolves OEP RVA
zero.

Reuse the PE64 EXE reconstruction path for Imports/IAT, TLS, DIR64, and image
base policy, and the DLL reconstruction path for Exports, dependencies,
resources, and `IMAGE_FILE_DLL`. Preserve source ASLR intent: a fixed input
does not gain relocations or `DYNAMIC_BASE`.

Register `PE64 + X64 + SharedLibrary` only after the same-bitness Loader,
capture, reconstruction, and loader validation slice is complete. Protocol v6
and the portable target descriptor already express this capability and do not
change.

## Consequences

- PE64 DLL support does not add a parallel debugger or fixer.
- Adding another DLL bitness is a Loader Catalog and format-strategy concern,
  not a coordinator, protocol, or UI branch.
- Both Loader executables are required adjacent release files.
- Unknown production DLLs are loaded and detached in isolation; their exports
  are never called by production verification.
- Automatic OEP discovery remains limited to standard or lightly modified UPX
  direct-jump and validated no-entry return tails.
