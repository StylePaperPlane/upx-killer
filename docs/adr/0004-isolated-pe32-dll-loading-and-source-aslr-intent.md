# ADR 0004: Isolated PE32 DLL loading and source ASLR intent

## Status

Accepted; generalized to PE32 and PE64 by ADR 0006.

## Context

An x64 Engine Host cannot execute a PE32 DLL as a process. A DLL must be mapped by a compatible process, its target `LOAD_DLL_DEBUG_EVENT` must be distinguished from dependency events, and its `DLL_PROCESS_ATTACH` call must be captured without invoking arbitrary exports. Repaired images must also preserve whether the source intended ASLR rather than equating a rebuilt relocation directory with permission to enable it.

## Decision

Use a separate fixed-base Win32 DLL Loader. It receives only the staged DLL path and dependency directory, applies restricted DLL search flags, calls `LoadLibraryExW`, calls `FreeLibrary`, and exits without invoking exports. The Engine Host remains x64 and owns the debug loop and Job; a loading adapter builds the command and matches the target event by the canonical path obtained from `LOAD_DLL_DEBUG_EVENT.hFile`.

The Parser records Image Kind and Source Load Policy. Application policy selects evidence bases independently from the final output base. Fixing receives explicit relocation and ASLR intent: fixed inputs stay fixed, relocatable inputs retain the source `DYNAMIC_BASE` state, and PE32 never gains `HIGH_ENTROPY_VA`.

Export parsing is a Core deep module over an RVA-addressable mapped image. Runtime memory protections are captured by the Dumper and supplied as section-layout evidence rather than read through Win32 APIs by the Fixer.

## Consequences

- DLL loading, event identification, export validation, section inference, and output placement remain independently testable.
- A same-bitness Loader is a required adjacent deployment binary.
- A fixed-base DLL can fail if its source preferred base is unavailable; the engine does not invent relocations.
- Ambiguous executable-and-writable memory is emitted explicitly as `.textw` to preserve behavior instead of pretending it is read-only code.
