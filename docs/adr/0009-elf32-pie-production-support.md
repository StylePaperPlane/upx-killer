# ADR 0009: ELF32 PIE through existing class-neutral ELF seams

## Status

Accepted.

## Context

ELF32 `ET_EXEC` already shared Parser, Application use cases, reconstruction,
protocol, Coordinator, and UI interfaces with ELF64. The remaining production
gate rejected ELF32 `ET_DYN` despite the existing Traits, IA32 thread context,
load-bias resolver, and dynamic-metadata reconstruction already supporting it.

UPX 5.2.0 restores PIE code in read-only shared `memfd` mappings. Linux rejects
software-breakpoint writes to those mappings, even while the tracee is stopped.
The recovered OEP must still be observed directly; treating a complete memory
snapshot as an implied hit would weaken the existing evidence contract.

## Decision

- Register ELF32 x86 executable `ET_DYN` through the same format-neutral
  Executable descriptor as ELF32 `ET_EXEC`.
- Parse entryless `ET_DYN` as SharedObject and reject it through Backend
  capabilities rather than treating it as a malformed executable.
- Keep explicit-entry semantics in Preparation: VA for `ET_EXEC`, RVA for PIE.
- Keep dynamic images' complete pre-entry snapshot and return it only after a
  confirmed OEP hit; capture static images at the confirmed OEP.
- Deepen the Linux Breakpoints module into a single execution-breakpoint
  interface. It first uses a byte software breakpoint and internally falls back
  to an x86 debug-register breakpoint when restored code is read-only/shared.
- Pin behavior fixtures to UPX 5.2.0. Do not add a production UPX-version gate.

## Consequences

Coordinator, protocol, WinUI, ELF use-case interfaces, public ELF models, and
Core Traits remain unchanged. ELF32 PIE adds no bitness branch outside the
existing Core and Linux adapter seams.

Dynamic PIE preserves interpreter, dependency, symbol, string, `REL`, and PLT
metadata. Static PIE preserves its source program-header semantics: it gains no
interpreter or dependency. GNU ld's minimal static-PIE dynamic table is source
metadata and is preserved; it is not an engine-generated dependency surface.

The hardware fallback consumes debug register zero only for the initial traced
thread and restores its previous address/control values on the OEP hit. Failure
to install either strategy remains a hard capture failure with no artifact.
