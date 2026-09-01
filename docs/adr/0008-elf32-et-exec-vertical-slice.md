# ADR 0008: ELF32 x86 ET_EXEC as a class-neutral vertical slice

## Status

Accepted.

The production-capability gate described here is superseded by ADR 0009 after
ELF32 PIE behavior and loader acceptance were established.

## Context

The ELF backend already supported ELF64 x86-64 executables through a portable
Coordinator, ELF use cases, and a Linux ptrace adapter. ELF32 support must not
duplicate the backend or expose native `Elf32_*`/`Elf64_*` structures through
Core, Application, protocol, or UI interfaces.

Runtime evidence also showed that recovered-image readiness is not identical to
capture readiness. A static UPX x86 image can expose valid recovered headers
while its writable data is still zero. Conversely, a dynamic PIE may contain
unrelocated dynamic-table addresses before its entry point and load-biased
values after it, so reconstructing only from a late snapshot can lose the disk
representation required by the ELF rebuilder.

## Decision

- Select an internal ELF Class/Traits strategy once in Core. Public ELF models
  use widened, class-neutral values.
- Keep IA32 register layout, `PTRACE_GETREGSET`, and software-breakpoint details
  private to the Linux ThreadContext and Debugging modules.
- Resolve PIE load bias from the recovered ELF-header address and the validated
  offset-zero `PT_LOAD` segment, then prove that every load range is covered.
- Require a confirmed recovered-entry breakpoint for every successful capture.
- For dynamic images, retain the last complete pre-entry dynamic-metadata
  snapshot and return it only after the entry breakpoint is confirmed.
- For static images, capture at the confirmed entry breakpoint so decompressed
  writable data is complete.
- Register only ELF32 x86 `ET_EXEC` in production. Keep ELF32 `ET_DYN` parseable
  but rejected until a behavior-preserving packed PIE fixture exists.

## Consequences

ELF32 and ELF64 share Parser, OEP, reconstruction, protocol, Coordinator, and UI
interfaces. The only class-specific implementation remains behind existing Core
Traits and Linux ThreadContext seams. Future ELF32 PIE work can add validation
evidence without changing those public interfaces.

The capture adapter maintains one optional pre-entry snapshot for dynamic
images. This is intentional evidence ownership, not a second format-specific
capture path. Static and dynamic capture timing is selected by ELF semantics,
not by address width.
