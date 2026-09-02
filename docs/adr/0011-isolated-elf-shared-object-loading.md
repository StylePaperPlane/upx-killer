# ADR 0011: Isolated ELF shared-object loading and recovery

## Status

Accepted.

## Context

An ELF shared object is not launched like an executable. UPX changes the
shared object's entry and program-header metadata so the loader reaches the
unpacking stub during `dlopen`; after loading, recovered code and data can live
in anonymous or deleted `memfd` mappings rather than in the staged file's
offset-zero mapping. Adding `dlopen` branches to the executable ptrace state
machine would couple two different loading lifecycles and would load untrusted
constructors inside the long-lived ELF Host.

The packed ELF32 and ELF64 acceptance fixtures preserve enough dynamic and
program-header evidence to reconstruct a bounded load layout. Their runtime
dynamic tables contain load-bias-adjusted process addresses that cannot be
written directly to a disk artifact.

## Decision

- Build independent ELF32 and ELF64 shared-object Loader processes from one
  source-level implementation. A class-keyed Loader Catalog is the only
  selection interface used by capture and validation.
- The Loader performs only `dlopen`, a controlled stop, and `dlclose`; it never
  calls unknown exports. The ELF Host remains the ptrace owner and is therefore
  able to terminate the complete job on cancellation, timeout, or failure.
- Route executable and shared-object capture through `ElfSnapshotCaptureRouter`.
  Keep the existing executable state machine free of shared-object loading
  branches.
- Recover the shared-object program-header layout in pure Core code using
  bounded UPX-preserved evidence. Locate the runtime object by its staged
  canonical path and offset-zero mapping, then validate every recovered load
  range before capture.
- Normalize loader-adjusted dynamic pointers and process-local dynamic values
  in pure Core code before reconstruction. Re-emit headers from the recovered
  layout instead of copying the packed runtime header.
- Advertise ELF32/x86 and ELF64/x86-64 `SharedLibrary +
  PositionIndependent` capabilities only after the corresponding Loader and
  end-to-end acceptance pass.

## Consequences

The public Contracts, protocol, Coordinator, UI, and artifact-publication
interfaces gain no ELF-specific types. ELF class details remain behind the
existing internal Traits boundary, while `dlopen`, ptrace state, paths, and
process cleanup remain in Linux Infrastructure.

The current production slice is deliberately narrower than arbitrary ELF
shared-object recovery. It accepts the validated standard/lightly modified UPX
layout represented by the integration fixtures. Unsupported or inconsistent
program headers, missing loaders, incomplete mappings, or malformed dynamic
metadata fail before artifact publication. Exact recovery of section tables,
debug data, and byte-identical original files is outside this decision.
