# ELF Shared Object vertical-slice plan

> Implemented by ADR 0011 and the ELF32/ELF64 shared-object validation gate.
> This document is retained as the original design checklist; the accepted
> architecture and verified scope are recorded in those documents.

## Scope

Extend the current ELF executable backend to little-endian x86 and x86-64
shared objects after the ELF32 PIE release gate remains stable.

## Required boundary

Keep the existing dependency direction:

`Coordinator -> ELF Backend -> Preparation/Capture/Reconstruction/Publication -> Linux Adapter`

Shared-object loading must be owned by a separate native Linux Loader process,
parallel to the isolated PE DLL Loader. It must not be added as branches in the
current ELF Host entry point or executable capture state machine.

The Loader receives a staged canonical path and dependency directory, applies a
restricted library-search policy, calls `dlopen`, reports the loaded target
mapping through a bounded binary control channel, and calls `dlclose`. It must
not invoke unknown exported functions. The ELF Host remains the ptrace owner and
identifies the target mapping by canonical path and device/inode identity rather
than by basename.

## Vertical slices

1. Add neutral `SharedLibrary` capability tests without enabling production.
2. Introduce an injected `ElfLoaderCatalog` keyed by ELF class; register no
   loader until its integration fixture passes.
3. Add the independent Linux Loader target and a versioned, bounded loader
   protocol. Keep `dlopen`, link-map, `/proc`, signals, and Linux handles inside
   the Linux adapter.
4. Capture constructor-time unpacking with explicit evidence that the target
   mapping, initial thread, stack state, and recovered entry/return transition
   belong to the staged shared object.
5. Preserve `DT_SONAME`, dynamic symbols, versioning, `REL`/`RELA`, PLT/GOT,
   constructors/destructors, TLS, program headers, and source load semantics.
6. Enable one descriptor only after Parser, capture, reconstruction, Loader
   validation, behavior, cancellation, timeout, crash, dependency, and cleanup
   tests pass for that class.

## Module and build constraints

- Public Contracts continue to expose only `TargetDescriptor` with
  `ImageKind::SharedLibrary` and format-neutral `ImageAddressing`; no `ET_*`,
  `Elf32_*`, `Elf64_*`, `link_map`, or ptrace type crosses a public interface.
- ELF class differences remain behind the existing internal Class/Traits
  strategy.
- The Linux Loader is a separate CMake target linked through target ownership;
  it does not compile Core or Application sources directly.
- New files use responsibility filters such as
  `Infrastructure\Linux\Loading`, `Tests\Fixtures\ELF\SharedObject`, and
  `Tests\Integration\ELF\SharedObject`. No `Utils`, `Common`, or shallow
  forwarding module is introduced.

## Acceptance gate

For both x86 and x86-64 fixtures, default and LZMA UPX variants must load and
unload in isolation, preserve observable constructor behavior, retain exports
and dynamic metadata, and produce Loader-verified artifacts. Missing
dependencies, constructor crashes, timeouts, cancellation, multiple loaded
objects with the same basename, and Loader termination must leave no process or
artifact behind. Existing PE and ELF executable regressions must remain
unchanged before production capability is registered.
