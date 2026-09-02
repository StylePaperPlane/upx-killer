# ADR 0010: Exact image-addressing capabilities

## Status

Accepted.

## Context

`TargetDescriptor` originally matched only binary family, class, CPU
architecture, and image kind. For ELF this made fixed-address `ET_EXEC` and PIE
look identical to the UI even though a backend may support only one. The Host
could advertise ELF32 x86 Executable, the UI could enable Start, and the
authoritative Probe could reject the more specific image after execution began.

Adding `ET_EXEC` or `ET_DYN` directly to Contracts would couple a portable
capability interface to ELF. Reusing PE ASLR flags would create the inverse
coupling and would not describe the executable loading model consistently.

## Decision

- Add format-neutral `ImageAddressing` to `TargetDescriptor` with
  `PlatformDefault`, `FixedAddress`, and `PositionIndependent` values.
- ELF inspection and the authoritative ELF capability module classify
  `ET_EXEC` as `FixedAddress` and executable `ET_DYN` as
  `PositionIndependent`.
- Advertise fixed-address and position-independent ELF32/ELF64 executables as
  separate manifest entries. The UI keeps exact descriptor equality and gains
  no ELF-specific branch.
- Keep PE capabilities on `PlatformDefault`; PE ASLR intent remains a
  reconstruction policy, not a distinct backend capability.
- Encode the new field with explicit wire values and advance the Engine Host
  protocol to v7. Older clients and hosts fail at protocol negotiation rather
  than decoding a descriptor with the wrong shape.

## Consequences

Inspector, Manifest, Probe, Workflow, and ViewModel now use one capability
vocabulary. A backend can independently open or close fixed-address, PIE, or
future shared-library slices without changing Coordinator or UI logic.

`ImageAddressing` describes how an image is addressed, not whether a particular
load happened at its preferred address. Format-specific loader and relocation
details remain in their Core and Infrastructure modules.

`PtraceElfSnapshotCapture` remains an executable-capture state-machine module in
this change. A future shared-object or multi-thread OEP slice must move evidence
selection into an internal deep module rather than add format and loader
branches to that state machine.
