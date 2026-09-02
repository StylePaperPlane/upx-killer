# ADR 0005: Format backends and portable engine contracts

## Status

Accepted on 2026-08-30.

## Context

The original PE execution path exposed PE-specific request, result, error, and
progress types to the WinUI application. Its application entry point also read
files, staged debug targets, captured processes, rebuilt imports and
relocations, fixed the image, validated it with the Windows loader, and wrote
the artifact. Adding PE64 DLL or ELF support would have required editing the UI,
protocol, and this single orchestration function.

## Decision

Introduce a portable `upx-killer-contracts` library. It describes target
family, bitness, architecture, image kind, jobs, progress, results, backend
manifests, and the versioned Engine Host protocol without Windows, WinRT, or PE
types.

`UnpackCoordinator` selects exactly one registered `IUnpackBackend`. The Engine
Host currently registers only `PeUnpackBackend`. The PE backend executes four
use cases in order:

1. target preparation;
2. runtime capture;
3. in-memory image reconstruction;
4. artifact publication.

Windows file, debugger, loader, pipe, and validation behavior is supplied by
Infrastructure adapters. The UI queries Host capabilities and does not contain
a PE support matrix. Protocol wire values are explicit and are not serialized
C++ enum ordinals.

PE64 DLL support adds its Loader Catalog entry and backend capability without
changing the coordinator, contracts, protocol, or UI support logic.
Future ELF32/ELF64 executable and shared-object support adds a separate backend;
the intended execution boundary is a WSL2 host rather than Windows debugging
types in the portable contracts.

Engine internals do not define a global error taxonomy. Each deep module owns
the failures it can produce (`DumpError`, `PeFixError`,
`DebugSessionError`, and use-case-specific errors). The PE contract translator
is the only place that maps those local failures into public `JobOutcome`,
`ErrorCategory`, detail code, and native code values. Adding a failure to one
module therefore does not require unrelated Core, Infrastructure, or protocol
interfaces to change.

Runtime capture crosses format boundaries through `CapturedImage`. This model
contains only a numeric load address, image-relative byte offsets, bytes,
memory protections, and warnings. It does not reuse PE RVA/file-offset types or
ELF virtual-address structures. PE and ELF modules must explicitly translate
the neutral address values at their own boundary.

## Consequences

- Backend additions do not require coordinator, UI workflow, or protocol model
  changes when existing descriptors can express the target.
- PE domain models remain private to the PE engine.
- Capture evidence remains reusable without importing a format domain model.
- Module-local failures reduce cross-layer change amplification; contract error
  compatibility remains centralized at the backend boundary.
- Each use case can be tested through a narrow I/O seam.
- The Host remains a single-job isolation boundary and continues to own concrete
  Windows composition.
- Protocol v6 was intentionally incompatible with older clients and hosts.
  ADR 0010 subsequently advances the protocol to v7 so manifests can carry
  exact fixed-address versus position-independent capabilities.
