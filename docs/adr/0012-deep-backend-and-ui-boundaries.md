# ADR 0012: Deep backend and UI composition boundaries

## Status

Accepted

## Context

The PE and ELF vertical slices shared stable job contracts, but several internal
boundaries still leaked change across formats and layers:

- ELF preparation, capture, and reconstruction returned the global job result,
  so adding an ELF-only failure required changing a cross-format contract.
- Linux duplicated the stage, validate, promote, and cleanup workflow already
  owned by artifact publication.
- The WinUI navigation catalog carried dependencies for every page in one
  aggregate, so adding a page enlarged the shell's constructor train.
- A blocking Windows pipe read delayed cancellation of a WSL-hosted job.
- Visual Studio Filters and CMake source lists could drift from physical module
  ownership without failing the repository audit.

## Decision

- Each ELF use case owns a small local failure enum and result. Only
  `ElfJobContractTranslator`, at the backend boundary, maps those failures to
  `JobOutcome`, `ErrorCategory`, stable UTF-8 detail codes, and native codes.
- `ArtifactPublicationUseCase` is format-neutral. It owns the complete
  stage/validate/promote/cleanup transaction and communicates only through
  `IArtifactStore`, `IArtifactValidator`, and contract-level artifact metadata.
  Windows PE and Linux ELF implementations remain adapters behind those seams.
- Each WinUI page owns a route factory with only that page's dependencies.
  `MainWindow` receives route registrations and remains unaware of workflows,
  settings stores, engine clients, and file-system adapters.
- Engine-host pipe reads accept a stop token and poll pipe availability in
  bounded intervals, allowing cancellation without exposing Win32 handles to
  Application code.
- The repository audit verifies authored physical directories against Filters
  and verifies that CMake targets explicitly register the sources owned by their
  modules.

## Consequences

- PE- or ELF-specific failures can evolve without expanding a shared engine-wide
  error enum or changing the wire protocol.
- A future format backend can reuse publication semantics without including PE
  or ELF headers and without duplicating cleanup behavior.
- Adding a page adds one route factory and one registration; it does not change
  the window shell or existing ViewModel constructors.
- Cancellation latency for an idle WSL host pipe is bounded by the polling
  interval rather than by the remote process producing a frame.
- Source moves that leave stale Filters or CMake lists fail the normal audit.

The architecture deliberately keeps format translators and page factories as
composition boundaries. They may contain mapping and dependency construction,
but must not acquire domain algorithms or platform workflows.
