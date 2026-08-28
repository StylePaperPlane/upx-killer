# ADR 0002: Runtime Import Observation and Rebuild

## Context

Packed images may have no useful static import table after unpacking. The loader has nevertheless resolved the IAT before the OEP breakpoint, so the dump contains authoritative function pointers.

## Decision

At the OEP breakpoint the Infrastructure debugging layer snapshots loaded modules and executable exports. Core scans validated IAT slots, groups contiguous slots by module, and emits an `ImportRebuildPlan` containing only module names, RVAs, and name/ordinal symbols. Forwarded and API-set exports are resolved to a unique loaded provider. The Fixer writes a read-only `.idata` section, clears stale Import/IAT/Delay-Import/Bound-Import directories, and the validator checks the resulting descriptors and thunk arrays.

If imports cannot be uniquely resolved, the Application returns `ImportsNotFound` or `ImportsAmbiguous` and does not create an output file. A genuinely import-free image may produce a `Completed` artifact with an empty plan. A missing plan remains `Partial` only for legacy explicit callers.

## Consequences

The engine does not execute repaired output. Runtime snapshots are platform-neutral at the Core boundary, limits are enforced during remote enumeration and parsing, and protocol callers may still provide an explicit plan.

Because a Memory Dump can contain loader-resolved absolute pointers outside the
source relocation table, runtime Imports alone are not sufficient to make the
Repaired Image relocatable. ADR 0003 therefore requires three controlled-base
snapshots, reconstructs the actual relocation slots, normalizes them to
0x140000000, and publishes a new Base Relocation Directory before an artifact
can be reported as Completed.
