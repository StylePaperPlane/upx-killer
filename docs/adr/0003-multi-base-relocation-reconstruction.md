# ADR 0003: Reconstruct relocations from three controlled-base snapshots

## Context

An OEP Memory Dump contains absolute image pointers after the packer and Windows
loader have adjusted them for the current load address. Reusing only the Target
Image's relocation table is incomplete because unpacking can overwrite packer
slots and restore additional application slots. Scanning one dump for
pointer-looking values is ambiguous.

Some supported UPX x64 images also have no Base Relocation Directory at all.
Rejecting those images prevents the engine from collecting the runtime evidence
that can reconstruct the real application relocations.

## Decision

The Application captures the same supported x64 PE at exactly
0x140000000, 0x180000000, and 0x1C0000000. All three runs must reach the same
resolved OEP RVA.

Targets with a valid source Base Relocation Directory are staged by
PeFileRebaser, which applies only validated DIR64 entries. When that directory
is completely empty, the dedicated NoSourceRelocationsImagePreparer path is
allowed only after automatic UPX analysis has produced a valid discovery plan.
Its transient copies change ImageBase and disable the two ASLR placement flags
so Windows uses the required preferred base; it does not create a relocation
section or change section data. The debugger verifies the actual base for every
run.

Core accepts a relocation slot only when the byte-identical location in all
three OEP snapshots satisfies value minus loadedBase equals a constant and the
normalized target remains inside the image. Source packer slots whose location
and target remain unchanged are excluded as stub residue. The Fixer normalizes
accepted slots to 0x140000000, emits a standard page-grouped .reloc, and restores
DYNAMIC_BASE and HIGH_ENTROPY_VA.

The final image must parse, expose valid Imports and IAT, round-trip through its
new relocation directory at a fourth base, map with SEC_IMAGE_NO_EXECUTE, and
start successfully. Any missing, ambiguous, inconsistent, or unverifiable
evidence fails without an artifact.

## Consequences

The engine can restore standard ASLR semantics without claiming byte-for-byte
identity with the pre-packed executable. The No Source Relocations path remains
UPX-specific and deliberately cannot be selected by an explicit OEP request or
an unsupported packer. Each unpack operation runs the target three times, so
latency increases in exchange for evidence strong enough to reject pointer-like
false positives.
