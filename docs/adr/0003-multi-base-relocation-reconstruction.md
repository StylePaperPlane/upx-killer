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

When the source permits controlled-base relocation, the Application captures
three distinct bases. All runs must reach the same resolved OEP RVA.

Targets with a source Base Relocation Directory are staged by PeFileRebaser,
which validates and applies only supported relocation entries. A nonempty
directory does not establish that the unpacked program can move: when the
source sets `IMAGE_FILE_RELOCS_STRIPPED`, the Application stages and captures
it once at its preferred base and emits a fixed-base Repaired Image. This also
handles UPX stub TLS relocations without claiming that the original program
has relocations. When the source directory is completely empty, the dedicated
NoSourceRelocationsImagePreparer path is allowed only after automatic UPX
analysis has produced a valid discovery plan.
Its transient copies change ImageBase and disable the two ASLR placement flags
so Windows uses the required preferred base; it does not create a relocation
section or change section data. The debugger verifies the actual base for every
run.

For relocation-eligible sources, Core accepts a relocation slot only when the
byte-identical location in all three OEP snapshots satisfies value minus
loadedBase equals a constant and the normalized target remains inside the image.
Source packer slots whose location
and target remain unchanged are excluded as stub residue. The Fixer normalizes
accepted slots to 0x140000000, emits a standard page-grouped .reloc, and restores
DYNAMIC_BASE and HIGH_ENTROPY_VA.

The final image must parse, expose valid Imports and IAT, map with
SEC_IMAGE_NO_EXECUTE, and start successfully. A relocatable output must also
round-trip through its new relocation directory at a fourth base. A fixed-base
output instead clears the source packer's relocation directory and retains the
source preferred base. Any missing, ambiguous, inconsistent, or unverifiable
evidence fails without an artifact.

## Consequences

The engine can restore ASLR semantics for relocation-eligible sources without
claiming byte-for-byte identity with the pre-packed executable. The No Source
Relocations path remains UPX-specific and deliberately cannot be selected by an
explicit OEP request or an unsupported packer. Relocation reconstruction uses
three runs; fixed-base output needs only one and never invents relocation slots.
