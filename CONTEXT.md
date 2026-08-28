# UPX Killer

UPX Killer loads a protected executable as Windows would load it, captures its in-memory image, and produces a repaired image that can be inspected or exported.

## Language

**Target Image**:
The original executable selected for analysis and unpacking.
_Avoid_: Input binary, source EXE

**Loaded Image**:
The Target Image after the operating-system loader has mapped it into a process address space.
_Avoid_: Process file, loaded file

**Memory Dump**:
A bounded capture of the Loaded Image before it is converted back to a disk layout.
_Avoid_: Dump file, raw executable

**Repaired Image**:
A PE disk image reconstructed from a Memory Dump with the headers and available metadata made internally consistent.
_Avoid_: Fixed EXE, output binary

**Original Entry Point (OEP)**:
The relative virtual address at which execution of the unpacked program is expected to begin.
_Avoid_: Entry address, absolute entry point

**Import Rebuild Plan**:
The known modules, imported symbols, and existing thunk locations needed to reconstruct the Repaired Image's imports.
_Avoid_: IAT data, imports list

**Runtime Import Observation**:
A platform-neutral snapshot of loaded module export addresses observed at the OEP breakpoint.
_Avoid_: Remote HANDLE, process export table

**Resolved Import**:
An import symbol whose IAT slot was matched uniquely to an executable runtime export.
_Avoid_: Guessed API, probable import

**Controlled-Base Snapshot**:
A Memory Dump captured after the same supported target reaches the same OEP RVA at one of the engine's exact required image bases.
_Avoid_: Random ASLR dump, rebased output

**Source Relocation Evidence**:
Validated DIR64 slots read from the Target Image's Base Relocation Directory. These slots are used only to prepare controlled-base copies and to exclude unchanged packer-stub residue.
_Avoid_: Reconstructed relocations, guessed pointers

**No Source Relocations Path**:
The UPX-specific controlled-loading path used only when the Target Image has an empty Base Relocation Directory and automatic UPX analysis has produced a valid OEP discovery plan. Transient copies change loader-placement metadata but never synthesize source relocation entries.
_Avoid_: Fake relocation table, fixed-base export

**Relocation Slot**:
A byte-accurate location in the unpacked Loaded Image whose DIR64 value changes by exactly the image-base delta across all three Controlled-Base Snapshots.
_Avoid_: Pointer-looking value, aligned qword guess

**Relocation Rebuild Plan**:
The validated Relocation Slots, their image-relative targets, the normalized preferred base, and the encoded Base Relocation Directory used to build the Repaired Image.
_Avoid_: Source relocation table, address patch list

**Partial Artifact**:
A Repaired Image whose structural validation passed but whose imports have not been rebuilt.
_Avoid_: Successful unpack, completed image

Automatic OEP captures are Completed only after Imports, IAT, semantic sections,
and reconstructed relocations all validate. Ambiguous or insufficient evidence
fails before writing an artifact.
