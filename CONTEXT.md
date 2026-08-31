# UPX Killer

UPX Killer loads a protected executable as Windows would load it, captures its in-memory image, and produces a repaired image that can be inspected or exported.

## Language

**Target Image**:
The original executable or dynamic library selected for analysis and unpacking.
_Avoid_: Input binary, source EXE

**Image Kind**:
Whether a PE Target Image is an Executable or a Dynamic Library. Image Kind controls the isolated Windows loading strategy; it does not change PE format or machine width.
_Avoid_: File extension, launch mode

**Source Load Policy**:
The Target Image's preferred base, `DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, and validated relocation availability. The Repaired Image preserves this intent instead of enabling ASLR merely because a relocation table can be built.
_Avoid_: Output ASLR preference, fixer defaults

**DLL Loader**:
The isolated same-bitness helper that maps and detaches a PE Dynamic Library without invoking unknown exports. One width-neutral source builds adjacent x86 and x64 Loader processes; the Engine Host selects one through the Loader Catalog and identifies the Target Image from its `LOAD_DLL_DEBUG_EVENT` file handle.
_Avoid_: DLL runner, export harness

**DLL Entry Invocation**:
The format-neutral view of a DLL entry call: module base, reason, and reserved value. Its Windows adapters read PE32 arguments from the stack and PE64 arguments from `RCX`, `RDX`, and `R8`; the debug state machine only consumes the view.
_Avoid_: DllMain stack frame, x64 register check

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

**DLL Return Transfer**:
The validated UPX tail that completes a no-entry Dynamic Library after its decompression work. PE32 and PE64 have format-specific instruction patterns, but both resolve to OEP RVA zero and must satisfy the same initial-thread, process-attach, stack-restoration, and changed-image evidence.
_Avoid_: guessed return, entry point zero shortcut

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

**Export Directory Model**:
The bounded, validated names, ordinals, function RVAs, and forwarders recovered from a mapped Dynamic Library. Non-forwarded targets are also code evidence for semantic section rebuilding.
_Avoid_: Export name list, dumpbin output

**Partial Artifact**:
A Repaired Image whose structural validation passed but whose imports have not been rebuilt.
_Avoid_: Successful unpack, completed image

**Target Descriptor**:
A format-neutral tuple of binary family, bitness, CPU architecture, and image kind used for capability matching. It contains no PE headers, loader handles, or UI types.
_Avoid_: PE support flag, file extension

**Backend Manifest**:
The stable backend identifier and Target Descriptors a backend currently executes in production.
_Avoid_: UI support matrix, parser feature list

**Unpack Job**:
The format-neutral request, progress stream, and result exchanged by the UI, Engine Host, Coordinator, and selected backend.
_Avoid_: PE request, debugger command

**PE Capture Evidence**:
One or more controlled-base PE memory captures, their resolved OEP, runtime import observation, and source relocation evidence. It is the complete input to PE image reconstruction.
_Avoid_: Process state, temporary file

**Artifact Publication**:
The use case that stages a reconstructed image, performs structural and loader validation through an adapter, and atomically promotes the validated artifact.
_Avoid_: Fixer write, direct output stream

Automatic OEP captures are Completed only after Imports, IAT, semantic sections,
and reconstructed relocations all validate. Ambiguous or insufficient evidence
fails before writing an artifact.
