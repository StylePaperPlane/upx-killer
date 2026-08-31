# ADR 0007: WSL2-hosted ELF64 backend through the public WSL API

## Status

Accepted

## Context

The application needs to unpack Linux x86-64 UPX executables without putting Linux `ptrace`, `/proc`, ELF loading, or filesystem semantics into the Windows PE engine. Reimplementing a Linux loader on Windows would duplicate kernel behavior and create a wide, fragile platform abstraction. Driving an interactive shell through `wsl.exe` would also mix command quoting and textual output with the versioned engine protocol.

## Decision

- Register ELF support as a separate format backend behind the existing Coordinator and format-neutral job contracts.
- Build a native Linux ELF Host that owns `ptrace`, process lifetime, runtime-memory capture, artifact permissions, and Linux loader validation.
- Dynamically resolve the public `WslLaunch` API in the Windows Engine Host. Launch the adjacent Linux Host with anonymous stdin/stdout pipes and exchange the same bounded protocol frames used by other hosts.
- Use `wsl.exe --list --verbose` only in the settings-side discovery adapter. Runtime execution does not parse shell output or construct a command-line protocol.
- Stage each target, adjacent shared-library dependencies, Linux Host, and result in a unique WSL filesystem directory. The bridge owns cleanup and atomically copies a validated result back to the requested Windows path.
- Keep PE registration independent. Missing WSL, no selected WSL2 distribution, or a missing Linux Host disables only the ELF64 capability.
- Support only little-endian ELF64 x86-64 executables in this slice. Both `ET_EXEC` and executable `ET_DYN` are accepted; shared objects and ELF32 require separate vertical slices.

## Consequences

- Linux-specific complexity stays behind one snapshot-capture and one publication boundary, while Core parsing, OEP analysis, reconstruction, and validation remain portable C++.
- The application can query capabilities without embedding ELF/WSL rules in WinUI.
- A WSL2 distribution must be selected before ELF support is advertised. The packaged Linux Host must remain adjacent to the Windows Engine Host.
- Cross-distribution ABI compatibility of the Linux Host remains a deployment risk; Release validation therefore runs the packaged Host inside the selected distribution.
- Reconstructed images are semantically and loader equivalent, not byte-identical to the original pre-UPX file.
