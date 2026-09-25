# ADR 0013: GitHub release catalog and future update bootstrap

## Status

Accepted

## Context

The configuration page needs to display the installed version and check whether
a newer stable release exists. The application is an unpackaged, self-contained
folder deployment containing the WinUI executable, Windows Engine Host, Linux
ELF Host, and architecture-specific loaders. Replacing that folder while the UI
and hosts are running is unsafe, and a normal application process cannot
reliably replace its own executable.

Operating a custom update server now would add authentication, availability,
deployment, monitoring, and data-retention responsibilities without providing a
product capability that GitHub Releases does not already supply.

## Decision

- Use the public GitHub Releases latest-release endpoint as the first
  `IReleaseCatalog` adapter. The Application workflow owns version parsing and
  comparison; the Infrastructure adapter owns HTTPS and JSON details.
- This slice is check-only. It does not download, execute, or replace files and
  does not silently update the application.
- Keep the release catalog seam independent of GitHub. A future staged-rollout
  or enterprise server can replace the adapter without changing the page,
  ViewModel, or version-comparison workflow.
- A future self-update must use a separate, minimal bootstrap executable. The
  bootstrap waits for all upx-killer processes to exit, verifies a signed
  manifest and every payload hash, stages a complete versioned directory,
  switches the active version atomically, starts the new version, and rolls back
  if startup health validation fails.
- Engine and loader updates may be activated after their current processes exit,
  but the WinUI executable itself requires restart. “Hot update” therefore means
  downloading and staging in the background followed by a controlled restart;
  it does not mean modifying loaded binaries in place.
- Update metadata must eventually include release channel, version, minimum
  compatible bootstrap version, protocol version, asset URL, file list, SHA-256
  values, signature, and rollback compatibility. A checksum published beside an
  asset is useful for manual verification but is not a substitute for a trusted
  signature in an automatic updater.

## Consequences

- No custom server, account, telemetry, or background updater is required for
  version checking.
- Network failure is a recoverable presentation state and never affects unpacking.
- Future update delivery has an explicit trust and rollback design before any
  code is allowed to replace executable content.
- A custom server becomes justified only for staged rollout, revocation,
  organization policy, private channels, or update analytics. Those requirements
  do not exist in the current product.
