# Changelog

This project follows [Semantic Versioning](https://semver.org/). Release versions use `vMAJOR.MINOR.PATCH` Git tags; this file records user-facing changes.

## [0.1.0] - 2026-10-30

First public Windows release.

### Added

- Windows Event Log review with channel, time, severity, provider, and text filters; live channel streaming; offline `.evtx` loading; event explanations, clustering, and export.
- The Scout packet capture screen with native IPv4 raw socket capture, optional Ethernet capture through Npcap, packet parsing, process attribution, filtering, and frame inspection.
- An animated Egyptian-inspired launch splash and optional video canvas, with a persistent Canvas Motion switch for slower PCs.
- A themed per-user Windows installer and shared uninstaller. The installer uses the complete six-second background loop, and the uninstaller is available from Windows' installed-apps entry, the Start Menu, or `Uninstall.exe` directly.
- A GitHub Actions release workflow that builds a self-contained Windows x64 package for `v*` tag pushes.
- Application diagnostics, crash reporting, searchable Help → Documentation and Help → About dialogs, and Pantheon pages.
- An accessible Scales / Triage route with a clear, themed work-in-progress status screen.

### Changed

- Hardened capture start/stop cleanup, packet-header validation, endpoint-based process attribution, bounded-buffer clearing, and rolling packet-rate telemetry.
- Added both native IPv4 and Ethernet capture modes. Ethernet mode reports link-layer details and requires Npcap; native raw socket capture requires elevation.
- Scout supports both native IPv4 and Npcap Ethernet capture. Process attribution is best-effort based on matching current local TCP/UDP sockets.
- The Scales / Triage page is accessible but remains a work in progress; correlation and anomaly scoring are not active.

### Known limitations

- Ethernet mode currently parses IPv4 and ARP frames; IPv6 dissection and packet export are not included.
- Windows event log access and packet capture visibility depend on account permissions and the selected capture mode.
- The app is a Windows x64 desktop application and requires the Microsoft WebView2 Runtime.
