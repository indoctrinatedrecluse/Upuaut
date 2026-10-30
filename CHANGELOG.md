# Changelog

This project follows [Semantic Versioning](https://semver.org/). Release versions use `vMAJOR.MINOR.PATCH` Git tags; this file records user-facing changes.

## [Unreleased]

### Added

- Scout now dissects IPv6 in Ethernet captures, exposes decoded protocol-layer fields and full frame bytes, groups endpoint conversations, follows TCP byte streams with gap markers, and opens/saves PCAPNG files.
- Scout has separate user-space capture and display filters, saved display filters, shared time-window filtering, and counters for parser rejects, filtered packets, FIFO overwrites, and receive errors.
- Chronicles supports structured Event ID/provider/custom-time queries, reusable query presets, equal-length prior-period comparisons, cluster-signature explanations, saved investigation cases, and JSON/CSV exports.
- Scales reviews the full bounded Scout buffer, groups matched/unmatched events, explains temporal proximity, records investigation notes, and saves/loads JSON cases or CSV summaries.
- Chronicles, Scout, and Scales share the selected time window and evidence handoff. Ctrl+1/2/3 navigate to those workspaces.

### Notes

- Scout capture filters run in user space and do not reduce capture-backend or kernel traffic. TCP Follow can only reconstruct bytes present in the capture, and TLS payloads remain encrypted.
- Scales' proximity percentage measures time distance within the configured window; it is not causal confidence.

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
