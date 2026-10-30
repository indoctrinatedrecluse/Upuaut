# Changelog

This project follows [Semantic Versioning](https://semver.org/). Releases use `vMAJOR.MINOR.PATCH` Git tags; this file records user-facing changes.

## [Unreleased]

### Added

- **Log Lab Phase 1 preview:** new log import and investigation workspace with format detection for plain text, JSON, JSON Lines, XML, and CSV; normalized entry fields and source-line provenance; severity filtering and search; raw-source inspection; and non-destructive JSON/XML pretty formatting. Imports are bounded to 32 MiB and 200,000 entries.

## [0.2.0] - 2026-10-30

This release expands Upuaut from the initial event-log and packet-inspection workspaces into a more complete investigation workflow. The Scales workspace is an early correlation preview; it reports temporal proximity and does not infer causation.

### Added

- **Evidence-grounded explanations:** Chronicles classifies events into readable categories, creates scenario headlines and searchable tags, surfaces the fields used as evidence, and gives event-specific investigation guidance. Rule-match strength is explicitly distinct from root-cause probability.
- **Richer Windows event extraction:** Nested `EventData` and `UserData` XML fields are retained, common provider field names receive normalized aliases, and positional event properties are kept when XML names are absent.
- **Richer packet dissection:** Ethernet mode decodes IPv4, IPv6, VLAN, ARP, TCP, UDP, ICMP, and ICMPv6 fields. Packet interpretations include categories, tags, evidence, and suggested checks; DNS questions and bounded A/AAAA/CNAME answers, selected HTTP metadata, and TLS ClientHello SNI are decoded when the fields are present in a captured segment.
- **Wireshark-inspired Scout workflows:** User-space capture and display filters, saved display filters, packet details and bytes, endpoint conversations, TCP Follow with sequence-gap markers, PCAPNG import/export, and capture health counters.
- **Chronicles investigation tools:** Structured event/provider/time queries, reusable presets, failure clusters, previous-period comparisons, investigation cases, and JSON/CSV report export.
- **Scales correlation preview:** Review recent System/Application warnings and errors alongside buffered Scout packets, filter matched and unmatched events, inspect evidence handoffs, add case notes, and save JSON/CSV output.
- **Shared investigation context:** Chronicles, Scout, and Scales share the selected time range and evidence handoff; `Ctrl+1`, `Ctrl+2`, and `Ctrl+3` navigate among them.
- **Consistent build version display:** The app, documentation, crash reports, installer, and installed-app registry entry use the build's version metadata.

### Changed

- Updated searchable help and documentation to match the current capture modes, protocol decoders, evidence model, and triage-preview limits.
- Improved error feedback for Chronicles queries and live capture controls so expected access or file errors are shown in the workspace.
- Removed the unsafe fixed `chkdsk C:` recommendation for storage events where the affected volume is not known.
- The release workflow validates semantic tag versions and packages a self-contained Windows x64 setup bundle when a `v*` tag is pushed.

### Known limitations

- Upuaut is a Windows x64 desktop app and requires the Microsoft WebView2 Runtime. Native IPv4 raw-socket capture requires elevation; Ethernet capture requires Npcap.
- Native raw-socket mode captures IPv4. Ethernet mode dissects IPv4 and IPv6, but protocol decoding is bounded to fields present in each captured frame. Split DNS, HTTP, or TLS handshakes are not reassembled by the protocol decoders.
- TLS application payloads remain encrypted. HTTP is cleartext; packet bytes may contain sensitive data even when the interpretation summary omits credential headers and URL query strings.
- Process attribution is best effort and depends on matching a packet to a current local TCP/UDP socket.
- Scales correlates by a ±2.5-second time window. Its score is time proximity only, not causal confidence or anomaly probability.
- PCAPNG import is capped at 250,000 frames per load; the live Scout buffer retains up to 15,000 frames.

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

### Known limitations at v0.1.0

- Ethernet mode parses IPv4 and ARP frames; IPv6 dissection and packet export are not included in this release.
- Windows event log access and packet capture visibility depend on account permissions and the selected capture mode.
- The app is a Windows x64 desktop application and requires the Microsoft WebView2 Runtime.
