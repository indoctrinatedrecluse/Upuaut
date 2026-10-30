# Changelog

This project follows [Semantic Versioning](https://semver.org/). Releases use `vMAJOR.MINOR.PATCH` Git tags; this file records user-facing changes.

## [Unreleased]

## [0.5.1] - 2026-10-31

### Fixed

- **Modal visibility and interaction:** Help, About, Documentation, and update dialogs now render in a viewport-safe overlay with guaranteed top clearance and internal scrolling on shorter screens. Removed the header backdrop filter that caused nested fixed dialogs to position relative to the header and clip behind it.
- **Hotfix metadata:** advance app, installer, and workflow fallback versions to `0.5.1`.

### Verification

- Windows Release builds completed with 0 warnings and 0 errors for the desktop app and setup project.
- Self-contained Windows x64 publishes completed for the app and single-file installer; required release media is present.
- Automated suite passed: 55 tests.

## [0.5.0] - 2026-10-31

### Added

- **Crash Forensics workspace:** inspect Windows user-mode minidumps and `.wer` crash reports locally. Extract bounded system, exception, module, thread, and available managed-runtime evidence; explain common Windows exception codes with cautious next checks; identify kernel dumps and hand off deep kernel analysis to WinDbg.
- **Log Lab crash handoff:** open a crash-specific finding in Crash Forensics with the selected log entry carried as context. WER report interpretation reuses Log Lab's parser and the shipped, source-attributed knowledge dataset.
- **Expanded offline Log Lab knowledge:** ship additional Python, Node.js, database, cloud, API, container, Kubernetes, .NET, Windows service/storage, and Java signatures, with deterministic matching, source links, evidence labels, and investigative recommendations.
- **Crash Forensics verification fixture:** add a synthetic WER report and representative signature set for repeatable parser/knowledge coverage.

### Changed

- Add searchable Crash Forensics usage documentation and connect Anpu's Pantheon card to the workspace.
- Advance app, setup, and workflow fallback version metadata to `0.5.0`.
- GitHub release messages now contain only the matching version section from `CHANGELOG.md`.

### Verification

- Windows Release builds completed with 0 warnings and 0 errors for the desktop app and setup project.
- Self-contained Windows x64 publishes completed for the app and single-file installer.
- Automated suite passed: 55 tests, including minidump bounds, WER knowledge reuse, and runtime Log Lab knowledge matching.

## [0.4.0] - 2026-10-30

### Added

- **The Scales cross-source investigations:** combine System/Application events, up to ten imported Log Lab sources, and Scout's current packet buffer in one time-windowed evidence timeline. Imported entries retain source file, line, parsed fields, severity, and message. Timestamped entries can be aligned; untimestamped entries remain available in Log Lab with a clear explanation.
- **Evidence links in The Scales:** show neighboring log entries and nearby frames; rank packet candidates using matching process IDs, endpoint addresses, DNS names, and process names when available. These are explicit match clues and temporal leads, not cause or confidence scores. Named case JSON preserves source evidence and notes; CSV exports the visible links.
- **Broader event review:** optionally include informational and verbose Windows events, and save that choice with the case.
- **Scout interface improvements:** list each active IPv4 address on multi-address adapters, show richer Npcap device descriptions, refresh the adapter list without losing the current selection, and prevent capture from silently falling back to another adapter.
- **Log import tolerance and bounds:** accept predominantly text files with up to 25% unreadable/control/replacement characters while retaining a separate 62% text-like threshold to reject binary-like data. Imports stay capped at 32 MiB, 200,000 structured source lines/entries, 512 fields per entry, and 16 KiB per field value; the original full source remains available when structured processing is line-capped.
- **Installer canvas playback:** bundle the 5.97-second setup loop with local and release builds, keep the poster until playback advances, and report/retry stalled playback.
- Diverse parser fixtures covering INI, logfmt, mixed syslog, access logs, Windows Event XML, crash traces, irregular delimiters, unknown extensions, readable save data, and solution files.

### Changed

- The navigation, Pantheon, documentation, case controls, and investigation language use the established **The Scales** / Ma'at theme instead of the Triage Preview label.
- Standard release metadata advances to `0.4.0`; release tags and setup archives use `v0.4.0` nomenclature.

### Verification

- Windows x64 UI release build completed with no warnings or errors.
- Automated suite passed: 50 tests.

## [0.3.0] - 2026-10-30

### Added

- **Log Lab Phase 1 preview:** new log import and investigation workspace with format detection for plain text, JSON, JSON Lines, XML, and CSV; normalized entry fields and source-line provenance; severity filtering and search; raw-source inspection; and non-destructive JSON/XML pretty formatting. Imports are bounded to 32 MiB and 200,000 entries.
- **Log Lab Phase 2 scenario analysis:** deterministic classification for crash, setup, update, authentication, security, network, storage, service, performance, maintenance, success, and general operational signals. Entry analysis includes readable headlines, searchable tags, matched evidence, suggested investigative checks, and rule-match strength that is explicitly separate from root-cause confidence. Added category summaries and scenario filtering.
- **Log Lab Phase 3 investigation tools:** source-order sequence review for repeated error signatures, nearby warning→error transitions, and error→success signals; saveable Markdown and JSON reports with summaries and bounded notable-entry details; and user-authored JSON regex parser profiles stored per Windows account. Profile pattern length, per-match timeout, total processing time, field count, and profile count are bounded. Applying a profile creates a derived entry view while preserving the original source.
- **Log Lab Phase 4 workflows:** built-in parser profiles for .NET console, Apache error, Nginx 4xx/5xx access, and RFC 3164 syslog logs; side-by-side comparison of linked sequence entries; and report-section controls for summaries, categories, sequences, notable entries, parser notes, and recommendations.
- **Log Lab Phase 5 timeline and saved filters:** UTC timeline buckets with warning/error volume and click-to-filter navigation; combined component and local-time range filters; up to 50 reusable filter presets per Windows account; configurable sequence windows and same-component pivots; and optional timeline trend sections in Markdown/JSON reports.
- **Log Lab raw-source recovery:** unknown and malformed structured formats fall back to source-preserving text entries; binary-like and empty inputs can be inspected in the raw editor, and parser or analysis failures are recorded in application diagnostics.
- **Release nomenclature:** standardize release tags as `vMAJOR.MINOR.PATCH`, with matching version metadata in the app, setup UI, registry entry, archive name, and release title.
- **In-app updates:** check the latest stable GitHub release on startup or from Help → Check for Updates; review release notes, confirm download and installation, then launch the familiar themed setup experience.
- **Installer loop packaging:** require and include the complete six-second installer canvas video in every release setup archive.

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
