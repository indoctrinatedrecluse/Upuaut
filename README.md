# Upuaut

Upuaut is a Windows desktop toolkit for investigating Windows event logs, inspecting network packets, and comparing nearby system and network signals. It combines a WPF host with a Blazor Hybrid interface and a dark, Egyptian-inspired visual theme.

## Workspaces

- **Chronicles** queries local Windows event channels and offline `.evtx` files. It supports severity, provider, event ID, time, and text filters; live event streaming; event explanations; failure clusters; period comparisons; and JSON, CSV, Markdown, and investigation-case exports.
- **Scout** captures IPv4 traffic through Windows raw sockets or Ethernet frames through Npcap. Ethernet mode dissects IPv4, IPv6, VLAN, ARP, TCP, UDP, ICMP, and ICMPv6. The inspector provides protocol details, bounded DNS question/answer data, selected HTTP metadata, TLS ClientHello SNI, and captured bytes. Scout also supports display and user-space capture filters, endpoint conversations, TCP Follow, and PCAPNG import/export.
- **Scales** is an early correlation preview. It places recent System/Application warning and error events beside packets already in Scout's buffer when they fall within ±2.5 seconds. The score is time proximity only; it does not establish causation or threat probability. Notes and case data can be saved as JSON or CSV.
- **Log Lab** imports operational, server, installer, diagnostic, and crash logs; extracts structured evidence when possible; provides scenario, sequence, and timeline analysis; and preserves an editable raw-source view when the format is unfamiliar or analysis fails.
- **Crash Forensics** inspects Windows user-mode minidumps and WER reports locally, extracts exception and available managed-runtime evidence, and reuses Log Lab's curated knowledge. Crash findings in Log Lab can be handed to this workspace with the source entry attached. Kernel dumps are identified and referred to WinDbg for deep analysis.
- **Crash Forensics** inspects Windows user-mode minidumps and WER reports locally, extracts exception and available managed-runtime evidence, and reuses Log Lab's curated knowledge. Crash findings in Log Lab can be handed to this workspace with the source entry attached. Kernel dumps are identified and referred to WinDbg for deep analysis.

Log Lab's built-in scenario knowledge is a versioned offline dataset of source-attributed error patterns, representative signatures, evidence labels, uncertainty-aware explanations, and safe investigation steps. The parser loads these patterns directly into its runtime rules, with fixture tests checking real matches; it is extended from primary vendor and project documentation and tested with synthetic examples. Third-party production log corpora are not redistributed. Optional AI features share settings through the AI Services button in the top bar or Help → Configure AI Settings. The API key is encrypted for the current Windows account, and features make provider requests only after the user explicitly asks.

Event and packet explanations expose their category, readable headline, tags, evidence, and suggested checks. These are deterministic rules and investigative guidance, not automated root-cause diagnoses.

## Planned Features

### General-purpose Log Lab

The workspace imports and investigates logs from many sources: application crash reports, installer and uninstaller logs, server logs, maintenance records, diagnostics, and other text or structured log files. The engine recognizes plain text, JSON, JSON Lines, XML, and CSV, extracts common fields on a best-effort basis, and keeps the original source available so uncertain interpretations can be checked. Phase 5 adds timeline navigation, time/component sequence pivots, and saved multi-condition filters.

The workspace currently includes:

- **Phase 1 delivered — parsing and evidence extraction:** detect plain text, JSON, JSON Lines, XML, and CSV; extract timestamps, severity, event/message text, components, processes, error codes, identifiers, and other fields when present; retain source lines and explain the extraction basis. Imports are currently limited to 32 MiB and 200,000 entries.
- **Phase 1 delivered — investigation workbench:** search parsed entries, filter by severity, inspect normalized fields and raw entry text, view the complete original source, and pretty-format JSON/XML in an editable view without changing the imported source.
- **Phase 2 delivered — human-readable analysis:** group findings into scenario categories including crash, installation, update, authentication, security, network, storage, service, performance, maintenance, success, failure, warning, and operational; provide readable headlines, tags, evidence, and suggested checks. Match strength reflects matched text signals, not root-cause confidence.
- **Phase 3 delivered — sequence review and reports:** group repeated error signatures, surface nearby warning→error and error→success sequences, and save compact Markdown or JSON investigation reports with scenario summaries, evidence, and source-line links.
- **Phase 3 delivered — custom parser profiles:** define line-matching and field-extraction regex rules in JSON, validate and save up to 30 profiles per Windows account, then apply one to the original imported log to create a separate derived view. Pattern length, match time, field count, and total application time are bounded.
- **Phase 4 delivered — profile library:** built-in profiles cover Microsoft .NET console logs, Apache error logs, Nginx access errors, and RFC 3164 syslog. They appear alongside saved profiles and can be loaded, edited, applied, or saved as a starting point for a custom parser.
- **Phase 4 delivered — report and sequence workbench:** choose which summary, sequence, notable-entry, parser-note, and suggested-check sections appear in exports; compare two linked events side by side and open either event in the inspector.
- **Phase 5 delivered — timeline and query presets:** browse timestamped events in bounded UTC buckets, click a bucket to filter the entry list, combine text/severity/scenario/component/time criteria, and save or reuse up to 50 named filters per Windows account.
- **Phase 5 delivered — sequence pivots:** choose the time window and optionally constrain warning/error/recovery comparisons to the same parsed component. Reports record the sequence settings and can include the timeline trend table.
- **Raw fallback and recovery:** unfamiliar, malformed, mixed, or binary-like imports remain available in the raw editor when structured parsing cannot confidently proceed. Analysis failures are recorded in Upuaut diagnostics and preserve the original decoded source.
- **Knowledge-base growth:** add source-attributed entries to `src/Upuaut.LogLab/Knowledge/log-knowledge-base.json`. Each entry should include stable signals, a category, conservative explanation, bounded remediation guidance, an authoritative source URL, and a representative example. Keep test fixtures synthetic unless a source dataset's license explicitly permits redistribution.
- **Optional AI review in every analysis workspace:** Chronicles, Scout, Weigher, Crash Forensics, and Log Lab share one provider profile, one AI Services modal, one prompt engine, and one review panel that stays visible before a selection is made. Only the selected unit (one Windows event, one log entry, one packet frame, one correlated event, or one crash artifact) is sent after the user presses **Request AI Review**, and each panel reports the prompt size against its hard ceiling. When no key is saved, the panel and shared profile strip explain how to configure one. The API key is protected with Windows DPAPI for the current account. AI output is advisory and separate from the deterministic findings.
- **Future extensions:** expand the built-in dialect and knowledge libraries and add further time-series metrics and parser-specific pivots.

Parsing, classification, and sequence grouping remain best-effort: unfamiliar or incomplete logs may only support partial extraction, and heuristic labels do not confirm root cause. Profile regexes run with time limits and can stop early on large or expensive inputs; parser profiles remain user-authored rules rather than automatic format discovery.

## Requirements and limitations

- Windows x64 and the Microsoft WebView2 Runtime.
- Native raw-socket packet capture requires running with administrator privileges. Ethernet capture requires a compatible Npcap installation.
- Native raw-socket mode captures IPv4. Ethernet mode supports IPv4 and IPv6 dissection.
- Application decoders operate on fields present in individual captured segments; split DNS/HTTP/TLS messages are not reassembled by those decoders. TCP Follow is a separate byte-stream view. TLS application data remains encrypted.
- HTTP and raw packet data can contain sensitive information. Capture filters run in user space and do not configure kernel/Npcap filtering. Process attribution is best effort and depends on a current local socket match.
- Scales compares timestamps, not causal relationships. Scout imports are limited to 250,000 frames per load, and its live buffer retains up to 15,000 frames.

## Build and run

Install the .NET 10 SDK and the Visual Studio workloads declared in `.vsconfig`, then build the solution:

```powershell
dotnet build Upuaut.sln
```

Run the desktop host:

```powershell
dotnet run --project src/Upuaut.App/Upuaut.App.csproj
```

For a build-and-launch workflow that requests Administrator privileges for Security event-log access and raw-socket capture, use `.\run.ps1`. Pass `-NoElevate` to continue as a standard user, `-Configuration Release` for a Release build, `-NoBuild` to launch an existing build, or `-Wait` to keep the terminal attached.

See the searchable in-app Documentation page for workspace workflows and `installer/README.md` for setup, uninstall, and video asset details.

## Release

Push a semantic version tag in the `vMAJOR.MINOR.PATCH` format, such as `v0.6.1`. The tag must match the `Version` declared in `Directory.Build.props`; the workflow fails before building when they disagree. Running the workflow manually (`workflow_dispatch`) uses that declared version, and every step carries an explicit timeout so a stalled publish or upload cannot leave the run hanging. The `Windows Release` GitHub Actions workflow publishes the self-contained Windows x64 app, bundles it with the themed setup program and required six-second installer loop, and attaches `Upuaut-Setup-win-x64-vVERSION.zip` to the GitHub Release. Release notes contain only that version's section from `CHANGELOG.md`. The app checks the latest stable release at startup and offers download/install after user confirmation; users can also check from Help → Check for Updates. Extract the full ZIP before running `Upuaut.Setup.exe`; the setup program uses its sibling payload folder.

See [CHANGELOG.md](CHANGELOG.md) for release history and [LICENSE](LICENSE) for the MIT license.

## Author

Created by **Abhishek Mitra** (`indoctrinatedrecluse`).

- [GitHub](https://github.com/indoctrinatedrecluse/)
- [Portfolio](https://portfolio-flutter-78bcf.web.app/)
