# 🐺 Upuaut (Wepwawet) — *The Opener of the Ways*

> *"He who scouts the hidden path through the underworld, dispels the obscuring mist, and guides the sovereign through the Duat."*

**Upuaut** is a high-performance Windows systems diagnostics, forensic log parser, crash analyzer, and network wire-sniffing instrument. Built for systems engineers, network administrators, and forensic investigators, Upuaut cuts through operating system obscurity—providing deep, correlated insights into Windows kernel events, structured and unstructured application logs, user-mode minidumps, and real-time network traffic.

It combines a native Windows Presentation Foundation (WPF) desktop host with an in-process Blazor Hybrid interface, rendered with Microsoft Fluent UI and styled with a dark, Egyptian Obsidian and Gold visual theme.

---

## 🏛️ System Architecture: The In-Process Hybrid Stack

Upuaut is engineered from the ground up using an **In-Process Blazor Hybrid** desktop architecture on **.NET 10 LTS**.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                       UPUAUT.EXE                                        │
│                                                                                         │
│  ┌──────────────────────────────────────────────┐ Direct Memory  ┌───────────────────┐  │
│  │          Windows Diagnostic Core Engine      │◄───────────────►│   Blazor Engine   │  │
│  │                                              │ Pointer Access  │                   │  │
│  │  • Windows Event Logs (EventLogReader)       │                 │ • State Store     │  │
│  │  • Driverless Raw Sockets (SIO_RCVALL IPv4)  │                 │ • Virtualizer     │  │
│  │  • Ethernet Frame Sniffing (Npcap / Pcap)    │                 │ • Filter Pipeline │  │
│  │  • Socket-to-PID Mapping (iphlpapi.dll)      │                 │ • Navigation      │  │
│  │  • Minidump & CLR Traversal (ClrMD Runtime)  │                 └─────────┬─────────┘  │
│  │  • Log Lab Deterministic Knowledge Base      │                           │            │
│  │  • Lock-Free Ring Buffers & Zero-Copy Slices │                           │ Direct     │
│  │  • Multi-Thread Crash Traps (Dispatcher/CLR) │                           │ Interop    │
│  │  • DPAPI Hardware-Encrypted Secret Storage   │                           │ (No IPC)   │
│  └──────────────────────────────────────────────┘                 ┌─────────▼─────────┐  │
│                                                                   │  WebView2 Canvas  │  │
│                                                                   │ • Fluent UI v5    │  │
│                                                                   │ • Virtual Grids   │  │
│                                                                   │ • Hex / Raw ASCII │  │
│                                                                   │ • 60 FPS Marquee  │  │
│                                                                   │ • Obsidian & Gold │  │
│                                                                   └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Why the In-Process Model?
- **Zero Serialization / No IPC Overhead:** Unlike Electron or Tauri architectures that marshal heavy packet frames and log records across JSON-RPC or WebSocket bridges, Blazor Hybrid runs in-process on the .NET 10 CLR. The UI and native subsystems share the same heap and virtual address space.
- **Direct Memory Pointer Access:** Captured network byte arrays, `.evtx` records, and raw file streams reside in high-efficiency memory buffers (`ReadOnlyMemory<byte>`, lock-free `Channel<T>`), allowing instant hex-dump inspection and zero-copy byte slicing.
- **Hardware-Accelerated Fluid Rendering:** Microsoft WebView2 utilizes the evergreen Chromium engine backed by Direct3D hardware acceleration for fluid 60–120 FPS virtualized data grids.
- **Native OS Integration:** Win32 APIs, the Windows Eventing infrastructure (`wevtapi.dll`), IP Helper network tables (`iphlpapi.dll`), and Windows Data Protection (`DPAPI`) are called directly via P/Invoke without intermediate daemon processes.

---

## 🛠️ Architectural Stack & Dependencies

| Subsystem | Technology / Package | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Runtime & Language** | **.NET 10 LTS** (C# 13) | `net10.0-windows10.0.19041.0` | Native 64-bit Windows execution with modern language features and unified runtime performance. |
| **Desktop Host** | **WPF (Windows Presentation Foundation)** | .NET 10 WPF | Native application window, system tray, lifecycle traps, and native window-title hieroglyphic ticker. |
| **Hybrid UI Canvas** | **Blazor Hybrid** (`Microsoft.AspNetCore.Components.WebView.Wpf`) | `10.0.120` | In-process Razor component renderer hosting the presentation layer inside Microsoft WebView2. |
| **Design System & UI** | **Microsoft Fluent UI for Blazor** | `5.0.1` | Windows 11 Fluent 2 components, icons, navigation menus, and virtualized data tables. |
| **Event Log Engine** | `System.Diagnostics.EventLog` / `EventLogReader` | `10.0.14` | High-throughput querying of live Windows Event Log channels and offline `.evtx` files via native XPath. |
| **Raw Socket Sniffer** | Native .NET `Socket` (`SocketType.Raw`) | Built-in | Driverless promiscuous IPv4 packet capture via `IOControlCode.ReceiveAll` (`SIO_RCVALL`). |
| **Ethernet Sniffer** | **SharpPcap** & **PacketDotNet** | `6.3.1` / `1.4.8` | Promiscuous Ethernet link-layer packet capture supporting IPv4, IPv6, VLAN, ARP, TCP, UDP, and ICMP via Npcap. |
| **Process Attribution** | Native Win32 **IP Helper** (`iphlpapi.dll`) | Win32 API | Real-time mapping of local TCP and UDP endpoints to active Process IDs (PIDs) and executable names. |
| **Crash & Dump Engine** | **Microsoft.Diagnostics.Runtime (ClrMD)** | `4.2.751201` | Out-of-process inspection of Windows user-mode minidumps (`.dmp`) and managed .NET runtime state. |
| **Markdown Rendering** | **Markdig** | `1.5.1` | Fast, bounded, and sanitized Markdown parser for AI reviews, investigation reports, and release notes. |
| **Secret Protection** | **Windows DPAPI** (`ProtectedData`) | Built-in Win32 | Per-user machine-bound encryption of optional AI provider credentials stored under `%LOCALAPPDATA%\Upuaut`. |
| **Logging & Diagnostics** | `Microsoft.Extensions.Logging.Abstractions` | `10.0.14` | Diagnostic logging bridge, daily rolling JSONL log rotation, and unhandled exception crash dumping. |

---

## ⚡ Workspaces & Current Feature Set

Upuaut organizes its diagnostic and forensic capabilities into specialized, dedicated workspaces:

### 1. 📜 The Duat Chronicles (`Upuaut.Chronicles`) — Windows Event Logs & ETW
- **Channel Ingestion:** Queries live Windows event channels (`System`, `Application`, `Security`, and operational logs like `DNS-Client` or `Diagnostics-Networking`) and streams offline `.evtx` files.
- **Kernel-Level XPath Optimization:** Evaluates structured XPath queries directly inside the Windows Eventing engine (`wevtapi.dll`) for sub-second retrieval across hundreds of thousands of events.
- **The Oracle Explanation Engine:** Deterministic rule engine translating cryptic Windows Event IDs, DCOM permission faults, BugChecks, and 150+ NTSTATUS and HRESULT codes into plain-language diagnoses and recommended investigation checks.
- **Quick-Triage Presets:** 1-click filters for immediate triage:
  - ⚡ **BSOD & BugChecks:** Event 1001 (`WER-SystemErrorReporting`) and Event 41 (`Kernel-Power`).
  - 💥 **Application Crashes:** Event 1000 (`Application Error`) and Event 1026 (`.NET Runtime`).
  - 🌐 **Network & DNS:** Event 1014 (`DNS Client Resolution Timeout`) and NetBT connection drops.
  - 💾 **Disk & Storage:** NTFS file system anomalies, bad blocks (Event 7), and storage controller resets.
  - 🔐 **Security & Logon Failures:** Event 4625 failed logons with interactive/RDP logon types and sub-status codes.
- **Noise Suppression & Clustering:** Built-in benign noise muting (e.g., DCOM 10016, ESENT checkpoints) and failure clustering to aggregate identical repeated errors.
- **Historical Analysis & Export:** Period-over-period comparisons, live streaming with `EventLogWatcher`, and export to JSON, CSV, Markdown, or named investigation cases.
- **Guarded AI Event Review:** On-demand AI review of the selected event's payload, decoded fields, and matched rule evidence.

### 2. 🐺 The Scout (`Upuaut.Scout`) — Network Packet Sniffing & Process Attribution
- **Dual-Engine Packet Capture:**
  - **Driverless Windows Native Raw Sockets:** Binds directly to the host IP using `SocketType.Raw` and `SIO_RCVALL` on IPv4 without third-party drivers (requires administrator elevation).
  - **Ethernet Capture via Npcap:** Promiscuous full link-layer capture supporting Ethernet, IPv4, IPv6, VLAN tags, and ARP frames.
- **Real-Time Process Attribution (PID Mapping):** Queries Windows IP Helper (`iphlpapi.dll`) via `GetExtendedTcpTable` and `GetExtendedUdpTable` to resolve owning Process IDs (PIDs) and process image names for active sockets in real time.
- **Deep Protocol Dissection:**
  - **Transport Layer:** TCP flags (SYN, ACK, FIN, RST, PSH, URG), sequence numbers, ACK numbers, window sizing, UDP, ICMP, and ICMPv6.
  - **Application Metadata:** DNS queries and bounded answers (A, AAAA, CNAME), HTTP methods, request URIs, response codes, credential-stripped headers (Host, Server, Content-Type), and TLS ClientHello Server Name Indication (SNI).
- **Wireshark-Inspired Analysis Workflows:**
  - Multi-tier filtering: protocol filters (TCP, TLS, DNS, UDP, ICMP), dynamic process filter dropdown, user-space capture filters, and saved display filters.
  - Real-time wire throughput gauges, packets/sec rate counters, and active process tallies.
  - Detailed Frame Inspector with 4-tuple socket coordinates, dissected header badges, and synchronized raw Hex Dump / ASCII payload viewer.
  - Endpoint conversation grouping and TCP Stream Follow with sequence-gap detection.
  - Capture file import (PCAPNG up to 250,000 frames) and PCAPNG export.
- **Anomaly Detection:** Out-of-order TCP RST bursts, abnormal connection terminations, and malformed/truncated packet warnings.
- **Guarded AI Frame Review:** On-demand AI review of the selected frame's headers, flags, and sanitized payload.

### 3. ⚖️ The Scales of Ma'at (`Upuaut.Weigher`) — Cross-Source Correlation & Temporal Triage
- **Temporal Alignment Window:** Interleaves Windows System/Application events, up to 10 imported Log Lab log sources, and active Scout packet frames along a synchronized time axis (default ±2.5s window).
- **Evidence Candidate Ranking:** Correlates and ranks packet candidates against log errors using matching process IDs, endpoint IP addresses, DNS domain names, and process names.
- **Multi-Source Evidence Timeline:** Unified chronological view connecting application faults directly to preceding or succeeding network resets, timeouts, and system logs.
- **Case Management & Notes:** Add investigation notes, save investigation cases as structured JSON preserving evidence links, and export visible links to CSV.
- **Guarded AI Correlation Review:** On-demand AI review examining a correlated event together with its nearest log record and matching network frame.

### 4. 🔬 Log Lab (`Upuaut.LogLab`) — Multi-Format General-Purpose Log Ingestion & Knowledge Base
- **Universal Multi-Format Ingestion:** Ingests plain text, JSON, JSON Lines, XML, and CSV files up to 32 MiB and 200,000 entries. Includes high fault tolerance for mixed or noisy text (accepts up to 25% replacement/control characters) while gracefully rejecting raw binary data.
- **Normalized Field Extraction:** Extracts timestamps (normalized to UTC), severity levels, components, process names, thread IDs, error codes, and message bodies while maintaining exact source line provenance.
- **Scenario Classification:** Automatically categorizes entries into scenarios: crash, setup, update, authentication, security, network, storage, service, performance, maintenance, success, failure, and operational.
- **Versioned Offline Knowledge Base:** Shipped with **51+ curated, source-attributed patterns** covering Kubernetes (`CrashLoopBackOff`, `OOMKilled`), systemd (`203/EXEC`), PostgreSQL, MySQL, Redis (`MISCONF`, memory limits), SQLite (`SQLITE_BUSY`), RabbitMQ, Go runtime, .NET exceptions, Python, Node.js, Docker, WHEA hardware faults, and Windows Application Error 1000.
- **Sequence Analysis:** Detects repeated error bursts, warning→error escalations, and error→success recovery patterns. Supports side-by-side comparison of linked sequence entries.
- **Custom & Built-in Parser Profiles:** Author and validate custom JSON regex extraction profiles (up to 30 per Windows account) with strict execution timeouts and bounds. Built-in profile library includes .NET console, Apache error, Nginx access, and RFC 3164 syslog formats.
- **Timeline Trend Navigation:** UTC timeline trend buckets with error/warning density counts and click-to-filter navigation; save up to 50 named multi-criteria filter presets.
- **Non-Destructive Raw Editor:** View the original unaltered source with syntax-aware, non-destructive JSON/XML pretty-printing.
- **Investigation Reports:** Export comprehensive Markdown or JSON reports with configurable summaries, categories, sequence analysis, notable entries, and remediation steps.
- **Guarded AI Log Review:** On-demand AI review of individual parsed entries.

### 5. 🛡️ Crash Forensics (`Upuaut.CrashForensics`) — Minidump & WER Forensic Analyzer
- **Local User-Mode Minidump (`.dmp`) Inspection:** Inspects Windows minidumps locally without transmitting memory dumps across the network.
- **Deep Evidence Extraction via ClrMD:** Traverses native and managed runtime state using Microsoft.Diagnostics.Runtime (ClrMD) to extract:
  - System architecture, OS version, and CPU count.
  - Exception code (e.g., `0xC0000005` Access Violation), exception address, and exception record chains.
  - Faulting module name, version, timestamp, and image base.
  - Active thread count, faulting thread ID, and available native/managed stack call frames.
  - Managed CLR runtime versions and unhandled exception details.
- **Windows Error Reporting (`.wer`) Parser:** Ingests and extracts structured metadata from user-mode WER crash files.
- **Knowledge Base Integration:** Maps crash codes and module faults against the Log Lab knowledge base to provide human-readable root-cause hypotheses and investigation steps.
- **Seamless Log Lab Handoff:** Open a crash finding from Log Lab directly in Crash Forensics with the source log context attached.
- **Kernel Dump Guidance:** Identifies full kernel dumps (`MEMORY.DMP`) and provides guidance for deep debugging via WinDbg.
- **Guarded AI Crash Review:** On-demand AI review of the extracted crash summary and faulting stack frame.

### 6. 𓋹 The Celestial Pantheon & Lore Portal (`Upuaut.UI/Pages/Pantheon.razor`)
- **Sacred Mythological Mappings:** Explores the 8 ancient Egyptian guardian deities dedicated to Upuaut's subsystems:
  - 🐺 **Upuaut (Wepwawet):** *Opener of the Ways* → The Scout (Wire Sniffer & Network Vanguard).
  - 📜 **Thoth (Djehuty):** *Lord of the Sacred Scribes* → The Duat Chronicles (Event Log Ingestion & Querying).
  - ⚖️ **Ma'at:** *The Feather of Truth* → The Scales (System Anomaly Triage & Cross-Source Correlation).
  - ☥ **Osiris (Asar):** *Lord of the Fallen Vessel* → Crash Forensics (Minidump & WER Artifact Triage).
  - 🛡️ **Anpu (Anubis):** *Guardian of the Threshold* → Crash Reporter & Persistent Telemetry Vault.
  - 📐 **Seshat:** *Mistress of Builders & Archives* → Log Lab & Custom Parser Workbench.
  - 💧 **Kebechet (Qebhet):** *The Celestial Purifier* → Noise Suppression & DCOM Filtering.
  - ⚡ **Seker (Sokar):** *Restorer of the Broken* → Forensic Remediation & Recommended Investigation Checks.
- **Animated Hieroglyphic Title Bar:** Continuous hardware-accelerated stream of the 25 Gardiner uniliteral signs, guardian names, and sacred symbols running across both the in-app header and the native Windows window title.

### 7. 🤖 Shared Guarded AI Review & Services Subsystem
- **Provider-Neutral Profile:** Supports DeepSeek, Google Gemini, OpenAI-compatible APIs, and local offline models (Ollama, LM Studio).
- **Strict Privacy & DPAPI Encryption:** API keys are encrypted with Windows DPAPI for the current Windows account and stored under `%LOCALAPPDATA%\Upuaut\Settings`. Keys are never logged or exposed.
- **Guarded, Bounded Submissions:** Every review is manual and button-triggered. Only a single selected unit (one event, one frame, one log line, one correlation, or one crash record) is sent—never the surrounding buffer or full dump. Submissions enforce a strict 12,000-character budget with visible compaction notes and a local 2,000,000-character refusal ceiling.
- **Tolerant AI Response Parser:** Handles chat completions, content parts, reasoning/thinking blocks, Gemini candidate structures, Server-Sent Events, and code fences.
- **Safe Markdown Rendering:** AI responses are rendered using Markdig with strict HTML sanitization, formatted tables, code syntax highlighting, and safe URL schemes.

### 8. 🔍 Enterprise Diagnostics, Telemetry & Updates
- **Diagnostics Drawer:** Real-time sliding drawer tracking managed memory footprint, process uptime, elevation status, and an in-memory ring buffer of the last 250 breadcrumbs.
- **Daily Rolling JSONL Logs:** Structured diagnostic telemetry saved under `%LOCALAPPDATA%\Upuaut\Logs\upuaut-YYYY-MM-DD.jsonl`.
- **Multi-Layered Crash Reporter:** Automatic post-mortem crash dumps saved under `%LOCALAPPDATA%\Upuaut\Crashes` with system specs, inner exception stacks, and breadcrumb histories.
- **In-App Auto-Updates:** Checks stable releases on GitHub at startup or via Help → Check for Updates, displays formatted release notes, and launches the installer.

---

## 📋 Requirements and Limitations

- **Operating System:** Windows 10 (version 19041+) or Windows 11 x64.
- **Runtimes:** .NET 10 Runtime and the Evergreen Microsoft WebView2 Runtime.
- **Privileges:**
  - Standard user privileges support offline `.evtx` viewing, Log Lab log analysis, Crash Forensics minidump inspection, PCAPNG offline viewing, and application diagnostics.
  - Administrator elevation is required for reading the Windows `Security` event log and running driverless native raw-socket packet capture (`SIO_RCVALL`).
- **Network Capture Modes:**
  - Native raw-socket mode captures IPv4 traffic without external drivers.
  - Promiscuous Ethernet capture (including IPv6, ARP, and VLAN tags) requires a compatible Npcap installation.
- **Protocol Decoding Bounds:** Application protocol decoders operate on fields present within individual captured frames; fragmented/split messages across multiple TCP segments are not reassembled by the protocol decoders (use the TCP Follow stream viewer for reassembled byte streams). TLS application traffic remains encrypted.
- **Buffer Capacities:** The live packet capture buffer retains up to 15,000 frames; PCAPNG imports support up to 250,000 frames per file. Log Lab imports are capped at 32 MiB and 200,000 entries.

---

## 🔨 Build and Run

### Prerequisites
- [.NET 10 SDK](https://dotnet.microsoft.com/)
- Visual Studio 2026 Enterprise Edition or Visual Studio 2022 (v17.10+) with the workloads specified in `.vsconfig` (Managed Desktop, WPF Prerequisites, .NET SDK).

### Build Solution
```powershell
dotnet build Upuaut.sln
```
*(Alternatively, open `Upuaut.slnx` or `Upuaut.sln` directly in Visual Studio).*

### Run Application
Launch the desktop host directly:
```powershell
dotnet run --project src/Upuaut.App/Upuaut.App.csproj
```

### Automation Script (`run.ps1`)
Use the repository bootstrapper script to compile and launch Upuaut. By default, `run.ps1` prompts for UAC elevation to unlock raw socket packet sniffing and Security log inspection:

```powershell
# Default launch with UAC elevation prompt
.\run.ps1

# Run as standard user without elevation prompt
.\run.ps1 -NoElevate

# Compile and run Release build
.\run.ps1 -Configuration Release

# Clean solution before compiling
.\run.ps1 -Clean

# Keep terminal attached to the host process
.\run.ps1 -Wait
```

### Run Automated Tests
Execute the comprehensive xUnit test suite (covering protocol decoders, forensic rules, surrogate pair validation, and AI response parsing):
```powershell
dotnet test Upuaut.sln
```

---

## 📦 Packaging & Release

Releases follow [Semantic Versioning](https://semver.org/) and match the `Version` declared in `Directory.Build.props`:
1. Push a tag in the format `vMAJOR.MINOR.PATCH` (e.g. `v0.7.0`).
2. The `Windows Release` GitHub Actions workflow compiles the self-contained Windows x64 desktop host and packages it with the themed setup installer (`Upuaut.Setup.exe`).
3. The release workflow publishes `Upuaut-Setup-win-x64-vVERSION.zip` containing the installer and required setup media.
4. See [installer/README.md](installer/README.md) for installer configuration and silent deployment flags.

---

## 🏛️ The Architect

Upuaut is designed and engineered by **Abhishek Mitra** ([`@indoctrinatedrecluse`](https://github.com/indoctrinatedrecluse)).

- 🎓 **Education:** MS in Computer Science, University of Southern California (USC), Los Angeles, CA.
- 💼 **Background:** Systems and full-stack software engineering across Microsoft IDC, Digite (Full-Stack DevOps), and Synactive (Desktop Architecture, San Francisco).
- 🌐 **Portfolio:** [portfolio-flutter-78bcf.web.app](https://portfolio-flutter-78bcf.web.app/)
- 🐙 **GitHub:** [github.com/indoctrinatedrecluse](https://github.com/indoctrinatedrecluse)
- ⭐ **Repository:** [github.com/indoctrinatedrecluse/Upuaut](https://github.com/indoctrinatedrecluse/Upuaut)

---

## ⚖️ License

Distributed under the [MIT License](LICENSE).
