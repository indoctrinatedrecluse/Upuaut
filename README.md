# 🐺 Upuaut (Wepwawet) — *The Opener of the Ways*

> *"He who scouts the hidden path through the underworld, dispels the obscuring mist, and guides the sovereign through the Duat."*

**Upuaut** is a modern, high-performance Windows systems diagnostics and network triage instrument. Built for systems engineers, network administrators, and power troubleshooters, Upuaut cuts through operating system obscurity—providing deep, correlated insights into Windows kernel events, system event logs, and real-time network traffic.

---

## ⚡ Core Philosophy & Brief

Troubleshooting modern Windows issues is often fragmented:
- **Event Viewer** is slow, monolithic, and disconnected from active network state.
- **Wireshark** provides immense depth into packet bytes, but struggles with real-time attribution to local Windows processes (PIDs) without clunky external capture scripts.
- **Sysinternals (Process Monitor / TCPView)** provides process snapshots, but lacks integrated packet-level inspection and unified chronological correlation.

**Upuaut** unifies these domains into a single, cohesive, modern diagnostic instrument:
1. **Windows Event Logs & Kernel ETW:** Live and historical event stream inspection powered by Microsoft's battle-tested diagnostic runtimes.
2. **On-Demand Packet Sniffing & Dissection:** Fast, zero-overhead packet capture with immediate socket-to-process attribution.
3. **Chronological Correlation:** Linking network drops, TCP resets, or DNS resolution timeouts directly to the system and application events that triggered or accompanied them.

---

## 🏛️ System Architecture: The In-Process Hybrid Model

Upuaut leverages a **Blazor Hybrid (In-Process)** desktop architecture on **.NET 10**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                 UPUAUT.EXE                                  │
│                                                                             │
│  ┌─────────────────────────────────┐   Direct In-Memory   ┌───────────────┐ │
│  │      Windows Diagnostics Core   │◄────────────────────►│ Blazor Engine │ │
│  │                                 │   Thread Channels    │               │ │
│  │  • Event Tracing for Windows    │                      │ • State Store │ │
│  │    (Microsoft.Diagnostics)      │                      │ • Filter Pipe │ │
│  │  • System.Diagnostics.Eventing  │                      │ • Virtualizer │ │
│  │  • Packet Capture & Dissection  │                      └───────┬───────┘ │
│  │  • Socket-to-PID Attribution    │                              │         │
│  │  • Lock-Free Ring Buffers       │                              │ Direct  │
│  └─────────────────────────────────┘                              │ Interop │
│                                                                   │ (No IPC)│
│                                                       ┌───────────▼───────┐ │
│                                                       │  WebView2 Canvas  │ │
│                                                       │ • Fluent UI (MS)  │ │
│                                                       │ • Virtual DataGrid│ │
│                                                       │ • Canvas Charting │ │
│                                                       │ • Egyptian Theme  │ │
│                                                       └───────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why this architecture?
- **Zero Network/IPC Overhead:** Unlike Tauri or Electron which serialize large packet arrays over JSON-RPC or WebSocket bridges, Blazor Hybrid executes C# in-process directly on the .NET 10 CLR.
- **Direct Native Memory Access:** Captured network frames and ETW event payloads remain in high-performance memory buffers (`ReadOnlyMemory<byte>`, lock-free `Channel<T>`).
- **High-Density Virtualization:** Capable of rendering tens of thousands of real-time packets or event logs at a steady 60–120 FPS by rendering only the visible viewport.
- **Modern Windows 11 Polish:** Powered by Microsoft Fluent UI for Blazor with bespoke Egyptian Obsidian & Gold styling.

---

## 🛠️ The Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Runtime & Host** | **.NET 10 (C# 13)** + WPF/Windows App SDK Blazor Host | Native 64-bit Windows execution with direct OS API interop. |
| **UI Framework** | **Blazor Hybrid** (`Microsoft.AspNetCore.Components.WebView`) | Reactive, component-driven UI running directly in-process. |
| **Component Library** | **Microsoft Fluent UI for Blazor** (`Microsoft.FluentUI.AspNetCore.Components`) | Windows 11 Fluent 2 design language, icons, and virtualized data grids. |
| **ETW & Tracing** | **`Microsoft.Diagnostics.Tracing.TraceEvent`** | Microsoft's gold-standard library for real-time Event Tracing for Windows. |
| **Event Log Engine** | **`System.Diagnostics.Eventing.Reader`** | Native querying of `.evtx` files and live Windows event log channels. |
| **Packet Engine** | **ETW Packet Capture / SharpPcap & PacketDotNet** | On-demand packet capture (driverless ETW or Npcap for promiscuous L2). |
| **Data Visualization** | **Canvas / LiveCharts2 / uPlot** | Real-time traffic throughput, packet rate sparklines, and protocol distributions. |

---

## 📜 The Thematic Pillars (Egyptian Lore & Functionality)

In ancient Egyptian mythology, Upuaut stood at the prow of the solar boat, brandishing weapons to clear dangerous entities from the path of Ra. In our architecture, the modules reflect this purpose:

### 1. 🐺 The Scout (`Upuaut.Scout`) — Network Sniffing & Process Attribution
- **On-Demand Sniffing:** Start and stop targeted packet captures on specific network adapters without launching heavyweight external suites.
- **Protocol Dissection:** Fast dissection of L2–L4 (Ethernet, IPv4, IPv6, TCP, UDP, ICMP) and essential L7 protocols (DNS, HTTP, TLS Server Name Indication).
- **Socket-to-Process (PID) Mapping:** Inspects Windows network table bindings (`GetExtendedTcpTable` / `GetExtendedUdpTable`) to tag packets with the owning process name and PID in real time.
- **Filter Syntaxes:** Intuitive query bar for filtering by protocol, IP, port, or process name.

### 2. 📜 The Duat Chronicles (`Upuaut.Chronicles`) — Windows Event Logs & ETW
- **Classic Event Logs:** Rapid, threaded querying of standard channels (`System`, `Application`, `Security`) and operational logs (`Microsoft-Windows-Diagnostics-Networking`, `DNS-Client`, etc.).
- **Real-Time ETW Surveillance:** Tap directly into kernel and user-mode ETW providers:
  - `Microsoft-Windows-TCPIP` (Connection resets, retransmissions, SYN floods).
  - `Microsoft-Windows-DNS-Client` (Latency, NXDOMAIN responses, server timeouts).
  - `Microsoft-Windows-Kernel-Process` (Spawning and termination lifecycle).
- **Error Aggregation:** Group identical error codes and warnings into actionable clusters instead of endless scrolling lists.

### 3. ⚖️ The Scales of Ma'at (`Upuaut.Weigher`) — Triage & Correlation Engine
- **Unified Timeline:** Interleaves system events and network anomalies onto a synchronized time axis.
- **Root-Cause Heuristics:** Automatically highlights suspicious patterns:
  - *Example:* An application crash event (`Event ID 1000`) occurring 5ms after a series of TCP connection resets to an upstream service.
  - *Example:* DNS lookup failure bursts correlated with local network interface flapping.

### 4. 🔱 The Standard (`Upuaut.Core`) — The Infrastructure Backbone
- High-throughput circular ring buffers (`RingBuffer<T>`) to guarantee predictable memory consumption even under sustained gigabit traffic.
- Zero-copy data slicing and high-efficiency search indexing.

---

## 📂 Planned Solution Structure

```
Upuaut/
│
├── .gitignore                          # Visual Studio, .NET, dumps, and trace exclusions
├── README.md                           # Project vision, architecture, and scope
├── Upuaut.sln                          # Master Solution
│
└── src/
    ├── Upuaut.Core/                    # Models, ring buffers, shared interfaces, contracts
    │   ├── Models/                     # PacketFrame, LogRecord, CorrelatedEvent
    │   └── Buffers/                    # Lock-free ring buffer & ring metrics
    │
    ├── Upuaut.Scout/                   # Network sniffing & packet dissection
    │   ├── Capture/                    # Driverless ETW / Npcap capture abstractions
    │   ├── Dissectors/                 # IP, TCP, UDP, DNS, TLS parser logic
    │   └── Attribution/                # Windows socket-to-PID resolver
    │
    ├── Upuaut.Chronicles/              # Windows Event Logs & ETW providers
    │   ├── Evtx/                       # System.Diagnostics.Eventing.Reader queries
    │   └── Etw/                        # TraceEvent session manager & listeners
    │
    ├── Upuaut.Weigher/                 # Heuristics & correlation rules
    │   └── Rules/                      # Anomaly detection & time-window correlators
    │
    ├── Upuaut.UI/                      # Blazor components, pages, visualizers
    │   ├── Pages/                      # Dashboard, Scout (Packets), Chronicles (Logs)
    │   ├── Components/                 # Virtualized tables, hex views, status badges
    │   └── Theme/                      # Egyptian Obsidian/Gold palette & styles
    │
    └── Upuaut.App/                     # WPF / Windows Blazor Hybrid desktop host
        ├── MainWindow.xaml             # Host window with WebView2 container
        └── App.xaml                    # Application bootstrapper & DI container
```

---

## 🗺️ Scope & Roadmap (Continuously Updated)

### Phase 1: Foundations & Scaffolding 🟢 (Completed)
- [x] Architecture & Tech Stack consensus.
- [x] Repository initialization & comprehensive `.gitignore`.
- [x] Technical specification & documentation (`README.md`).
- [x] MIT License added.
- [x] Solution scaffolding (`Upuaut.sln` + clean 6-project modular split).
- [x] Desktop host setup (WPF Blazor Hybrid with .NET 10 & Microsoft Fluent UI v5).
- [x] Dark Egyptian theme scaffolding (Obsidian `#090A0D`, Sand `#E6C687`, Lapis `#1E3A8A`, Gold `#D4AF37`).
- [x] Remote repository created and pushed (`https://github.com/indoctrinatedrecluse/Upuaut`).

### Phase 2: The Chronicles (Windows Logs & The Oracle) 🟢 (Completed)
- [x] Historical and live Windows Event Log engine (`System.Diagnostics.Eventing.Reader`) with optimized XPath generation.
- [x] Friendly Human-Readable Error Explanation Engine (*The Oracle*) decoding cryptic Windows events, DCOM warnings, BSOD BugChecks, and 150+ NTSTATUS/HRESULT codes.
- [x] Deep Forensic Decoder for Critical & Error events:
  - Decodes BSOD Stop Codes (decimal and hex) with root causes and minidump locations.
  - Decodes Application Error 1000 (faulting module roles, memory access violations `0xC0000005`, stack overruns).
  - Decodes Service Control Manager 7000/7009/7031 with friendly Win32 exit codes.
  - Decodes Security 4625 failed logons with interactive/RDP logon types and sub-status causes.
  - Decodes Disk and NTFS filesystem corruption indices with actionable shell remediation commands (`sfc /scannow`, `chkdsk`, `sc.exe`).
- [x] Multi-level filtration (Critical, Error, Warning, Info), Channel selector, and Time-range filters.
- [x] 1-Click Quick-Triage Presets (⚡ BSOD & Reboots, 💥 App Crashes, 🌐 Network Drops, 💾 Disk Health, 🔐 Failed Logons).
- [x] Benign noise suppression toggle (e.g. DCOM 10016) to surface only real issues.
- [x] Full-text search across messages, providers, Event IDs, and error codes.
- [x] Real-time event watcher (`EventLogWatcher`) for live log streaming.
- [x] Enterprise diagnostic logging (`AppLogger`) and crash reporter subsystem (`CrashReporter`) with interactive in-app diagnostics drawer (`DiagnosticsDrawer.razor`).
- [x] Unified PowerShell bootstrapper script (`run.ps1`) with automatic UAC elevation by default.

### Phase 3: The Scout (On-Demand Packet Sniffing) 🟢 (Completed)
- [x] Driverless Native Windows Raw Socket Capture Engine (`SIO_RCVALL` on IPv4).
- [x] Live Socket-to-Process (PID) Attribution via Windows IP Helper API (`GetExtendedTcpTable`, `GetExtendedUdpTable` in `iphlpapi.dll`).
- [x] Packet dissection engine (Ethernet, IPv4, TCP with flags/windows, UDP, ICMP, DNS query domain names).
- [x] Anomaly detection (TCP connection resets / aborts flagged in real time).
- [x] Wireshark-inspired interactive UI (`Scout.razor`):
  - Real-time wire throughput, packets/sec rate, total data volume, and active process count.
  - Protocol filters (All, TCP, TLS/HTTPS, DNS, UDP, ICMP).
  - Dynamic Process Filter dropdown for isolating traffic to specific applications (e.g., `chrome.exe`, `discord.exe`).
  - Wire frame table with auto-scroll and per-packet process badges.
  - Detailed Frame Inspector with socket 4-tuple coordinates, protocol flags, and raw byte Hex Dump & ASCII viewer.

### Phase 4: Pantheon Lore, Documentation, & Developer Experience 🟢 (Completed)
- [x] **The Celestial Pantheon & Sacred Lore Portal (`/pantheon`):**
  - Dedicated lore explorer detailing the 7 Egyptian guardian deities and their direct software mappings:
    - 🐺 **Upuaut (Wepwawet):** Opener of the Ways → *The Scout (Driverless Wire Sniffer & Network Vanguard)*
    - 📜 **Thoth (Djehuty):** Master of Sacred Words → *The Duat Chronicles & Event Log Ingestion Engine*
    - ⚖️ **Ma'at:** The Feather of Truth → *The Scales (System Triage & Anomaly Weigher)*
    - 🛡️ **Anpu (Anubis):** Guardian of the Tomb → *Crash Reporter & Forensic Memory Dumper*
    - 📖 **Seshat:** Mistress of Books → *The Sacred Archives & Documentation Engine*
    - 💧 **Kebechet (Qebhet):** Lady of Cold Water → *Benign Noise Suppression & DCOM Filtering*
    - ⚡ **Seker (Sokar):** Restorer of the Broken → *1-Click Forensic Remediation Engine*
- [x] **Header Account & Pantheon Flyout Menu:** Fast access to the Architect profile, quick lore summaries, system documentation, and diagnostic drawers.
- [x] **System Documentation Portal (`/docs`):** Complete searchable architectural specifications, forensic manuals, CLI reference, and code examples.
- [x] **Help Menu:** Searchable in-app task guides plus an About dialog with the app brief and author profile links.
- [x] **Visual Studio 2026 Enterprise Edition Support:**
  - Modern XML Solution format (`Upuaut.slnx`) partitioned into `/src/` and `/tests/` alongside classic `Upuaut.sln`.
  - `.editorconfig` enforcing C# 13 and Razor formatting conventions.
  - `.vsconfig` declaring required Visual Studio desktop and diagnostic workloads.
  - `launchSettings.json` with Standard and Administrator (Elevated) launch profiles.
- [x] **About & Architect Specs (`/about`):** Detailed application specifications and background credentials.

### Phase 5: The Scales (Correlation & Anomaly Detection) ⚪
- [ ] The `/weigher` route currently shows a work-in-progress notice; it does not report live triage results.
- [ ] Correlated timeline view matching network drops to system event errors.
- [ ] Automated heuristic triage (highlighting suspicious error bursts and timeouts).
- [ ] Capture export (`.pcapng` and `.evtx` / structured `.json`).

---

## 🏛️ The Architect

Upuaut is designed and engineered by **Abhishek Mitra** ([`@indoctrinatedrecluse`](https://github.com/indoctrinatedrecluse)).

- 🎓 **Education:** MS in Computer Science, University of Southern California (USC), Los Angeles, CA.
- 💼 **Background:** Software engineering across Microsoft IDC, Digite (Full-Stack DevOps), and Synactive (Desktop Architecture, San Francisco).
- 🌐 **Portfolio Website:** [portfolio-flutter-78bcf.web.app](https://portfolio-flutter-78bcf.web.app/)
- 🐙 **GitHub Profile:** [github.com/indoctrinatedrecluse](https://github.com/indoctrinatedrecluse)
- ⭐ **Repository:** [github.com/indoctrinatedrecluse/Upuaut](https://github.com/indoctrinatedrecluse/Upuaut)

---

## ⚖️ License
Distributed under the [MIT License](LICENSE).

## Windows installer and release

The custom per-user Windows setup experience, video asset locations, and release instructions are documented in [installer/README.md](installer/README.md). Pushing a `v*` tag builds the self-contained x64 package and attaches it to a GitHub Release through `.github/workflows/release.yml`.

