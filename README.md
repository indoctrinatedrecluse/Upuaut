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

### Phase 2: The Chronicles (Windows Logs & ETW) ⚪
- [ ] Live and historical Windows Event Log reader with XPath search.
- [ ] Real-time ETW session listener for kernel/network providers.
- [ ] High-performance virtualized log table with instant search and severity filtering.

### Phase 3: The Scout (On-Demand Packet Sniffing) ⚪
- [ ] Adapter enumeration and capture session management.
- [ ] Packet dissection engine (Ethernet, IPv4/IPv6, TCP, UDP, DNS, TLS).
- [ ] Live socket-to-PID attribution (identifying the Windows process behind each packet).
- [ ] Detail pane with protocol breakdown and raw hex/ASCII inspection.

### Phase 4: The Scales (Correlation & Anomaly Detection) ⚪
- [ ] Correlated timeline view matching network drops to system event errors.
- [ ] Automated heuristic triage (highlighting suspicious error bursts and timeouts).
- [ ] Capture export (`.pcapng` and `.evtx` / structured `.json`).

---

## ⚖️ License
Distributed under the [MIT License](LICENSE).

