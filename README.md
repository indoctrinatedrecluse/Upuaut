# Upuaut

Upuaut is a Windows desktop toolkit for investigating Windows event logs, inspecting network packets, and comparing nearby system and network signals. It combines a WPF host with a Blazor Hybrid interface and a dark, Egyptian-inspired visual theme.

## Workspaces

- **Chronicles** queries local Windows event channels and offline `.evtx` files. It supports severity, provider, event ID, time, and text filters; live event streaming; event explanations; failure clusters; period comparisons; and JSON, CSV, Markdown, and investigation-case exports.
- **Scout** captures IPv4 traffic through Windows raw sockets or Ethernet frames through Npcap. Ethernet mode dissects IPv4, IPv6, VLAN, ARP, TCP, UDP, ICMP, and ICMPv6. The inspector provides protocol details, bounded DNS question/answer data, selected HTTP metadata, TLS ClientHello SNI, and captured bytes. Scout also supports display and user-space capture filters, endpoint conversations, TCP Follow, and PCAPNG import/export.
- **Scales** is an early correlation preview. It places recent System/Application warning and error events beside packets already in Scout's buffer when they fall within ±2.5 seconds. The score is time proximity only; it does not establish causation or threat probability. Notes and case data can be saved as JSON or CSV.

Event and packet explanations expose their category, readable headline, tags, evidence, and suggested checks. These are deterministic rules and investigative guidance, not automated root-cause diagnoses.

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

See the searchable in-app Documentation page for workspace workflows and `installer/README.md` for setup, uninstall, and video asset details.

## Release

Push a semantic version tag such as `v0.2.0`. The `Windows Release` GitHub Actions workflow publishes the self-contained Windows x64 app, bundles it with the themed setup program, and attaches a ZIP package to the GitHub Release. Extract the full ZIP before running `Upuaut.Setup.exe`; the setup program uses its sibling payload folder.

See [CHANGELOG.md](CHANGELOG.md) for release history and [LICENSE](LICENSE) for the MIT license.

## Author

Created by **Abhishek Mitra** (`indoctrinatedrecluse`).

- [GitHub](https://github.com/indoctrinatedrecluse/)
- [Portfolio](https://portfolio-flutter-78bcf.web.app/)
