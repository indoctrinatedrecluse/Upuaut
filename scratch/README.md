# Synthetic Log Lab Fixtures

These files are synthetic and contain no real user, host, or network data. Import them from **Log Lab** to explore common formats and scenarios. All timestamps use UTC; documentation-only IP addresses are used in network examples.

| File | Format | Scenario to inspect |
| --- | --- | --- |
| 01-setup-installation.txt | Plain text | Successful install with a recoverable warning, a retry, and completion |
| 02-dotnet-application-crash.txt | Plain text | Warning-to-crash sequence, exception details, error code, and stack trace |
| 03-web-access-errors.csv | CSV | Successful requests alongside HTTP 503 and 404 responses |
| 04-authentication-events.jsonl | JSON Lines | Successful login, failed authentication, and temporary account lock |
| 05-service-recovery.xml | XML | Service failure followed by automatic recovery |
| 06-malformed-structured.json | Malformed JSON | Parser fallback to raw text while preserving the original source |
| 07-unclassified-maintenance.txt | Plain text | Unfamiliar maintenance messages with few recognized severity signals |
| 08-empty-log.txt | Empty | Empty-file handling and an empty raw editor |
| 09-application-events.ini | INI sections | Section-per-event key/value parsing with timestamps, component names, IDs, and messages |
| 10-service-events.logfmt | Logfmt | Quoted values, identifiers, durations, and status-aware severities |
| 11-syslog-mixed-formats.txt | RFC 5424 and RFC 3164 | Syslog priority decoding, hosts, programs, timestamps, and daemon failures |
| 12-apache-access.txt | Apache combined access | Request, client, status, response size, referrer, and user-agent extraction |
| 13-windows-event-export.xml | Windows Event XML | Repeated namespaced event records, provider metadata, event IDs, and event data |
| 14-python-crash-traceback.txt | Multiline plain text | Traceback grouping and cause/error evidence attached to one event |
| 15-database-audit.txt | Key/value records | Unquoted and quoted fields, transaction IDs, latency, and deadlock signals |
| 16-unusual-delimiters.txt | Custom delimiter text | Mixed separators and unstructured operator notes for raw/manual review |
| 17-agent-export.xlog | Unknown `.xlog` extension | Proprietary-looking pipe-delimited worker export; extension label remains visible while content is inspected as plain text |
| 18-readable-savegame.hex | Hex dump text | ASCII hex view of a game-save record; should remain readable text even though its filename suggests binary data |
| 19-sample-solution.sln | Visual Studio solution | Ordinary structured text outside the log domain; should remain available for raw inspection |
| 20-cloud-database-runtime.txt | Logfmt | Synthetic cloud/container, database, runtime, TLS, DNS, storage, and socket errors for source-backed knowledge matching |
| 21-expanded-knowledge-cases.txt | Multiline/plain text | Representative Python, Node.js, SQL Server, Oracle, gRPC, AWS, HTTP, MongoDB, Elasticsearch, Docker, Linux, Kubernetes, NGINX, .NET, Java, and Windows signatures |

The fixtures are deliberately small so they can be opened quickly. Try searching for terms such as timeout, 503, authentication, recovered, deadlock, or retries, then compare the scenario findings with the raw source. Some files intentionally mix records or use nonstandard syntax so you can check parser notes and the raw-source fallback.

| 22 | 22-application-wer-report.wer | Synthetic Windows Error Reporting APPCRASH report; validates field preservation and access-violation knowledge reuse. |
