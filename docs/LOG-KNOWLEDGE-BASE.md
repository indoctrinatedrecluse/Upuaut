# Log Lab knowledge patterns

Log Lab uses an offline, deterministic ranked phrase matcher backed by `src/Upuaut.LogLab/Knowledge/log-knowledge-base.json`. Each data row stores a stable ID, category, headline, explanation, signals, tags, recommendations, source name/URL, and a representative example. Curated patterns are evaluated alongside broad scenario rules; the strongest set of specific signals wins. The engine returns matched evidence, a stable rule ID, a primary documentation link, and investigation steps. “Match strength” describes how much matching evidence appeared in the entry, not the probability of a particular root cause.

The parser does not download logs or send user data to a service. Source documentation informs the explanation and remediation guidance. The scratch fixture `scratch/20-cloud-database-runtime.log` contains synthetic lines with representative public error codes and phrases, not copied third-party log records. This avoids bundling datasets whose redistribution terms may be unclear and helps prevent fitting rules to one log corpus.

## Current source-backed coverage

| Area | Signals covered | Primary reference |
|---|---|---|
| Kubernetes | `CrashLoopBackOff`, `ImagePullBackOff`, `ErrImagePull`, `OOMKilled` | [Debugging Kubernetes applications](https://kubernetes.io/docs/tasks/debug/), [container resource management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/) |
| systemd | `203/EXEC`, `EXIT_EXEC` | [systemd.exec exit codes](https://freedesktop.org/software/systemd/man/latest/systemd.exec.html) |
| PostgreSQL | SQLSTATE `23505`, `53300`, `40001` | [PostgreSQL error codes](https://www.postgresql.org/docs/current/errcodes-appendix.html), [serialization failure handling](https://www.postgresql.org/docs/current/mvcc-serialization-failure-handling.html) |
| MySQL | Error `1040` connection capacity, `1045` access denied | [Too many connections](https://dev.mysql.com/doc/refman/8.0/en/too-many-connections.html), [access denied](https://dev.mysql.com/doc/refman/8.0/en/error-access-denied.html) |
| .NET / JVM | Managed memory exhaustion and JVM heap/Metaspace exhaustion | [System.OutOfMemoryException](https://learn.microsoft.com/dotnet/api/system.outofmemoryexception), [Java platform documentation](https://docs.oracle.com/en/java/javase/) |
| HTTP proxying | Gateway errors and upstream timeout/close signals | [NGINX proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) |
| TLS, DNS, storage, sockets | Certificate trust/expiry, name lookup, ENOSPC, bind conflicts | [TLS troubleshooting](https://learn.microsoft.com/dotnet/core/extensions/sslstream-troubleshooting), [DNS client troubleshooting](https://learn.microsoft.com/windows-server/networking/dns/troubleshoot/troubleshoot-dns-client-resolution-issues), [SocketError](https://learn.microsoft.com/dotnet/api/system.net.sockets.socketerror) |
| Python and Node.js | Import/encoding/permission/network exceptions, Node module resolution and socket errors | [Python built-in exceptions](https://docs.python.org/3/library/exceptions.html), [Node.js errors](https://nodejs.org/api/errors.html) |
| SQL Server and Oracle | Login rejection, deadlocks, transaction-log exhaustion, unique constraints, session/connection limits | [SQL Server 18456](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/mssqlserver-18456-database-engine-error), [SQL Server 1205](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/mssqlserver-1205-database-engine-error), [SQL Server 9002](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/mssqlserver-9002-database-engine-error), [Oracle error messages](https://docs.oracle.com/en/database/oracle/oracle-database/23/errmg/) |
| Distributed services and cloud | gRPC deadlines/availability/quotas, AWS S3 throttling, HTTP 401/413/429, MongoDB duplicate keys, Elasticsearch circuit breaker | [gRPC status codes](https://grpc.io/docs/guides/status-codes/), [AWS 503 guidance](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-503-service-unavailable.html), [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585.html), [MongoDB error codes](https://www.mongodb.com/docs/manual/reference/error-codes/), [Elasticsearch circuit breakers](https://www.elastic.co/guide/en/elasticsearch/reference/current/circuit-breaker.html) |
| Build, containers, and host resources | npm dependency conflicts, Docker storage failures, Linux OOM kills, Kubernetes scheduling and NGINX client disconnects | [npm dependency resolution](https://docs.npmjs.com/cli/v11/using-npm/dependency-resolution/), [Docker daemon troubleshooting](https://docs.docker.com/engine/daemon/troubleshoot/), [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), [Kubernetes resource management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/), [NGINX log module](https://nginx.org/en/docs/http/ngx_http_log_module.html) |

Windows Event Log enrichment also covers unexpected shutdowns and correlates the importance of nearby BugCheck, shutdown, and service-install events. Event ID 41 is intentionally described as an unclean-shutdown signal rather than a root cause; see [Microsoft's troubleshooting guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart).

## Ranking and safe interpretation

- Phrase matching is case-insensitive and bounded to each parsed entry's message, source, and a limited number of fields. Regex matching is not used for the knowledge rules, so adversarial input cannot cause catastrophic regex backtracking.
- Longer, more specific overlapping signals replace shorter duplicates before scoring. Several independent signals strengthen a match; one weak match stays weak.
- Broad rules remain available when no specific rule matches. Every recommendation asks for corroborating context and avoids automatic remediation.
- Source links document the interpretation. A log message may be vendor-modified or incomplete, so the original entry and neighboring records remain authoritative.
- The LogHub project is useful as a research/evaluation index, but its datasets are not bundled here: [LogHub repository](https://github.com/logpai/loghub).

## Optional AI review

DeepSeek chat completions, Gemini `generateContent`, and OpenAI-compatible chat completions are supported. The service has no automatic startup check or background request. It sends only the currently selected entry after the user selects **Request AI Review**; entries over 24,000 characters are rejected locally. Provider name, model, and endpoint are stored under `%LOCALAPPDATA%\Upuaut\Settings`; the API key is protected using Windows DPAPI for the current user. The key is never shown again after saving or written to app logs. Remote analysis requires network access and is subject to the configured provider's retention, privacy, and billing terms.
