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

The fixtures are deliberately small so they can be opened quickly. Try searching for terms such as timeout, 503, authentication, recovered, or retries, then compare the scenario findings with the raw source.
