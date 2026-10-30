using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Runtime;
using Upuaut.CrashForensics.Models;
using Upuaut.LogLab;
using Upuaut.LogLab.Models;

namespace Upuaut.CrashForensics;

/// <summary>Bounded local analysis for Windows minidumps and WER reports, with optional signed DAC/symbol lookup.</summary>
public sealed class CrashArtifactAnalyzer(ILogParsingEngine logParser, ILogAnalysisEngine logAnalysis) : ICrashArtifactAnalyzer
{
    public const long MaximumDumpBytes = 64L * 1024 * 1024 * 1024;
    public const long MaximumWerBytes = 32L * 1024 * 1024;
    private const int MaximumWerFindings = 100;
    private static readonly Regex ExceptionCodePattern = new(@"\b0x(?<code>[0-9a-f]{8})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
    private static readonly string SymbolCachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Upuaut", "SymbolCache");

    public async Task<CrashAnalysisResult> AnalyzeAsync(string path, bool resolveMicrosoftSymbols = false, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Choose a crash artifact first.", nameof(path));
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists) throw new FileNotFoundException("The selected crash artifact could not be found.", fullPath);
        if (file.Length is <= 0 or > MaximumDumpBytes)
            throw new InvalidDataException($"The selected artifact is empty or exceeds the {MaximumDumpBytes / (1024d * 1024 * 1024):0} GiB safety limit.");

        var extension = file.Extension;
        if (extension.Equals(".wer", StringComparison.OrdinalIgnoreCase))
        {
            if (file.Length > MaximumWerBytes) throw new InvalidDataException("Windows Error Reporting files are limited to 32 MiB.");
            return await AnalyzeWerAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }

        var header = new byte[16];
        await using (var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var read = await stream.ReadAsync(header, cancellationToken).ConfigureAwait(false);
            if (WindowsMinidumpReader.HasMinidumpSignature(header.AsSpan(0, read)))
                return await Task.Run(() => AnalyzeMinidump(fullPath, file.Length, resolveMicrosoftSymbols, cancellationToken), cancellationToken).ConfigureAwait(false);
            if (IsKernelDumpHeader(header.AsSpan(0, read))) return BuildKernelDumpResult(fullPath, file.Length);
        }

        return new(Path.GetFileName(fullPath), fullPath, file.Length, CrashArtifactKind.Unknown,
            "The file is not a supported Windows minidump or .wer report.", null, null, null, null, null, [], [], [], [], [],
            new Dictionary<string, string>(), ["No supported crash-artifact signature was found. The original file was not modified."]);
    }

    private async Task<CrashAnalysisResult> AnalyzeWerAsync(string path, CancellationToken cancellationToken)
    {
        var document = await logParser.ImportFileAsync(path, cancellationToken).ConfigureAwait(false);
        var report = logAnalysis.Analyze(document);
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in document.Entries)
        foreach (var pair in entry.Fields)
        {
            if (fields.Count >= 256) break;
            var key = Clip(pair.Key, 128);
            if (!string.IsNullOrWhiteSpace(key) && !fields.ContainsKey(key)) fields[key] = Clip(pair.Value, 2_048);
        }

        var logEvidence = document.Entries.Take(MaximumWerFindings).Select(entry =>
        {
            report.Entries.TryGetValue(entry.Index, out var analysis);
            return new CrashLogEvidence(entry.SourceLine, entry.Severity.ToString(), Clip(entry.Message, 2_000), analysis?.Headline,
                analysis?.Explanation, analysis?.KnowledgeSource);
        }).ToArray();
        var allText = string.Join("\n", document.OriginalText, string.Join('\n', fields.Values));
        var findings = new List<CrashFinding>();
        var seenCodes = new HashSet<uint>();
        foreach (Match match in ExceptionCodePattern.Matches(allText).Cast<Match>().Take(8))
        {
            if (!uint.TryParse(match.Groups["code"].Value, System.Globalization.NumberStyles.HexNumber, null, out var code) || !seenCodes.Add(code)) continue;
            var finding = ExplainException(code, 0, 0, []);
            if (finding is not null) findings.Add(finding);
        }
        foreach (var analysis in report.Entries.Values.Where(item => item.KnowledgeId is not null).Take(12))
            findings.Add(new(analysis.KnowledgeId!, analysis.Headline, analysis.Explanation, analysis.Recommendations));

        var appName = FindField(fields, "AppName", "NsAppName", "ApplicationName");
        var eventType = FindField(fields, "EventType", "FriendlyEventName");
        var summary = string.Join(" · ", new[] { "Windows Error Reporting report", eventType, appName }.Where(value => !string.IsNullOrWhiteSpace(value)));
        if (document.Entries.Count == 0) summary += " · No structured records were extracted; the source remains available in the findings list.";
        var warnings = document.Warnings.ToList();
        if (document.Entries.Count > MaximumWerFindings) warnings.Add($"Only the first {MaximumWerFindings} report entries are shown in this view.");
        return new(Path.GetFileName(path), path, document.ByteLength, CrashArtifactKind.WindowsErrorReport, summary,
            null, FindField(fields, "OSVersion", "WindowsVersion", "OsVersion"), null, null, null, [], [], [], findings,
            logEvidence, fields, warnings);
    }

    private static CrashAnalysisResult AnalyzeMinidump(string path, long fileSize, bool resolveMicrosoftSymbols, CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        WindowsMinidumpMetadata metadata;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.RandomAccess))
            metadata = WindowsMinidumpReader.Read(stream, cancellationToken);
        warnings.AddRange(metadata.Warnings);

        var runtimes = new List<ManagedRuntimeEvidence>();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dataTarget = DataTarget.LoadDump(path, new DataTargetOptions
            {
                SymbolPaths = resolveMicrosoftSymbols ? ["https://msdl.microsoft.com/download/symbols"] : [],
                SymbolCachePath = SymbolCachePath,
                Limits = new DataTargetLimits
                {
                    MaxMinidumpStreams = 512,
                    MaxMinidumpMemoryRanges = 1_000_000,
                    MaxThreads = 1_024,
                    MaxStackFrames = 128,
                    MaxModules = 4_096,
                    MaxAppDomains = 256,
                    MaxPESections = 1_024,
                    MaxPEDebugDirectories = 4_096,
                    MaxPEExportNames = 100_000,
                    MaxPERelocations = 1_000_000
                }
            });
            using (dataTarget)
            {
                foreach (var runtimeInfo in dataTarget.ClrVersions.Take(8))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var threads = new List<ManagedThreadEvidence>();
                    try
                    {
                        using var runtime = runtimeInfo.CreateRuntime();
                        foreach (var thread in runtime.Threads.Take(256))
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            var frames = new List<string>();
                            foreach (var frame in thread.EnumerateStackTrace(includeContext: false, maxFrames: 96).Take(96))
                            {
                                var name = frame.ToString();
                                if (!string.IsNullOrWhiteSpace(name)) frames.Add(Clip(name, 500));
                            }
                            threads.Add(new(thread.OSThreadId, thread.ManagedThreadId, thread.IsAlive, frames));
                        }
                    }
                    catch (Exception ex) when (IsRecoverableDumpError(ex))
                    {
                        warnings.Add($"Managed runtime {runtimeInfo.Version} was detected, but its managed stacks could not be read: {Describe(ex)}");
                    }
                    runtimes.Add(new(runtimeInfo.Flavor.ToString(), runtimeInfo.Version.ToString(), threads));
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsRecoverableDumpError(ex))
        {
            warnings.Add(resolveMicrosoftSymbols
                ? $"Managed runtime inspection or optional Microsoft symbol lookup did not complete: {Describe(ex)}"
                : $"Managed runtime metadata could not be resolved without network symbol lookup: {Describe(ex)}");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var findings = new List<CrashFinding>();
        if (metadata.Exception is { } exception && ExplainException(exception.Code, exception.ThreadId, exception.Address, exception.Parameters) is { } explanation)
            findings.Add(explanation);
        var summary = metadata.Exception is { } exceptionInfo
            ? $"Windows user-mode minidump · exception {FormatException(exceptionInfo.Code)} · thread {exceptionInfo.ThreadId}"
            : "Windows user-mode minidump · no exception stream was recorded";
        if (runtimes.Count > 0) summary += $" · {runtimes.Count} managed runtime(s) inspected";
        if (resolveMicrosoftSymbols) summary += " · Microsoft symbol lookup was requested";
        return new(Path.GetFileName(path), path, fileSize, CrashArtifactKind.WindowsMinidump, summary, metadata.Architecture,
            metadata.OperatingSystem, metadata.DumpTimestampUtc, metadata.ProcessId, metadata.Exception, metadata.Modules,
            metadata.Threads, runtimes, findings, [], new Dictionary<string, string>(), warnings);
    }

    public static CrashFinding? ExplainException(uint code, uint threadId, ulong address, IReadOnlyList<ulong> parameters)
    {
        var codeText = FormatException(code);
        var checks = new List<string>
        {
            "Compare this exception with the application's event, WER report, and surrounding logs from the same time.",
            "Use matching application binaries and symbols before treating an address as a named function or module."
        };
        var explanation = code switch
        {
            0xC0000005 => "An access violation records an invalid memory access. The exception parameters may distinguish a read, write, or execute access and identify the referenced address; it does not by itself identify the responsible component.",
            0xC0000006 => "An in-page error occurred while the process attempted to page memory into its address space. The underlying I/O status and storage events are needed to explain the failure.",
            0xC000001D => "The processor encountered an invalid instruction. Check the instruction address, loaded module, architecture compatibility, and whether executable code or memory was corrupted.",
            0xC00000FD => "The thread exhausted its stack. Deep or recursive calls are possible explanations, but the stack trace and thread context are needed to distinguish them.",
            0xC0000374 => "The process reported heap corruption. This is a symptom that may be detected after the original invalid write; the reporting instruction may not be the corrupting operation.",
            0xC0000409 => "A fail-fast condition terminated the process. This status can represent several fast-fail checks; inspect the exception parameters and matching runtime or application diagnostics.",
            0xE0434352 => "The process reported a CLR-managed exception through the Windows exception mechanism. The dump may need the matching .NET runtime DAC and managed stack data to identify the exception type and call path.",
            0x80000003 => "A breakpoint exception was recorded. Debugger breakpoints can be intentional; establish whether the process had a debugger or explicitly raised a breakpoint before treating it as a crash cause.",
            _ => null
        };
        if (explanation is null) return null;
        if (code == 0xC0000005 && parameters.Count >= 2)
        {
            var operation = parameters[0] switch { 0 => "read", 1 => "write", 8 => "execute", _ => $"operation {parameters[0]}" };
            checks.Add($"The exception record identifies a {operation} involving address 0x{parameters[1]:X}.");
        }
        return new(codeText, $"Exception {codeText}: {ExceptionName(code)}", explanation + $" Recorded thread: {threadId}; instruction address: 0x{address:X}.", checks);
    }

    public static string FormatException(uint code) => $"0x{code:X8}";

    public static string ExceptionName(uint code) => code switch
    {
        0xC0000005 => "Access violation",
        0xC0000006 => "In-page error",
        0xC000001D => "Illegal instruction",
        0xC00000FD => "Stack overflow",
        0xC0000374 => "Heap corruption",
        0xC0000409 => "Fail-fast termination",
        0xE0434352 => "CLR exception",
        0x80000003 => "Breakpoint",
        _ => "Unhandled exception"
    };

    private static CrashAnalysisResult BuildKernelDumpResult(string path, long fileSize) =>
        new(Path.GetFileName(path), path, fileSize, CrashArtifactKind.WindowsKernelDump,
            "Windows kernel crash dump detected. This format requires a kernel debugger for reliable bugcheck, driver, and stack analysis.",
            null, null, null, null, null, [], [], [], [], [], new Dictionary<string, string>(),
            ["Upuaut recognized a Windows PAGE/DUMP-style kernel dump but does not parse kernel memory. The file was not modified.", "Open the file in Microsoft WinDbg for supported kernel-mode analysis."]);

    private static bool IsKernelDumpHeader(ReadOnlySpan<byte> header)
    {
        var text = Encoding.ASCII.GetString(header);
        return text.StartsWith("PAGE", StringComparison.Ordinal) || text.StartsWith("PAGEDUMP", StringComparison.Ordinal) ||
               text.StartsWith("DU64", StringComparison.Ordinal) || text.StartsWith("DUMP", StringComparison.Ordinal);
    }

    private static string? FindField(IReadOnlyDictionary<string, string> fields, params string[] names)
    {
        foreach (var name in names)
            if (fields.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)) return Clip(value, 500);
        return null;
    }

    private static bool IsRecoverableDumpError(Exception exception) => exception is InvalidDataException or IOException or UnauthorizedAccessException or
        InvalidOperationException or NotSupportedException or BadImageFormatException or DllNotFoundException or FileLoadException or
        System.Runtime.InteropServices.COMException or ArgumentException or OverflowException;

    private static string Describe(Exception exception) => Clip(string.IsNullOrWhiteSpace(exception.Message) ? exception.GetType().Name : exception.Message, 500);
    private static string Clip(string? value, int maximum) => string.IsNullOrEmpty(value) || value.Length <= maximum ? value ?? string.Empty : value[..(maximum - 1)] + "…";
}
