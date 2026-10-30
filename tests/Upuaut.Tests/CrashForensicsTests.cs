using System.Buffers.Binary;
using Upuaut.CrashForensics;
using Upuaut.CrashForensics.Models;
using Upuaut.LogLab;

namespace Upuaut.Tests;

public sealed class CrashForensicsTests
{
    [Fact]
    public void Minidump_reader_extracts_bounded_system_and_exception_metadata()
    {
        var bytes = CreateMinidump();
        using var stream = new MemoryStream(bytes);

        var result = WindowsMinidumpReader.Read(stream);

        Assert.Equal("x64", result.Architecture);
        Assert.Equal("Windows NT 10.0.26100", result.OperatingSystem);
        Assert.Equal(0xC0000005u, result.Exception?.Code);
        Assert.Equal(7u, result.Exception?.ThreadId);
        Assert.Equal(0x1234ul, result.Exception?.Address);
        Assert.Equal(new ulong[] { 1, 0xDEADBEEF }, result.Exception?.Parameters);
    }

    [Fact]
    public async Task Wer_report_reuses_log_lab_fields_and_curated_crash_knowledge()
    {
        var analyzer = new CrashArtifactAnalyzer(new LogParsingEngine(), new LogAnalysisEngine());
        var path = Path.Combine(AppContext.BaseDirectory, "scratch", "22-application-wer-report.wer");

        var result = await analyzer.AnalyzeAsync(path);

        Assert.Equal(CrashArtifactKind.WindowsErrorReport, result.Kind);
        Assert.Equal("FixtureApp.exe", result.ReportFields["AppName"]);
        Assert.Contains(result.Findings, finding => finding.Code == "0xC0000005");
        Assert.NotEmpty(result.LogEvidence);
    }

    [Fact]
    public void Access_violation_explanation_uses_recorded_operation_and_address()
    {
        var finding = CrashArtifactAnalyzer.ExplainException(0xC0000005, 9, 0x1234, [1, 0xDEADBEEF]);

        Assert.NotNull(finding);
        Assert.Contains("Access violation", finding.Headline);
        Assert.Contains(finding.Checks, check => check.Contains("write", StringComparison.Ordinal));
        Assert.Contains(finding.Checks, check => check.Contains("DEADBEEF", StringComparison.Ordinal));
        Assert.Null(CrashArtifactAnalyzer.ExplainException(0xDEADBEEF, 0, 0, []));
    }

    [Fact]
    public async Task Expanded_knowledge_fixture_is_matched_by_the_runtime_log_analysis_engine()
    {
        var parser = new LogParsingEngine();
        var document = await parser.ImportFileAsync(Path.Combine(AppContext.BaseDirectory, "scratch", "21-expanded-knowledge-cases.txt"));
        var analysis = new LogAnalysisEngine().Analyze(document);

        Assert.True(LogKnowledgeBase.GetBuiltInPatterns().Count >= 40);
        Assert.Contains(analysis.Entries.Values, entry => entry.KnowledgeId == "dotnet-assembly-load-failure");
        Assert.Contains(analysis.Entries.Values, entry => entry.KnowledgeId == "dotnet-tls-authentication-failure");
        Assert.Contains(analysis.Entries.Values, entry => entry.KnowledgeId == "java-heap-out-of-memory");
        Assert.All(analysis.Entries.Values.Where(entry => entry.KnowledgeId is not null), entry =>
        {
            Assert.NotEmpty(entry.KnowledgeSource!);
            Assert.Contains(entry.Tags, tag => tag.StartsWith("knowledge:", StringComparison.Ordinal));
        });
    }

    [Fact]
    public void Minidump_reader_rejects_a_truncated_directory_without_reading_out_of_bounds()
    {
        var bytes = new byte[40];
        Write32(bytes, 0, 0x504D444D);
        Write32(bytes, 8, 2);
        Write32(bytes, 12, 32);
        using var stream = new MemoryStream(bytes);

        Assert.Throws<InvalidDataException>(() => WindowsMinidumpReader.Read(stream));
    }

    private static byte[] CreateMinidump()
    {
        var bytes = new byte[280];
        Write32(bytes, 0, 0x504D444D);
        Write32(bytes, 8, 2);
        Write32(bytes, 12, 32);
        Write32(bytes, 20, 1_798_000_000);
        Write32(bytes, 32, 7); Write32(bytes, 36, 56); Write32(bytes, 40, 56);
        Write32(bytes, 44, 6); Write32(bytes, 48, 168); Write32(bytes, 52, 112);
        Write16(bytes, 56, 9);
        Write32(bytes, 64, 10); Write32(bytes, 68, 0); Write32(bytes, 72, 26100); Write32(bytes, 76, 2);
        Write32(bytes, 112, 7);
        Write32(bytes, 120, 0xC0000005);
        Write64(bytes, 136, 0x1234);
        Write32(bytes, 152, 2);
        Write64(bytes, 160, 1); Write64(bytes, 168, 0xDEADBEEF);
        return bytes;
    }

    private static void Write16(byte[] bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset), value);
    private static void Write32(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
    private static void Write64(byte[] bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset), value);
}
