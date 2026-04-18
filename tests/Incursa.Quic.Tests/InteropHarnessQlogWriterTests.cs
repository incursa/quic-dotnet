using Incursa.Quic.InteropHarness;
using Incursa.Quic.Qlog;
using Incursa.Qlog;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessQlogWriterTests
{
    [Fact]
    public void CreateOutputPathSanitizesTheStemAndKeepsTheFileInsideTheRequestedDirectory()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-qlog-writer");
        string outputDirectory = fixture.CreateSubdirectory("qlog");
        string stem = $"client{Path.DirectorySeparatorChar}capture{Path.AltDirectorySeparatorChar}:{new string(Path.GetInvalidFileNameChars())}";

        string outputPath = InteropHarnessQlogWriter.CreateOutputPath(outputDirectory, stem);
        string fileName = Path.GetFileName(outputPath);

        Assert.Equal(outputDirectory, Path.GetDirectoryName(outputPath));
        Assert.EndsWith(".qlog", fileName, StringComparison.OrdinalIgnoreCase);
        Assert.True(fileName.IndexOfAny(Path.GetInvalidFileNameChars()) < 0);
        Assert.DoesNotContain(Path.DirectorySeparatorChar, fileName);
        Assert.DoesNotContain(Path.AltDirectorySeparatorChar, fileName);
        Assert.DoesNotContain(':', fileName);
    }

    [Fact]
    public void TryWriteWithEmptyPayloadsDoesNotCreateDirectoriesOrFiles()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-qlog-writer");
        string outputPath = Path.Combine(fixture.RootDirectory, "missing", "trace.qlog");

        QlogFile qlogFile = new();
        Assert.True(InteropHarnessQlogWriter.TryWrite(outputPath, qlogFile, out string? fileErrorMessage));
        Assert.Null(fileErrorMessage);
        Assert.False(Directory.Exists(Path.GetDirectoryName(outputPath)!));
        Assert.False(File.Exists(outputPath));

        QuicQlogCapture capture = new();
        Assert.True(InteropHarnessQlogWriter.TryWrite(outputPath, capture, out string? captureErrorMessage));
        Assert.Null(captureErrorMessage);
        Assert.False(Directory.Exists(Path.GetDirectoryName(outputPath)!));
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public void TryWriteCreatesTheTargetDirectoryBeforeWritingQlogContent()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-qlog-writer");
        string outputDirectory = Path.Combine(fixture.RootDirectory, "nested", "qlog");
        string outputPath = InteropHarnessQlogWriter.CreateOutputPath(outputDirectory, "client-handshake");

        QlogTrace trace = new()
        {
            VantagePoint = new QlogVantagePoint
            {
                Type = QlogKnownValues.ClientVantagePoint,
            },
        };
        trace.EventSchemas.Add(new Uri("urn:ietf:params:qlog:events:quic"));

        QlogFile file = new();
        file.Traces.Add(trace);

        Assert.True(InteropHarnessQlogWriter.TryWrite(outputPath, file, out string? errorMessage), errorMessage);
        Assert.Null(errorMessage);
        Assert.True(Directory.Exists(outputDirectory));
        Assert.True(File.Exists(outputPath));
        Assert.NotEqual(0, new FileInfo(outputPath).Length);
    }

    [Fact]
    public void TryWriteReturnsAUsefulMessageWhenTheOutputPathCannotBeWritten()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-qlog-writer");
        string outputPath = Path.Combine(fixture.RootDirectory, "blocked", "trace.qlog");
        Directory.CreateDirectory(outputPath);

        QlogFile file = new();
        file.Traces.Add(new QlogTrace());

        Assert.False(InteropHarnessQlogWriter.TryWrite(outputPath, file, out string? errorMessage));
        Assert.NotNull(errorMessage);
        Assert.Contains("interop harness: failed to write qlog output", errorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(outputPath, errorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.True(Directory.Exists(outputPath));
    }
}
