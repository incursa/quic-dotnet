using Incursa.Qlog;
using Incursa.Qlog.Serialization.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0004")]
public sealed class REQ_QUIC_INT_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiagnosticsSinkRemainsStructuredAndCheapWhenDisabled()
    {
        CollectingDiagnosticsSink sink = new();
        QuicDiagnosticEvent diagnostic = new(
            "connection.runtime.path",
            "classified",
            "Packet classified as probable NAT rebinding.",
            QuicDiagnosticSeverity.Warning);

        sink.Emit(diagnostic);
        QuicNullDiagnosticsSink.Instance.Emit(diagnostic);

        Assert.True(sink.IsEnabled);
        Assert.Single(sink.Events);
        Assert.Equal("connection.runtime.path", sink.Events[0].Category);
        Assert.Equal("classified", sink.Events[0].Name);
        Assert.False(QuicNullDiagnosticsSink.Instance.IsEnabled);

        QuicConnectionEmitDiagnosticEffect effect = new(diagnostic);
        Assert.Equal(QuicDiagnosticSeverity.Warning, effect.Diagnostic.Severity);
        Assert.Contains("probable NAT rebinding", effect.Diagnostic.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QlogWriterPersistsContainedJsonToTheRequestedDirectory()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-qlog");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");

        QlogFile file = new();
        QlogTrace trace = new()
        {
            VantagePoint = new QlogVantagePoint
            {
                Type = QlogKnownValues.ClientVantagePoint,
            },
        };
        trace.EventSchemas.Add(new Uri("urn:ietf:params:qlog:events:quic"));
        file.Traces.Add(trace);

        string outputPath = InteropHarnessQlogWriter.CreateOutputPath(qlogDirectory, "client-handshake");
        Assert.True(InteropHarnessQlogWriter.TryWrite(outputPath, file, out string? errorMessage), errorMessage);
        Assert.EndsWith(".qlog", outputPath, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(outputPath));

        QlogFile roundTripped = QlogJsonSerializer.Deserialize(File.ReadAllText(outputPath));
        Assert.Single(roundTripped.Traces);
        Assert.Equal(QlogKnownValues.ContainedFileSchemaUri, roundTripped.FileSchema);
        Assert.Equal(QlogKnownValues.ContainedJsonSerializationFormat, roundTripped.SerializationFormat);
    }

    private sealed class CollectingDiagnosticsSink : IQuicDiagnosticsSink
    {
        public List<QuicDiagnosticEvent> Events { get; } = [];

        public bool IsEnabled => true;

        public void Emit(QuicDiagnosticEvent diagnosticEvent)
        {
            Events.Add(diagnosticEvent);
        }
    }
}
