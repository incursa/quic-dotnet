namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0104")]
public sealed class REQ_QUIC_CRT_0104
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NullDiagnosticsSinkIsCheapAndNoOpWhenDisabled()
    {
        QuicDiagnosticEvent diagnosticEvent = new(
            Category: "runtime",
            Name: "null",
            Message: "test",
            Severity: QuicDiagnosticSeverity.Info);

        Assert.False(QuicNullDiagnosticsSink.Instance.IsEnabled);
        QuicNullDiagnosticsSink.Instance.Emit(diagnosticEvent);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EnabledDiagnosticSinksCanStillReceiveStructuredEvents()
    {
        RecordingDiagnosticsSink sink = new();
        QuicDiagnosticEvent diagnosticEvent = new(
            Category: "runtime",
            Name: "structured",
            Message: "structured",
            Severity: QuicDiagnosticSeverity.Warning);

        sink.Emit(diagnosticEvent);

        Assert.True(sink.IsEnabled);
        Assert.Equal(1, sink.ReportCount);
        Assert.Equal("runtime", sink.LastEvent.Category);
        Assert.Equal("structured", sink.LastEvent.Name);
        Assert.Equal("structured", sink.LastEvent.Message);
        Assert.Equal(QuicDiagnosticSeverity.Warning, sink.LastEvent.Severity);
    }

    private sealed class RecordingDiagnosticsSink : IQuicDiagnosticsSink
    {
        public bool IsEnabled => true;

        public int ReportCount { get; private set; }

        public QuicDiagnosticEvent LastEvent { get; private set; }

        public void Emit(QuicDiagnosticEvent diagnosticEvent)
        {
            ReportCount++;
            LastEvent = diagnosticEvent;
        }
    }
}
