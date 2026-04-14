namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0134")]
public sealed class REQ_QUIC_CRT_0134
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StructuredTransportDiagnosticsExposeTypedKindsAndPayloads()
    {
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.3",
            RemotePort: 443,
            LocalPort: 61234);

        byte[] initialPacketReceivedBytes = [0x01, 0x02, 0x03];
        byte[] initialPacketSentBytes = [0x04, 0x05, 0x06];
        byte[] retryReceivedBytes = [0x07, 0x08];
        byte[] versionNegotiationReceivedBytes = [0x09];

        QuicDiagnosticEvent initialPacketReceived = QuicDiagnostics.InitialPacketReceived(pathIdentity, initialPacketReceivedBytes);
        QuicDiagnosticEvent initialPacketSent = QuicDiagnostics.InitialPacketSent(pathIdentity, initialPacketSentBytes);
        QuicDiagnosticEvent retryReceived = QuicDiagnostics.RetryReceived(retryReceivedBytes);
        QuicDiagnosticEvent versionNegotiationReceived = QuicDiagnostics.VersionNegotiationReceived(versionNegotiationReceivedBytes);
        QuicDiagnosticEvent initialTranscriptAdvanced = QuicDiagnostics.TranscriptAdvanced(QuicTlsEncryptionLevel.Initial, 2);
        QuicDiagnosticEvent handshakeTranscriptAdvanced = QuicDiagnostics.TranscriptAdvanced(QuicTlsEncryptionLevel.Handshake, 5);
        QuicDiagnosticEvent addressChangeClassified = QuicDiagnostics.AddressChangeClassified(
            pathIdentity,
            QuicConnectionPathClassification.MigrationCandidate);

        Assert.Equal(QuicDiagnosticKind.InitialPacketReceived, initialPacketReceived.Kind);
        Assert.Equal(QuicDiagnosticSeverity.Trace, initialPacketReceived.Severity);
        Assert.Equal(pathIdentity, initialPacketReceived.PathIdentity);
        Assert.Contains("203.0.113.10:443", initialPacketReceived.Message, StringComparison.Ordinal);
        Assert.Equal(initialPacketReceivedBytes, initialPacketReceived.PacketBytes.ToArray());

        Assert.Equal(QuicDiagnosticKind.InitialPacketSent, initialPacketSent.Kind);
        Assert.Equal(QuicDiagnosticSeverity.Trace, initialPacketSent.Severity);
        Assert.Equal(pathIdentity, initialPacketSent.PathIdentity);
        Assert.Contains("203.0.113.10:443", initialPacketSent.Message, StringComparison.Ordinal);
        Assert.Equal(initialPacketSentBytes, initialPacketSent.PacketBytes.ToArray());

        Assert.Equal(QuicDiagnosticKind.RetryReceived, retryReceived.Kind);
        Assert.Equal(QuicDiagnosticSeverity.Trace, retryReceived.Severity);
        Assert.Equal(retryReceivedBytes, retryReceived.PacketBytes.ToArray());

        Assert.Equal(QuicDiagnosticKind.VersionNegotiationReceived, versionNegotiationReceived.Kind);
        Assert.Equal(QuicDiagnosticSeverity.Trace, versionNegotiationReceived.Severity);
        Assert.Equal(versionNegotiationReceivedBytes, versionNegotiationReceived.PacketBytes.ToArray());

        Assert.Equal(QuicDiagnosticKind.InitialTranscriptAdvanced, initialTranscriptAdvanced.Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, initialTranscriptAdvanced.EncryptionLevel);
        Assert.Equal(2, initialTranscriptAdvanced.TranscriptUpdateCount);

        Assert.Equal(QuicDiagnosticKind.HandshakeTranscriptAdvanced, handshakeTranscriptAdvanced.Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, handshakeTranscriptAdvanced.EncryptionLevel);
        Assert.Equal(5, handshakeTranscriptAdvanced.TranscriptUpdateCount);

        Assert.Equal(QuicDiagnosticKind.AddressChangeClassified, addressChangeClassified.Kind);
        Assert.Equal(QuicConnectionPathClassification.MigrationCandidate, addressChangeClassified.PathClassification);
        Assert.Equal(pathIdentity, addressChangeClassified.PathIdentity);

        RecordingDiagnosticsSink sink = new();
        sink.Emit(initialPacketReceived);
        sink.Emit(initialPacketSent);
        sink.Emit(retryReceived);
        sink.Emit(versionNegotiationReceived);
        sink.Emit(initialTranscriptAdvanced);
        sink.Emit(handshakeTranscriptAdvanced);
        sink.Emit(addressChangeClassified);

        Assert.True(sink.IsEnabled);
        Assert.Equal(7, sink.Events.Count);
        Assert.All(sink.Events, diagnosticEvent => Assert.NotEqual(QuicDiagnosticKind.Unknown, diagnosticEvent.Kind));

        Assert.False(QuicNullDiagnosticsSink.Instance.IsEnabled);
        QuicNullDiagnosticsSink.Instance.Emit(addressChangeClassified);
    }

    private sealed class RecordingDiagnosticsSink : IQuicDiagnosticsSink
    {
        public bool IsEnabled => true;

        public List<QuicDiagnosticEvent> Events { get; } = [];

        public void Emit(QuicDiagnosticEvent diagnosticEvent)
        {
            Events.Add(diagnosticEvent);
        }
    }
}
