namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0107")]
public sealed class REQ_QUIC_CRT_0107
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TranscriptProgressStagesPeerTransportParametersOnlyAfterACompleteHandshakeMessage()
    {
        byte[] transcript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

        QuicTlsTranscriptProgress progress = new();
        progress.AppendCryptoBytes(offset: 0, transcript.AsSpan(0, 5));

        Assert.Equal(5UL, progress.IngressCursor);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, progress.Phase);
        Assert.Null(progress.StagedPeerTransportParameters);
        Assert.Equal(QuicTlsTranscriptStepKind.None, progress.Advance(QuicTlsRole.Client).Kind);

        progress.AppendCryptoBytes(offset: 5, transcript.AsSpan(5));
        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, step.Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, progress.Phase);
        Assert.NotNull(step.TransportParameters);
        Assert.Equal(30UL, step.TransportParameters!.MaxIdleTimeout);
        Assert.True(step.TransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, step.TransportParameters.InitialSourceConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TranscriptProgressLeavesTruncatedHandshakeMessagesIncomplete()
    {
        byte[] transcript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

        QuicTlsTranscriptProgress progress = new();
        progress.AppendCryptoBytes(offset: 0, transcript.AsSpan(0, transcript.Length - 1));

        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.None, step.Kind);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, progress.Phase);
        Assert.True(progress.HasPendingBytes);
        Assert.False(progress.IsTerminalFailure);
        Assert.Null(progress.TerminalAlertDescription);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TranscriptProgressRejectsFurtherProgressAfterDeterministicCompletion()
    {
        byte[] transcript = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

        QuicTlsTranscriptProgress progress = new();
        progress.AppendCryptoBytes(offset: 0, transcript);

        QuicTlsTranscriptStep firstStep = progress.Advance(QuicTlsRole.Client);
        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, firstStep.Kind);
        Assert.True(progress.MarkPeerTransportParametersAuthenticated());
        Assert.Equal(QuicTlsTranscriptPhase.Completed, progress.Phase);

        progress.AppendCryptoBytes(offset: progress.IngressCursor, transcript);
        QuicTlsTranscriptStep repeatedStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, repeatedStep.Kind);
        Assert.Equal((ushort)0x0010, repeatedStep.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TranscriptProgressRoutesMalformedHandshakeMessagesToAFatalAlert()
    {
        QuicTlsTranscriptProgress progress = new();
        progress.AppendCryptoBytes(offset: 0, [0x08, 0x00, 0x00, 0x03, 0x00, 0x02, 0x12]);

        QuicTlsTranscriptStep step = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, step.Kind);
        Assert.Equal((ushort)0x0032, step.AlertDescription);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, progress.Phase);
        Assert.True(progress.IsTerminalFailure);
        Assert.Equal((ushort)0x0032, progress.TerminalAlertDescription);
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
        };
    }

    private static byte[] CreateFormattedTransportParameters(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int bytesWritten));

        return encodedTransportParameters[..bytesWritten];
    }

    private static byte[] CreateEncryptedExtensionsTranscript(ReadOnlySpan<byte> encodedTransportParameters)
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicTransportParametersMessage(
            parameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int bytesWritten));

        Array.Resize(ref transcript, bytesWritten);
        return transcript;
    }
}
