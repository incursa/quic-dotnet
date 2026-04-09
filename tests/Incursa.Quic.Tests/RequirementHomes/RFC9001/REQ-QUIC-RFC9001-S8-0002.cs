namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S8-0002")]
public sealed class REQ_QUIC_RFC9001_S8_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeStateCommitsSnapshotsOnlyAfterPeerFinishedVerification()
    {
        QuicTransportParameters sourceParameters = CreatePeerTransportParameters();
        QuicTransportParameters parsedParameters = CreatePeerTransportParameters();

        QuicTransportTlsBridgeState bridge = new();

        Assert.False(bridge.CanCommitPeerTransportParameters(parsedParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: 48,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: 48,
            TransportParameters: parsedParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));

        Assert.False(bridge.CanCommitPeerTransportParameters(parsedParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));

        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.False(bridge.CanCommitPeerTransportParameters(parsedParameters));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(bridge.CanCommitPeerTransportParameters(parsedParameters));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: parsedParameters)));
        Assert.True(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));

        sourceParameters.InitialSourceConnectionId![0] = 0xFF;
        parsedParameters.InitialSourceConnectionId![0] = 0xEE;
        parsedParameters.PreferredAddress!.ConnectionId[0] = 0xDD;
        parsedParameters.PreferredAddress.StatelessResetToken[0] = 0xCC;

        Assert.NotSame(sourceParameters, bridge.PeerTransportParameters);
        Assert.NotSame(parsedParameters, bridge.PeerTransportParameters);
        Assert.True(bridge.PeerTransportParametersCommitted);
        Assert.True(bridge.PeerHandshakeTranscriptCompleted);
        Assert.Equal(30UL, bridge.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(bridge.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, bridge.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(new byte[] { 0x44, 0x55 }, bridge.PeerTransportParameters.PreferredAddress!.ConnectionId);
        Assert.Equal(new byte[] { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F }, bridge.PeerTransportParameters.PreferredAddress.StatelessResetToken);
        Assert.False(bridge.CanCommitPeerTransportParameters(parsedParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: parsedParameters)));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FatalTranscriptStateBlocksCommitAndTranscriptCompletion()
    {
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();

        QuicTransportTlsBridgeState bridge = new();
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: 48,
            TransportParameters: peerParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.FatalAlert, AlertDescription: 0x0032)));

        Assert.True(bridge.IsTerminal);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, bridge.HandshakeTranscriptPhase);
        Assert.False(bridge.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerParameters)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverRequiresPeerFinishedVerificationBeforeCommittingPeerTransportParameters()
    {
        QuicTransportParameters localParameters = CreateLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();

        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(localParameters));

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
            QuicTlsHandshakeMessageType.ServerHello,
            handshakeMessageLength: 48,
            selectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            transcriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256);

        Assert.Single(serverHelloUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, serverHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, serverHelloUpdates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, serverHelloUpdates[0].TranscriptHashAlgorithm);

        IReadOnlyList<QuicTlsStateUpdate> stageUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            QuicTlsHandshakeMessageType.EncryptedExtensions,
            handshakeMessageLength: 48,
            transportParameters: peerParameters);

        Assert.Single(stageUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, stageUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, stageUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, stageUpdates[0].TranscriptPhase);
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        Assert.Empty(driver.CommitPeerTransportParameters(peerParameters));

        IReadOnlyList<QuicTlsStateUpdate> completedUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.Completed,
            QuicTlsHandshakeMessageType.Finished,
            handshakeMessageLength: 48);

        Assert.Single(completedUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, completedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, completedUpdates[0].HandshakeMessageType);
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(driver.State.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(driver.State.CanCommitPeerTransportParameters(peerParameters));

        IReadOnlyList<QuicTlsStateUpdate> commitUpdates = driver.CommitPeerTransportParameters(peerParameters);
        Assert.Single(commitUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersCommitted, commitUpdates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersCommitted);
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.Equal(30UL, driver.State.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(driver.State.PeerTransportParameters.DisableActiveMigration);
    }

    private static QuicTransportParameters CreateLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [203, 0, 113, 7],
                IPv4Port = 9443,
                IPv6Address = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
                IPv6Port = 9553,
                ConnectionId = [0x44, 0x55],
                StatelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F],
            },
        };
    }
}
