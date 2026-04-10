namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0118")]
public sealed class REQ_QUIC_CRT_0118
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleBridgeStateKeepsCommitExplicitAndSeparateFromTranscriptCompletion()
    {
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Server);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localTransportParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
            HandshakeMessageLength: 96,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TransportParameters: peerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 32,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));

        Assert.False(bridge.PeerTransportParametersCommitted);
        Assert.False(bridge.PeerHandshakeTranscriptCompleted);
        Assert.False(bridge.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerTransportParameters)));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(bridge.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerTransportParameters)));

        Assert.True(bridge.PeerTransportParametersCommitted);
        Assert.False(bridge.PeerHandshakeTranscriptCompleted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleDriverPublishesCommitOnlyAfterInboundClientFinishedProof()
    {
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server);

        Assert.Single(driver.StartHandshake(localTransportParameters));
        Assert.True(driver.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
            HandshakeMessageLength: 96,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TransportParameters: peerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(driver.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(driver.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 32,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));

        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));

        Assert.True(driver.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));

        IReadOnlyList<QuicTlsStateUpdate> commitUpdates = driver.CommitPeerTransportParameters(peerTransportParameters);
        Assert.Single(commitUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersCommitted, commitUpdates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersCommitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleCommitRejectsRepeatedConflictingFatalAndMismatchedAttemptsDeterministically()
    {
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTransportParameters mismatchedPeerTransportParameters = CreateClientTransportParameters();
        mismatchedPeerTransportParameters.MaxIdleTimeout++;

        QuicTransportTlsBridgeState bridge = CreateServerProofedBridgeState(peerTransportParameters);

        Assert.False(bridge.CanCommitPeerTransportParameters(mismatchedPeerTransportParameters));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: mismatchedPeerTransportParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerTransportParameters)));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerTransportParameters)));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: mismatchedPeerTransportParameters)));

        QuicTransportTlsBridgeState terminalBridge = CreateServerProofedBridgeState(peerTransportParameters);
        Assert.True(terminalBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.FatalAlert,
            AlertDescription: 0x0032)));
        Assert.True(terminalBridge.IsTerminal);
        Assert.False(terminalBridge.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.False(terminalBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerTransportParameters)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleRuntimeConsumesCommitWithoutImplyingTranscriptCompletion()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            tlsRole: QuicTlsRole.Server);
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
                    HandshakeMessageLength: 96,
                    SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                    TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                    TransportParameters: peerTransportParameters,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 2,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                    HandshakeMessageLength: 32,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed)),
            nowTicks: 2).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 3,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 3).StateChanged);

        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.TlsState.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
    }

    private static QuicTransportTlsBridgeState CreateServerProofedBridgeState(QuicTransportParameters peerTransportParameters)
    {
        QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Server);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: CreateBootstrapLocalTransportParameters())));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
            HandshakeMessageLength: 96,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TransportParameters: peerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 32,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        return bridge;
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreateClientTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
