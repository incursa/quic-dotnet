namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0003")]
public sealed class REQ_QUIC_INT_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TlsTransportStateTracksParametersKeysAndHandshakeCompletion()
    {
        QuicTransportParameters localParameters = new()
        {
            MaxIdleTimeout = 15,
        };

        QuicTransportParameters peerParameters = new()
        {
            DisableActiveMigration = true,
        };

        QuicTransportTlsBridgeState state = new();

        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localParameters)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: 48,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: 48,
            TransportParameters: peerParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
        Assert.True(state.PeerCertificatePolicyAccepted);
        Assert.False(state.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(state.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerParameters)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Initial)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeyUpdateInstalled,
            KeyPhase: 2)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysDiscarded,
            QuicTlsEncryptionLevel.Initial)));

        Assert.NotSame(localParameters, state.LocalTransportParameters);
        Assert.NotSame(peerParameters, state.PeerTransportParameters);
        Assert.Equal(localParameters.MaxIdleTimeout, state.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(peerParameters.DisableActiveMigration, state.PeerTransportParameters!.DisableActiveMigration);
        Assert.False(state.InitialKeysAvailable);
        Assert.True(state.HandshakeKeysAvailable);
        Assert.True(state.OneRttKeysAvailable);
        Assert.True(state.OldKeysDiscarded);
        Assert.True(state.PeerTransportParametersCommitted);
        Assert.True(state.PeerHandshakeTranscriptCompleted);
        Assert.Equal(2U, state.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesTlsHandshakeTranscriptCompletedUpdates()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                    HandshakeMessageLength: 48,
                    SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                    TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                    TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                    HandshakeMessageLength: 48,
                    TransportParameters: new QuicTransportParameters
                    {
                        DisableActiveMigration = true,
                    },
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 9).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 9).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 9).StateChanged);

        Assert.False(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: new QuicTransportParameters
                    {
                        DisableActiveMigration = true,
                    })),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed)),
            nowTicks: 9).StateChanged);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)),
            nowTicks: 10).StateChanged);
        Assert.Equal(QuicConnectionEventKind.TlsStateUpdated, result.EventKind);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: new QuicTransportParameters
                    {
                        DisableActiveMigration = true,
                    })),
            nowTicks: 10).StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
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
