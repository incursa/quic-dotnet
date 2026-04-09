namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0022")]
public sealed class REQ_QUIC_CRT_0022
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesTlsTransportParametersAndHandshakeCompletion()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 1);

        QuicTransportParameters localParameters = new()
        {
            MaxIdleTimeout = 15,
        };

        QuicTransportParameters peerSeedParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };

        Span<byte> encodedPeerParameters = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            peerSeedParameters,
            QuicTransportParameterRole.Server,
            encodedPeerParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedPeerParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters peerParameters));

        QuicConnectionTransitionResult localTransportResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.LocalTransportParametersReady,
                    TransportParameters: localParameters)),
            nowTicks: 10);

        Assert.True(localTransportResult.StateChanged);

        QuicConnectionTransitionResult serverHelloResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                    HandshakeMessageLength: 48,
                    SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                    TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                    TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)),
            nowTicks: 12);

        Assert.True(serverHelloResult.StateChanged);

        QuicConnectionTransitionResult stageResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 15,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                    HandshakeMessageLength: 48,
                    TransportParameters: peerParameters,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 15);

        Assert.True(stageResult.StateChanged);

        QuicConnectionTransitionResult certificateVerifyResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 16,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 16);

        Assert.True(certificateVerifyResult.StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 16,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 16).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 16,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 16).StateChanged);
        Assert.True(runtime.TlsState.PeerCertificatePolicyAccepted);

        QuicConnectionTransitionResult completedResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 25,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed)),
            nowTicks: 25);

        Assert.True(completedResult.StateChanged);

        QuicConnectionTransitionResult handshakeResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 30,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 30);

        Assert.True(handshakeResult.StateChanged);
        QuicConnectionTransitionResult peerTransportResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 35,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)),
            nowTicks: 35);

        Assert.True(peerTransportResult.StateChanged);
        QuicConnectionTransitionResult peerTransportCommitResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 40,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: peerParameters)),
            nowTicks: 40);

        Assert.True(peerTransportCommitResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));
        Assert.Equal(15UL, runtime.LocalMaxIdleTimeoutMicros);
        Assert.Equal(30UL, runtime.PeerMaxIdleTimeoutMicros);
        Assert.NotNull(runtime.IdleTimeoutState);
        Assert.Equal(15UL, runtime.IdleTimeoutState!.EffectiveIdleTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialAndHandshakeKeyDiscardsCleanSenderRuntimeState()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1200,
            SentAtMicros: 100,
            AckEliciting: true));
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 2,
            PayloadBytes: 1200,
            SentAtMicros: 200,
            AckEliciting: true));

        Assert.True(runtime.SendRuntime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 300,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));
        Assert.Equal(1, runtime.SendRuntime.ProbeTimeoutCount);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.KeysAvailable, QuicTlsEncryptionLevel.Initial)),
            nowTicks: 5).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 6,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.KeysAvailable, QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 6).StateChanged);

        QuicConnectionTransitionResult initialDiscardResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Initial)),
            nowTicks: 10);

        Assert.True(initialDiscardResult.StateChanged);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Equal(0, runtime.SendRuntime.ProbeTimeoutCount);
        Assert.Null(runtime.SendRuntime.LossDetectionDeadlineMicros);

        QuicConnectionTransitionResult handshakeDiscardResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 20,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 20);

        Assert.True(handshakeDiscardResult.StateChanged);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Empty(runtime.SendRuntime.SentPackets);
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
