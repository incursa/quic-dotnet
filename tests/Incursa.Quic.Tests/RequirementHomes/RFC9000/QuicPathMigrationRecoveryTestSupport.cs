namespace Incursa.Quic.Tests;

internal readonly record struct QuicPathMigrationRecoverySnapshot(
    int SentPacketCount,
    int PendingRetransmissionCount,
    bool HasAckElicitingPacketsInFlight,
    ulong? LossDetectionDeadlineMicros,
    int ProbeTimeoutCount,
    ulong CongestionWindowBytes,
    ulong SlowStartThresholdBytes,
    ulong BytesInFlightBytes,
    ulong? RecoveryStartTimeMicros);

internal static class QuicPathMigrationRecoveryTestSupport
{
    internal static QuicConnectionCloseMetadata CreateConnectionCloseMetadata()
    {
        return new QuicConnectionCloseMetadata(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);
    }

    internal static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
    }

    internal static QuicConnectionRuntime CreateRuntimeWithActivePath(QuicConnectionPathIdentity activePath)
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2).StateChanged);

        return runtime;
    }

    internal static void DirtyRecoveryState(QuicConnectionRuntime runtime)
    {
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 1_000,
            AckEliciting: true));

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 1_200,
            SentAtMicros: 1_100,
            AckEliciting: true));

        Assert.True(runtime.SendRuntime.FlowController.CongestionControlState.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.True(runtime.SendRuntime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            smoothedRttMicros: 900,
            rttVarMicros: 300,
            maxAckDelayMicros: 25,
            handshakeConfirmed: true));
    }

    internal static QuicPathMigrationRecoverySnapshot CaptureRecoveryState(QuicConnectionRuntime runtime)
    {
        QuicCongestionControlState congestionControlState = runtime.SendRuntime.FlowController.CongestionControlState;
        return new QuicPathMigrationRecoverySnapshot(
            SentPacketCount: runtime.SendRuntime.SentPackets.Count,
            PendingRetransmissionCount: runtime.SendRuntime.PendingRetransmissionCount,
            HasAckElicitingPacketsInFlight: runtime.SendRuntime.HasAckElicitingPacketsInFlight,
            LossDetectionDeadlineMicros: runtime.SendRuntime.LossDetectionDeadlineMicros,
            ProbeTimeoutCount: runtime.SendRuntime.ProbeTimeoutCount,
            CongestionWindowBytes: congestionControlState.CongestionWindowBytes,
            SlowStartThresholdBytes: congestionControlState.SlowStartThresholdBytes,
            BytesInFlightBytes: congestionControlState.BytesInFlightBytes,
            RecoveryStartTimeMicros: congestionControlState.RecoveryStartTimeMicros);
    }

    internal static QuicConnectionTransitionResult ValidatePath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        long observedAtTicks)
    {
        return runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity),
            nowTicks: observedAtTicks);
    }

    internal static void CommitPeerTransportParameters(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerTransportParameters)
    {
        QuicTransportTlsBridgeState bridge = runtime.TlsState;

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
            TransportParameters: peerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerTransportParameters)));

        Assert.True(bridge.PeerTransportParametersCommitted);
        Assert.NotNull(bridge.PeerTransportParameters);
    }
}
