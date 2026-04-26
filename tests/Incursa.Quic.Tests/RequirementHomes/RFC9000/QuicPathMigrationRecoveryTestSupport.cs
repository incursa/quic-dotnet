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
    ulong? RecoveryStartTimeMicros,
    ulong SmoothedRttMicros,
    ulong RttVarMicros,
    bool EcnValidated);

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

    internal static QuicConnectionRuntime CreateRuntime(IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            diagnosticsSink: diagnosticsSink);
    }

    internal static QuicConnectionRuntime CreateRuntimeWithActivePath(
        QuicConnectionPathIdentity activePath,
        IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        QuicConnectionRuntime runtime = CreateRuntime(diagnosticsSink);

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

        Assert.True(runtime.SendRuntime.RttEstimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 1_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            handshakeConfirmed: true));
        runtime.SendRuntime.EcnValidationState.DisableEcn();
    }

    internal static QuicPathMigrationRecoverySnapshot CaptureRecoveryState(QuicConnectionRuntime runtime)
    {
        QuicCongestionControlState congestionControlState = runtime.SendRuntime.FlowController.CongestionControlState;
        QuicConnectionPathRecoverySnapshot pathRecoverySnapshot = runtime.SendRuntime.CapturePathRecoverySnapshot();
        return new QuicPathMigrationRecoverySnapshot(
            SentPacketCount: runtime.SendRuntime.SentPackets.Count,
            PendingRetransmissionCount: runtime.SendRuntime.PendingRetransmissionCount,
            HasAckElicitingPacketsInFlight: runtime.SendRuntime.HasAckElicitingPacketsInFlight,
            LossDetectionDeadlineMicros: runtime.SendRuntime.LossDetectionDeadlineMicros,
            ProbeTimeoutCount: runtime.SendRuntime.ProbeTimeoutCount,
            CongestionWindowBytes: congestionControlState.CongestionWindowBytes,
            SlowStartThresholdBytes: congestionControlState.SlowStartThresholdBytes,
            BytesInFlightBytes: congestionControlState.BytesInFlightBytes,
            RecoveryStartTimeMicros: congestionControlState.RecoveryStartTimeMicros,
            SmoothedRttMicros: pathRecoverySnapshot.SmoothedRttMicros,
            RttVarMicros: pathRecoverySnapshot.RttVarMicros,
            EcnValidated: pathRecoverySnapshot.EcnValidated);
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

    internal static void CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerTransportParameters)
    {
        CommitPeerTransportParameters(runtime, peerTransportParameters);

        using QuicConnectionRuntime materialRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsPacketProtectionMaterial oneRttOpenPacketProtectionMaterial =
            materialRuntime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial oneRttProtectPacketProtectionMaterial =
            materialRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    EncryptionLevel: QuicTlsEncryptionLevel.OneRtt)),
            nowTicks: 0).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: oneRttOpenPacketProtectionMaterial)),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 2,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: oneRttProtectPacketProtectionMaterial)),
            nowTicks: 2).StateChanged);

        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    internal static void AssertChangedPeerAddressStartsPathValidationBeforePromotion(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity changedPeerAddressPath,
        long observedAtTicks)
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                observedAtTicks,
                changedPeerAddressPath,
                datagram),
            observedAtTicks);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            changedPeerAddressPath,
            out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == changedPeerAddressPath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    internal static void AssertPreviouslyValidatedPeerAddressBypassesAnotherValidationChallenge(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity firstValidatedPath,
        QuicConnectionPathIdentity secondValidatedPath)
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                firstValidatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(ValidatePath(
            runtime,
            firstValidatedPath,
            observedAtTicks: 30).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                secondValidatedPath,
                datagram),
            nowTicks: 40).StateChanged);

        Assert.True(ValidatePath(
            runtime,
            secondValidatedPath,
            observedAtTicks: 50).StateChanged);

        QuicConnectionTransitionResult reuseResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 60,
                firstValidatedPath,
                datagram),
            nowTicks: 60);

        Assert.True(reuseResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(firstValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(reuseResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == firstValidatedPath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
    }
}

internal sealed class QuicRecordingDiagnosticsSink : IQuicDiagnosticsSink
{
    public bool IsEnabled => true;

    public List<QuicDiagnosticEvent> Events { get; } = [];

    public void Emit(QuicDiagnosticEvent diagnosticEvent)
    {
        Events.Add(diagnosticEvent);
    }
}
