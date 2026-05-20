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
    private static readonly byte[] ConfirmedClientHandshakeDestinationConnectionId =
    [
        0x10, 0x11, 0x12, 0x13,
    ];

    private static readonly byte[] ConfirmedClientHandshakeSourceConnectionId =
    [
        0x14, 0x15, 0x16, 0x17,
    ];

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
        return CreateRuntimeWithActivePathBeforeHandshakeConfirmation(activePath, diagnosticsSink);
    }

    internal static QuicConnectionRuntime CreateRuntimeWithConfirmedHandshakeAndActivePath(
        QuicConnectionPathIdentity activePath,
        IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        return CreateRuntimeWithConfirmedHandshakeAndActivePath(
            activePath,
            new QuicTransportParameters
            {
                InitialSourceConnectionId = ConfirmedClientHandshakeSourceConnectionId.ToArray(),
            },
            diagnosticsSink);
    }

    internal static QuicConnectionRuntime CreateRuntimeWithConfirmedHandshakeAndActivePath(
        QuicConnectionPathIdentity activePath,
        QuicTransportParameters peerTransportParameters,
        IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
            activePath,
            peerTransportParameters,
            diagnosticsSink);

        Assert.True(QuicPostHandshakeTicketTestSupport.ReceiveProtectedHandshakeDonePacket(runtime, observedAtTicks: 3).StateChanged);
        Assert.True(runtime.HandshakeConfirmed);

        return runtime;
    }

    internal static QuicConnectionRuntime CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
        QuicConnectionPathIdentity activePath,
        QuicTransportParameters peerTransportParameters,
        IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePathBeforeHandshakeConfirmation(
            activePath,
            diagnosticsSink);

        ReadOnlySpan<byte> peerInitialSourceConnectionId = peerTransportParameters.InitialSourceConnectionId is { } initialSourceConnectionId
            ? initialSourceConnectionId
            : ConfirmedClientHandshakeDestinationConnectionId;

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(peerInitialSourceConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(ConfirmedClientHandshakeSourceConnectionId));
        CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            peerTransportParameters);
        ApplyCommittedPeerTransportParametersToRuntime(runtime, peerTransportParameters);

        return runtime;
    }

    internal static QuicConnectionRuntime CreateRuntimeWithActivePathBeforeHandshakeConfirmation(
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

    internal static QuicConnectionRuntime CreateServerRuntimeWithActivePath(
        QuicConnectionPathIdentity activePath,
        IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server,
            diagnosticsSink: diagnosticsSink);

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

    internal static QuicConnectionRuntime CreateServerRuntimeWithConfirmedHandshakeAndActivePath(
        QuicConnectionPathIdentity activePath,
        IQuicDiagnosticsSink? diagnosticsSink = null,
        ulong connectionSendLimit = 4096,
        ulong streamSendLimit = 4096)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionSendLimit: connectionSendLimit,
                localBidirectionalSendLimit: streamSendLimit,
                peerBidirectionalReceiveLimit: streamSendLimit),
            tlsRole: QuicTlsRole.Server,
            diagnosticsSink: diagnosticsSink);

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2).StateChanged);

        CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            new QuicTransportParameters
            {
                InitialSourceConnectionId = [],
                InitialMaxData = connectionSendLimit,
                InitialMaxStreamDataBidiLocal = streamSendLimit,
                InitialMaxStreamDataBidiRemote = streamSendLimit,
                InitialMaxStreamDataUni = streamSendLimit,
            });

        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
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

    internal static void ApplyCommittedPeerTransportParametersToRuntime(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerTransportParameters,
        long observedAtTicks = 2)
    {
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                observedAtTicks,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: peerTransportParameters)),
            nowTicks: observedAtTicks);

        Assert.Null(runtime.TerminalState);
        _ = result;
    }

    internal static void ApplyLocalActiveConnectionIdLimit(
        QuicConnectionRuntime runtime,
        ulong activeConnectionIdLimit,
        long observedAtTicks = 1)
    {
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                observedAtTicks,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.LocalTransportParametersReady,
                    TransportParameters: new QuicTransportParameters
                    {
                        ActiveConnectionIdLimit = activeConnectionIdLimit,
                    })),
            nowTicks: observedAtTicks);

        Assert.Null(runtime.TerminalState);
        _ = result;
    }

    internal static void AddUnusedPeerConnectionId(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber = 2,
        byte connectionIdStart = 0x80,
        long observedAtTicks = 10)
    {
        byte[] connectionId =
        [
            connectionIdStart,
            unchecked((byte)(connectionIdStart + 1)),
            unchecked((byte)(connectionIdStart + 2)),
            unchecked((byte)(connectionIdStart + 3)),
        ];

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber,
            retirePriorTo: 0,
            connectionId,
            observedAtTicks,
            statelessResetTokenStart: unchecked((byte)(connectionIdStart + 0x10)));

        Assert.True(result.StateChanged);
        Assert.Null(runtime.TerminalState);
    }

    internal static void AssertChangedPeerAddressStartsPathValidationBeforePromotion(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity changedPeerAddressPath,
        long observedAtTicks)
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
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
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            changedPeerAddressPath,
            runtime: runtime);
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
