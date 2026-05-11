using System;
using System.Linq;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P3-0006">A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or Handshake packets.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P3-0011">A CONNECTION_CLOSE frame of type 0x1d MUST be replaced by a CONNECTION_CLOSE frame of type 0x1c when sending the frame in Initial or Handshake packets.</workbench-requirement>
/// </workbench-requirements>
public sealed class REQ_QUIC_RFC9000_S10P2P3_0011
{
    private static readonly byte[] InitialDestinationConnectionId = QuicS17P2P3TestSupport.InitialDestinationConnectionId;
    private static readonly byte[] InitialSourceConnectionId = QuicS17P2P3TestSupport.InitialSourceConnectionId;
    private static readonly byte[] ServerSourceConnectionId = [0x51, 0x52, 0x53, 0x54];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0006")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalCloseRequestedDuringEstablishment_UsesTransportApplicationErrorClose()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.73", RemotePort: 443);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ApplicationError,
            ApplicationErrorCode: null,
            TriggeringFrameType: null,
            ReasonPhrase: null);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));

        QuicConnectionCloseFrame expectedClose = new(
            QuicTransportErrorCode.ApplicationError,
            triggeringFrameType: 0,
            []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(send.Datagram.Span, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.False(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1C, parsedFrame.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.ApplicationError, parsedFrame.ErrorCode);
        Assert.Equal(0UL, parsedFrame.TriggeringFrameType);
        Assert.Equal(send.Datagram.Length, bytesConsumed);
        Assert.True(send.Datagram.Span.SequenceEqual(QuicFrameTestData.BuildConnectionCloseFrame(expectedClose)));
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void LocalCloseRequestedBeforeHandshakeConfirmation_ServerSendsInitialAndHandshakeCloses()
    {
        PreConfirmationCloseSend close = CreatePreConfirmationApplicationCloseSend();

        Assert.Equal(3, close.SendEffects.Length);
        AssertDowngradedApplicationClosePayload(OpenInitialClosePayload(
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Initial).Datagram));
        AssertDowngradedApplicationClosePayload(OpenHandshakeClosePayload(
            close.Runtime,
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Handshake).Datagram));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void LocalCloseRequestedBeforeHandshakeConfirmation_SendsHandshakeAndOneRttCloses()
    {
        PreConfirmationCloseSend close = CreatePreConfirmationApplicationCloseSend();

        Assert.Equal(3, close.SendEffects.Length);
        AssertDowngradedApplicationClosePayload(OpenHandshakeClosePayload(
            close.Runtime,
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Handshake).Datagram));
        AssertApplicationClosePayload(OpenApplicationClosePayload(
            close.Runtime,
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.ApplicationData).Datagram));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0006")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void LocalCloseRequestedBeforeHandshakeConfirmation_DowngradesApplicationCloseInInitialAndHandshake()
    {
        PreConfirmationCloseSend close = CreatePreConfirmationApplicationCloseSend();

        AssertDowngradedApplicationClosePayload(OpenInitialClosePayload(
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Initial).Datagram));
        AssertDowngradedApplicationClosePayload(OpenHandshakeClosePayload(
            close.Runtime,
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Handshake).Datagram));
        AssertApplicationClosePayload(OpenApplicationClosePayload(
            close.Runtime,
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.ApplicationData).Datagram));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalCloseRequestedBeforeHandshakeConfirmation_ClearsReasonPhraseWhenDowngrading()
    {
        PreConfirmationCloseSend close = CreatePreConfirmationApplicationCloseSend();

        AssertDowngradedApplicationClosePayloadHasEmptyReasonPhrase(OpenInitialClosePayload(
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Initial).Datagram));
        AssertDowngradedApplicationClosePayloadHasEmptyReasonPhrase(OpenHandshakeClosePayload(
            close.Runtime,
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Handshake).Datagram));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalCloseRequestedBeforeHandshakeConfirmation_UsesApplicationErrorWhenDowngrading()
    {
        PreConfirmationCloseSend close = CreatePreConfirmationApplicationCloseSend();

        AssertDowngradedApplicationClosePayloadUsesApplicationError(OpenInitialClosePayload(
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Initial).Datagram));
        AssertDowngradedApplicationClosePayloadUsesApplicationError(OpenHandshakeClosePayload(
            close.Runtime,
            AssertSingleSendByPacketNumberSpace(close.SendEffects, QuicPacketNumberSpace.Handshake).Datagram));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0006")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void LocalCloseRequestedAfterOneRttKeepsTheApplicationCloseFrameType()
    {
        (QuicConnectionRuntime runtime, QuicConnectionSendDatagramEffect send) = CreateOneRttApplicationCloseSend();

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            send.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal(0UL, parsedFrame.ErrorCode);
        Assert.Equal((byte)0x1D, parsedFrame.FrameType);
        Assert.True(payload[bytesConsumed..].SequenceEqual(new byte[payloadLength - bytesConsumed]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void LocalCloseRequestedWithoutAnActivePathStillTransitionsToClosingWithoutSendingDatagram()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: null,
            ApplicationErrorCode: 42,
            TriggeringFrameType: null,
            ReasonPhrase: null);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        Assert.Null(runtime.ActivePath);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.CloseLifetime);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    private static PreConfirmationCloseSend CreatePreConfirmationApplicationCloseSend()
    {
        QuicConnectionRuntime runtime = CreatePreConfirmationServerRuntimeWithCloseKeys();

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: null,
            ApplicationErrorCode: 42,
            TriggeringFrameType: null,
            ReasonPhrase: "must not be sent below 1-RTT");

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 10,
                closeMetadata),
            nowTicks: 10);

        QuicConnectionSendDatagramEffect[] sendEffects = result.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        return new PreConfirmationCloseSend(runtime, sendEffects);
    }

    private static (QuicConnectionRuntime Runtime, QuicConnectionSendDatagramEffect Send) CreateOneRttApplicationCloseSend()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        QuicConnectionPathIdentity pathIdentity = new("203.0.113.74", RemotePort: 443);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: null,
            ApplicationErrorCode: 0,
            TriggeringFrameType: null,
            ReasonPhrase: null);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 10,
                closeMetadata),
            nowTicks: 10);

        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));
        Assert.Equal(runtime.ActivePath.Value.Identity, send.PathIdentity);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        return (runtime, send);
    }

    private static QuicConnectionRuntime CreatePreConfirmationServerRuntimeWithCloseKeys()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 100,
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(InitialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(InitialSourceConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(ServerSourceConnectionId));

        QuicConnectionPathIdentity path = new("203.0.113.75", RemotePort: 443);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0).StateChanged);

        SeedProtectPacketProtectionMaterial(
            runtime,
            QuicTlsEncryptionLevel.Handshake,
            QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
            observedAtTicks: 1);
        SeedProtectPacketProtectionMaterial(
            runtime,
            QuicTlsEncryptionLevel.OneRtt,
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            observedAtTicks: 3);

        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out _));
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        return runtime;
    }

    private static void SeedProtectPacketProtectionMaterial(
        QuicConnectionRuntime runtime,
        QuicTlsEncryptionLevel encryptionLevel,
        QuicTlsUpdateKind materialUpdateKind,
        long observedAtTicks)
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            encryptionLevel,
            out QuicTlsPacketProtectionMaterial material));

        if (encryptionLevel == QuicTlsEncryptionLevel.OneRtt)
        {
            MarkPeerFinishedVerifiedWithoutConfirmingHandshake(runtime);
        }

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: observedAtTicks,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    EncryptionLevel: encryptionLevel)),
            nowTicks: observedAtTicks).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: observedAtTicks + 1,
                new QuicTlsStateUpdate(
                    materialUpdateKind,
                    PacketProtectionMaterial: material)),
            nowTicks: observedAtTicks + 1).StateChanged);
    }

    private static void MarkPeerFinishedVerifiedWithoutConfirmingHandshake(QuicConnectionRuntime runtime)
    {
        typeof(QuicTransportTlsBridgeState)
            .GetProperty(nameof(QuicTransportTlsBridgeState.PeerFinishedVerified))!
            .SetValue(runtime.TlsState, true);
    }

    private static QuicConnectionSendDatagramEffect AssertSingleSendByPacketNumberSpace(
        QuicConnectionSendDatagramEffect[] sendEffects,
        QuicPacketNumberSpace packetNumberSpace)
    {
        return Assert.Single(sendEffects, effect =>
            QuicPacketParser.TryGetPacketNumberSpace(effect.Datagram.Span, out QuicPacketNumberSpace observedPacketNumberSpace)
            && observedPacketNumberSpace == packetNumberSpace);
    }

    private static byte[] OpenInitialClosePayload(ReadOnlyMemory<byte> datagram)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, ServerSourceConnectionId);
        Assert.True(coordinator.TryOpenOutboundInitialPacket(
            datagram.Span,
            protection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    private static byte[] OpenHandshakeClosePayload(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(
            out QuicTlsPacketProtectionMaterial handshakeMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(InitialSourceConnectionId, ServerSourceConnectionId);
        Assert.True(coordinator.TryOpenHandshakePacket(
            datagram.Span,
            handshakeMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    private static byte[] OpenApplicationClosePayload(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    private static void AssertDowngradedApplicationClosePayload(ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
            payload,
            out QuicConnectionCloseFrame parsedFrame,
            out int bytesConsumed));
        Assert.False(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1C, parsedFrame.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.ApplicationError, parsedFrame.ErrorCode);
        Assert.Equal(0UL, parsedFrame.TriggeringFrameType);
        Assert.True(parsedFrame.ReasonPhrase.IsEmpty);
        Assert.True(payload[bytesConsumed..].SequenceEqual(new byte[payload.Length - bytesConsumed]));
    }

    private static void AssertDowngradedApplicationClosePayloadHasEmptyReasonPhrase(ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
            payload,
            out QuicConnectionCloseFrame parsedFrame,
            out int bytesConsumed));
        Assert.False(parsedFrame.IsApplicationError);
        Assert.True(parsedFrame.ReasonPhrase.IsEmpty);
        Assert.True(payload[bytesConsumed..].SequenceEqual(new byte[payload.Length - bytesConsumed]));
    }

    private static void AssertDowngradedApplicationClosePayloadUsesApplicationError(ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
            payload,
            out QuicConnectionCloseFrame parsedFrame,
            out int bytesConsumed));
        Assert.False(parsedFrame.IsApplicationError);
        Assert.Equal((ulong)QuicTransportErrorCode.ApplicationError, parsedFrame.ErrorCode);
        Assert.True(payload[bytesConsumed..].SequenceEqual(new byte[payload.Length - bytesConsumed]));
    }

    private static void AssertApplicationClosePayload(ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
            payload,
            out QuicConnectionCloseFrame parsedFrame,
            out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1D, parsedFrame.FrameType);
        Assert.Equal(42UL, parsedFrame.ErrorCode);
        Assert.False(parsedFrame.ReasonPhrase.IsEmpty);
        Assert.True(payload[bytesConsumed..].SequenceEqual(new byte[payload.Length - bytesConsumed]));
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 100);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 200,
                PeerMaxIdleTimeoutMicros: 200,
                CurrentProbeTimeoutMicros: 100),
            nowTicks: 0);

        return runtime;
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

    private readonly record struct PreConfirmationCloseSend(
        QuicConnectionRuntime Runtime,
        QuicConnectionSendDatagramEffect[] SendEffects);
}
