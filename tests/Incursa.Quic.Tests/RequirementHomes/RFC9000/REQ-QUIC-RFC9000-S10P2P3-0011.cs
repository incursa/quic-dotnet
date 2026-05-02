using System;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P3-0006">A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or Handshake packets.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P3-0011">A CONNECTION_CLOSE frame of type 0x1d MUST be replaced by a CONNECTION_CLOSE frame of type 0x1c when sending the frame in Initial or Handshake packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2P3-0011")]
[Requirement("REQ-QUIC-RFC9000-S10P2P3-0006")]
public sealed class REQ_QUIC_RFC9000_S10P2P3_0011
{
    [Fact]
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
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
}
