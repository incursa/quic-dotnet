using System;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0019">When an application wishes to abandon a connection during the handshake, an endpoint MAY send a CONNECTION_CLOSE frame (type 0x1c) with an error code of APPLICATION_ERROR in an Initial or Handshake packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P19-0019")]
public sealed class REQ_QUIC_RFC9000_S19P19_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalCloseRequestedDuringEstablishment_UsesTransportApplicationErrorClose()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.71", RemotePort: 443);

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
