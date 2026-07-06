// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1366">When an application wishes to abandon a connection during the handshake, an endpoint MAY send a CONNECTION_CLOSE frame (type 0x1c) with an error code of APPLICATION_ERROR in an Initial or Handshake packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1366")]
public sealed class REQ_QUIC_RFC9000_1366
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ApplicationSpecificConnectionClosePayloadIsNotTheHandshakeAbandonForm()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(
            errorCode: (ulong)QuicTransportErrorCode.ApplicationError,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1D, parsedFrame.FrameType);
        Assert.NotEqual((byte)0x1C, parsedFrame.FrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LocalCloseRequestedDuringEstablishment_FuzzUsesTransportCloseApplicationErrorForm()
    {
        for (long observedAtTicks = 1; observedAtTicks <= 4; observedAtTicks++)
        {
            QuicConnectionRuntime runtime = CreateRuntime();
            QuicConnectionPathIdentity path = new("203.0.113.71", RemotePort: 443);

            runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 0,
                    path,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 0);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    observedAtTicks,
                    new QuicConnectionCloseMetadata(
                        QuicTransportErrorCode.ApplicationError,
                        ApplicationErrorCode: null,
                        TriggeringFrameType: null,
                        ReasonPhrase: null)),
                nowTicks: observedAtTicks);

            QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
                Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(send.Datagram.Span, out QuicConnectionCloseFrame parsedFrame, out _));
            Assert.False(parsedFrame.IsApplicationError);
            Assert.Equal((byte)0x1C, parsedFrame.FrameType);
            Assert.Equal((ulong)QuicTransportErrorCode.ApplicationError, parsedFrame.ErrorCode);
        }
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
