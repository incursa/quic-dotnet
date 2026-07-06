// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_ConnectionCloseIdle_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0554")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void IdleTimeoutPtoFloorFuzz_UsesAtLeastThreeTimesTheCurrentProbeTimeout()
    {
        foreach ((ulong? Local, ulong? Peer, ulong Pto) testCase in new (ulong?, ulong?, ulong)[]
        {
            (1, null, 1),
            (10, 20, 4),
            (100, 80, 40),
            (null, 50, 20),
            (ulong.MaxValue, null, 7),
            (1, 2, (ulong.MaxValue / 3) + 1),
        })
        {
            Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
                testCase.Local,
                testCase.Peer,
                testCase.Pto,
                out ulong effectiveIdleTimeoutMicros));

            ulong expectedFloor = testCase.Pto > ulong.MaxValue / 3
                ? ulong.MaxValue
                : testCase.Pto * 3;
            ulong advertised = SelectAdvertisedTimeout(testCase.Local, testCase.Peer);
            Assert.Equal(Math.Max(advertised, expectedFloor), effectiveIdleTimeoutMicros);
            Assert.True(effectiveIdleTimeoutMicros >= expectedFloor);
        }

        Assert.False(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: 1,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0562")]
    [Requirement("REQ-QUIC-RFC9000-0572")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ImmediateCloseFuzz_EmitsConnectionCloseAndEntersClosingState()
    {
        foreach (QuicTransportErrorCode errorCode in new[]
        {
            QuicTransportErrorCode.NoError,
            QuicTransportErrorCode.ProtocolViolation,
            QuicTransportErrorCode.FlowControlError,
        })
        {
            QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
            QuicConnectionCloseMetadata closeMetadata = new(
                TransportErrorCode: errorCode,
                ApplicationErrorCode: null,
                TriggeringFrameType: 0x1c,
                ReasonPhrase: null);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: 1,
                    closeMetadata),
                nowTicks: 1);

            QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
                Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                send.Datagram.Span,
                out QuicConnectionCloseFrame closeFrame,
                out int bytesConsumed));
            Assert.Equal(send.Datagram.Length, bytesConsumed);
            Assert.Equal((ulong)errorCode, closeFrame.ErrorCode);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
            Assert.False(runtime.CanSendOrdinaryPackets);
            Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
            Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        }

        QuicConnectionLifecycleState lifecycle = new();
        Assert.True(lifecycle.TryEnterClosingState());
        Assert.True(lifecycle.IsClosing);
        Assert.False(lifecycle.CanSendPackets);
        Assert.False(lifecycle.TryEnterClosingState());
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            currentProbeTimeoutMicros: 100);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 200,
                PeerMaxIdleTimeoutMicros: 200,
                CurrentProbeTimeoutMicros: 100),
            nowTicks: 0);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                PathIdentity: new QuicConnectionPathIdentity("203.0.113.60", RemotePort: 443),
                Datagram: new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0);

        return runtime;
    }

    private static ulong SelectAdvertisedTimeout(ulong? local, ulong? peer)
    {
        if (local is > 0 && peer is > 0)
        {
            return Math.Min(local.Value, peer.Value);
        }

        return local is > 0 ? local.Value : peer!.Value;
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
