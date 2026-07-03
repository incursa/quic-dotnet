// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S10-2-1-P3-S1-R01">An endpoint SHOULD limit the rate at which it generates packets in the closing state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-2-1-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0576
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosingRuntimeRepliesBeforeTheCloseLifetimeExpires()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity path) = CreateRuntime();

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: dueTicks - 1,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: dueTicks - 1);

        QuicConnectionCloseFrame expectedClose = new(
            QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x1c,
            []);
        byte[] expectedDatagram = QuicFrameTestData.BuildConnectionCloseFrame(expectedClose);
        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));

        Assert.Equal(path, send.PathIdentity);
        Assert.True(expectedDatagram.AsSpan().SequenceEqual(send.Datagram.Span));
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PacketsAfterCloseLifetimeExpiryDoNotTriggerAnotherCloseReply()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity path) = CreateRuntime();

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.CloseLifetime);

        runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                QuicConnectionTimerKind.CloseLifetime,
                generation),
            nowTicks: dueTicks);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: dueTicks + 1,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: dueTicks + 1);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(result.StateChanged);
        Assert.Empty(result.Effects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CloseLifetimeExpiryDiscardsTheConnection()
    {
        (QuicConnectionRuntime runtime, _) = CreateRuntime();

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.CloseLifetime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                QuicConnectionTimerKind.CloseLifetime,
                generation),
            nowTicks: dueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    private static (QuicConnectionRuntime Runtime, QuicConnectionPathIdentity Path) CreateRuntime()
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

        QuicConnectionPathIdentity path = new("203.0.113.60", RemotePort: 443);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0);

        return (runtime, path);
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
