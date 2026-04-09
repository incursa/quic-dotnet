namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0023")]
public sealed class REQ_QUIC_CRT_0023
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimePhaseIsTheSourceOfTruthForOrdinarySendingLegality()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime activeRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        Assert.Equal(QuicConnectionSendingMode.Ordinary, activeRuntime.SendingMode);
        Assert.True(activeRuntime.CanSendOrdinaryPackets);

        activeRuntime.Transition(new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 0), nowTicks: 0);

        Assert.Equal(QuicConnectionPhase.Active, activeRuntime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, activeRuntime.SendingMode);
        Assert.True(activeRuntime.CanSendOrdinaryPackets);

        activeRuntime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "closing")),
            nowTicks: 1);

        Assert.Equal(QuicConnectionSendingMode.CloseOnly, activeRuntime.SendingMode);
        Assert.False(activeRuntime.CanSendOrdinaryPackets);

        QuicConnectionRuntime drainingRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        drainingRuntime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "peer close")),
            nowTicks: 2);

        Assert.Equal(QuicConnectionSendingMode.None, drainingRuntime.SendingMode);
        Assert.False(drainingRuntime.CanSendOrdinaryPackets);

        QuicConnectionRuntime discardedRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        discardedRuntime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "closing")),
            nowTicks: 3);

        long discardDueTicks = discardedRuntime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;
        discardedRuntime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: discardDueTicks,
                QuicConnectionTimerKind.CloseLifetime,
                Generation: discardedRuntime.TimerState.GetGeneration(QuicConnectionTimerKind.CloseLifetime)),
            nowTicks: discardDueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, discardedRuntime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, discardedRuntime.SendingMode);
        Assert.False(discardedRuntime.CanSendOrdinaryPackets);
    }
}
