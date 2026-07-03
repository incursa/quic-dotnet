// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-2-1-P4-S1-R01">An endpoint's selected connection ID and the QUIC version are sufficient information to identify packets for a closing connection; the endpoint MAY discard all other connection state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-2-1-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S10P2P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalCloseRequested_ClearsIdleTimeoutStateAndRetainsTheSelectedConnectionIdentity()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0).StateChanged);

        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
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

        Assert.Equal(path, send.PathIdentity);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(path, runtime.ActivePath.Value.Identity);
        Assert.False(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.TerminalState?.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LocalCloseRequested_WhileClosingDoesNotReplaceTheRetainedSelectedConnectionIdentity()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.71", RemotePort: 443);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0).StateChanged);

        QuicConnectionCloseMetadata firstClose = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                firstClose),
            nowTicks: 1);

        Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(firstResult.Effects, effect => effect is QuicConnectionSendDatagramEffect));

        long? closeLifetimeDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime);

        QuicConnectionTransitionResult secondResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 2,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "ignored")),
            nowTicks: 2);

        Assert.False(secondResult.StateChanged);
        Assert.Empty(secondResult.Effects);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.Equal(closeLifetimeDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.Equal(firstClose, runtime.TerminalState?.Close);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(path, runtime.ActivePath.Value.Identity);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: 4_096,
                connectionSendLimit: 4_096,
                localBidirectionalReceiveLimit: 4_096,
                peerBidirectionalReceiveLimit: 4_096,
                localBidirectionalSendLimit: 4_096,
                peerBidirectionalSendLimit: 4_096),
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
