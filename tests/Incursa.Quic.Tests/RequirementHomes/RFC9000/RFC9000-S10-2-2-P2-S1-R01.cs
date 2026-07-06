// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S10-2-2-P2-S1-R01")]
public sealed class RFC9000_S10_2_2_P2_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceivedConnectionCloseFrame_EmitsANoErrorReplyBeforeDraining()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.40", RemotePort: 443);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0);

        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "peer close");

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        QuicConnectionCloseFrame expectedReply = new(
            QuicTransportErrorCode.NoError,
            triggeringFrameType: 0x1c,
            []);
        byte[] expectedDatagram = QuicFrameTestData.BuildConnectionCloseFrame(expectedReply);
        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState?.Origin);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.Equal(path, send.PathIdentity);
        Assert.True(expectedDatagram.AsSpan().SequenceEqual(send.Datagram.Span));
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.DrainLifetime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReceivedConnectionCloseFrame_WhileAlreadyDrainingDoesNotEmitAnotherClosePacket()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.41", RemotePort: 443);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0);

        runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 1,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "peer close")),
            nowTicks: 1);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 2,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "peer close")),
            nowTicks: 2);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ReceivedConnectionCloseFrame_WithoutAmplificationBudgetStillEntersDrainingWithoutReply()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.42", RemotePort: 443);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                ReadOnlyMemory<byte>.Empty),
            nowTicks: 0);

        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "no budget");

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Equal(0UL, runtime.ActivePath!.Value.AmplificationState.SentPayloadBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ReceivedConnectionCloseSendsAtMostOneNoErrorReplyBeforeDraining()
    {
        foreach ((int index, int receivedDatagramLength, QuicTransportErrorCode peerErrorCode, string reasonPhrase, bool expectReply) in new[]
        {
            (0, QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, QuicTransportErrorCode.ProtocolViolation, "peer protocol close", true),
            (1, QuicVersionNegotiation.Version1MinimumDatagramPayloadSize + 64, QuicTransportErrorCode.NoError, "peer no-error close", true),
            (2, 1, QuicTransportErrorCode.InternalError, "amplification constrained", false),
            (3, 0, QuicTransportErrorCode.FlowControlError, "no amplification budget", false),
        })
        {
            QuicConnectionRuntime runtime = CreateRuntime();
            QuicConnectionPathIdentity path = new($"203.0.113.{50 + index}", RemotePort: 443 + index);

            runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 0,
                    path,
                    receivedDatagramLength == 0
                        ? ReadOnlyMemory<byte>.Empty
                        : new byte[receivedDatagramLength]),
                nowTicks: 0);

            QuicConnectionCloseMetadata closeMetadata = new(
                peerErrorCode,
                ApplicationErrorCode: null,
                TriggeringFrameType: 0x1c,
                ReasonPhrase: reasonPhrase);

            QuicConnectionTransitionResult firstCloseResult = runtime.Transition(
                new QuicConnectionConnectionCloseFrameReceivedEvent(
                    ObservedAtTicks: 1,
                    closeMetadata),
                nowTicks: 1);

            QuicConnectionSendDatagramEffect[] firstCloseSends = firstCloseResult.Effects
                .OfType<QuicConnectionSendDatagramEffect>()
                .ToArray();

            Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
            Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
            Assert.False(runtime.CanSendOrdinaryPackets);
            Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState?.Origin);
            Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
            Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
            Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));

            if (expectReply)
            {
                QuicConnectionSendDatagramEffect send = Assert.Single(firstCloseSends);
                QuicConnectionCloseFrame expectedReply = new(
                    QuicTransportErrorCode.NoError,
                    triggeringFrameType: 0x1c,
                    []);
                byte[] expectedDatagram = QuicFrameTestData.BuildConnectionCloseFrame(expectedReply);
                Assert.Equal(path, send.PathIdentity);
                Assert.True(expectedDatagram.AsSpan().SequenceEqual(send.Datagram.Span));
            }
            else
            {
                Assert.Empty(firstCloseSends);
            }

            QuicConnectionTransitionResult secondCloseResult = runtime.Transition(
                new QuicConnectionConnectionCloseFrameReceivedEvent(
                    ObservedAtTicks: 2,
                    closeMetadata),
                nowTicks: 2);

            Assert.DoesNotContain(secondCloseResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
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
