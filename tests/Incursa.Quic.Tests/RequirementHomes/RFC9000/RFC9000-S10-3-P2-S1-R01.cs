// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S10-3-P2-S1-R01">An endpoint that wishes to communicate a fatal connection error MUST use a CONNECTION_CLOSE frame if it is able.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-3-P2-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0604
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalCloseRequested_EmitsConnectionCloseWhenTheEndpointCanStillSend()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.90", RemotePort: 443);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0);

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
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.CloseLifetime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LocalCloseRequested_WithoutAnActivePathDoesNotEmitAConnectionCloseDatagram()
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
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.CloseLifetime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LocalCloseRequested_EmitsConnectionCloseForFatalErrorVariantsWhenAble()
    {
        QuicConnectionCloseMetadata[] cases =
        [
            new(
                TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
                ApplicationErrorCode: null,
                TriggeringFrameType: 0x06,
                ReasonPhrase: null),
            new(
                TransportErrorCode: QuicTransportErrorCode.FlowControlError,
                ApplicationErrorCode: null,
                TriggeringFrameType: 0x10,
                ReasonPhrase: "flow"),
            new(
                TransportErrorCode: null,
                ApplicationErrorCode: 42,
                TriggeringFrameType: null,
                ReasonPhrase: null),
            new(
                TransportErrorCode: null,
                ApplicationErrorCode: 0x1234,
                TriggeringFrameType: null,
                ReasonPhrase: "app"),
        ];

        for (int index = 0; index < cases.Length; index++)
        {
            QuicConnectionRuntime runtime = CreateRuntime();
            QuicConnectionPathIdentity path = new($"203.0.113.{100 + index}", RemotePort: 443 + index);

            runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 0,
                    path,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 0);

            QuicConnectionCloseMetadata closeMetadata = cases[index];
            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: 1,
                    closeMetadata),
                nowTicks: 1);

            QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
                Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));

            Assert.Equal(path, send.PathIdentity);
            AssertConnectionClosePayload(send.Datagram.Span, closeMetadata);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
            Assert.False(runtime.CanSendOrdinaryPackets);
            Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
            Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        }
    }

    private static void AssertConnectionClosePayload(
        ReadOnlySpan<byte> payload,
        QuicConnectionCloseMetadata closeMetadata)
    {
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
            payload,
            out QuicConnectionCloseFrame parsed,
            out int bytesConsumed));
        Assert.Equal(payload.Length, bytesConsumed);

        if (closeMetadata.ApplicationErrorCode.HasValue)
        {
            if (parsed.IsApplicationError)
            {
                Assert.Equal(closeMetadata.ApplicationErrorCode.Value, parsed.ErrorCode);
                Assert.False(parsed.HasTriggeringFrameType);
            }
            else
            {
                Assert.Equal((ulong)QuicTransportErrorCode.ApplicationError, parsed.ErrorCode);
            }
        }
        else
        {
            Assert.False(parsed.IsApplicationError);
            Assert.Equal((ulong)(closeMetadata.TransportErrorCode ?? QuicTransportErrorCode.NoError), parsed.ErrorCode);
            Assert.Equal(closeMetadata.TriggeringFrameType ?? 0, parsed.TriggeringFrameType);
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
