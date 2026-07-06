// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_CloseErrorsMaxStreams_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0658")]
    [Requirement("REQ-QUIC-RFC9000-0659")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TransportErrorCodeFuzz_RoundTripsApplicableAndGenericCloseCodes()
    {
        foreach ((QuicTransportErrorCode ErrorCode, ulong TriggeringFrameType, byte[] ReasonPhrase) testCase in new (QuicTransportErrorCode, ulong, byte[])[]
        {
            (QuicTransportErrorCode.FlowControlError, 0x08UL, [0x66, 0x6C, 0x6F, 0x77]),
            (QuicTransportErrorCode.ProtocolViolation, 0x02UL, [0x70, 0x72, 0x6F, 0x74]),
            (QuicTransportErrorCode.InternalError, 0x02UL, [0x69, 0x6E, 0x74]),
        })
        {
            QuicConnectionCloseFrame frame = new(
                testCase.ErrorCode,
                testCase.TriggeringFrameType,
                testCase.ReasonPhrase);
            byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.False(parsed.IsApplicationError);
            Assert.Equal((byte)0x1C, parsed.FrameType);
            Assert.Equal((ulong)testCase.ErrorCode, parsed.ErrorCode);
            Assert.True(parsed.HasTriggeringFrameType);
            Assert.Equal(testCase.TriggeringFrameType, parsed.TriggeringFrameType);
            Assert.True(testCase.ReasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));

            byte[] destination = new byte[64];
            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination.AsSpan(0, bytesWritten)));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0665")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClosingRuntimeFuzz_RepliesToAdditionalAttributedPacketsWithConnectionClose()
    {
        foreach ((QuicTransportErrorCode ErrorCode, ulong TriggeringFrameType, string RemoteAddress) testCase in new (QuicTransportErrorCode, ulong, string)[]
        {
            (QuicTransportErrorCode.NoError, 0x00UL, "203.0.113.50"),
            (QuicTransportErrorCode.ProtocolViolation, 0x1CUL, "203.0.113.51"),
            (QuicTransportErrorCode.FlowControlError, 0x10UL, "203.0.113.52"),
        })
        {
            QuicConnectionRuntime runtime = CreateRuntime();
            QuicConnectionPathIdentity path = new(testCase.RemoteAddress, RemotePort: 443);

            runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 0,
                    path,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 0);
            runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: 1,
                    new QuicConnectionCloseMetadata(
                        testCase.ErrorCode,
                        ApplicationErrorCode: null,
                        testCase.TriggeringFrameType,
                        ReasonPhrase: null)),
                nowTicks: 1);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 2,
                    path,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 2);

            QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
                Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));
            Assert.Equal(path, send.PathIdentity);
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                send.Datagram.Span,
                out QuicConnectionCloseFrame parsedClose,
                out int bytesConsumed));
            Assert.Equal(send.Datagram.Length, bytesConsumed);
            Assert.Equal((ulong)testCase.ErrorCode, parsedClose.ErrorCode);
            Assert.Equal(testCase.TriggeringFrameType, parsedClose.TriggeringFrameType);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0804")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaxStreamsReleaseFuzz_UsesTheMatchingStreamTypeLimitInMaxStreamsFrames()
    {
        foreach ((bool Bidirectional, ulong PeerStreamId, byte StreamFrameType) testCase in new (bool, ulong, byte)[]
        {
            (true, 1UL, 0x0B),
            (false, 3UL, 0x0B),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                incomingBidirectionalStreamLimit: 1,
                incomingUnidirectionalStreamLimit: 1);
            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(testCase.StreamFrameType, testCase.PeerStreamId, streamData: []),
                out QuicStreamFrame frame));

            Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            if (testCase.Bidirectional)
            {
                Assert.True(state.TryAbortLocalStreamWrites(testCase.PeerStreamId, out ulong finalSize, out errorCode));
                Assert.Equal(default, errorCode);
                Assert.Equal(0UL, finalSize);
            }

            Assert.True(state.TryPeekPeerStreamCapacityRelease(testCase.PeerStreamId, out QuicMaxStreamsFrame releaseFrame));
            Assert.Equal(testCase.Bidirectional, releaseFrame.IsBidirectional);
            Assert.Equal(2UL, releaseFrame.MaximumStreams);

            Assert.True(state.TryCommitPeerStreamCapacityRelease(testCase.PeerStreamId, releaseFrame));
            Assert.Equal(
                2UL,
                testCase.Bidirectional ? state.IncomingBidirectionalStreamLimit : state.IncomingUnidirectionalStreamLimit);
        }
    }

    private static QuicConnectionRuntime CreateRuntime()
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
