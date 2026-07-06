// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P14_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamLimitExhaustionReturnsStreamsBlockedWithoutOpeningTheBlockedStream()
    {
        foreach ((bool bidirectional, ulong streamLimit, ulong firstStreamId, ulong blockedStreamId) in new[]
        {
            (true, 0UL, 0UL, 0UL),
            (true, 1UL, 0UL, 4UL),
            (true, 2UL, 0UL, 8UL),
            (false, 0UL, 2UL, 2UL),
            (false, 1UL, 2UL, 6UL),
            (false, 2UL, 2UL, 10UL),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                peerBidirectionalStreamLimit: bidirectional ? streamLimit : 4UL,
                peerUnidirectionalStreamLimit: bidirectional ? 4UL : streamLimit);

            if (streamLimit > 0)
            {
                for (ulong index = 0; index < streamLimit; index++)
                {
                    Assert.True(state.TryOpenLocalStream(
                        bidirectional,
                        out QuicStreamId openedStreamId,
                        out QuicStreamsBlockedFrame openedBlockedFrame));
                    Assert.Equal(default, openedBlockedFrame);
                    Assert.Equal(firstStreamId + (index * 4), openedStreamId.Value);
                }
            }

            Assert.False(state.TryOpenLocalStream(
                bidirectional,
                out QuicStreamId blockedStream,
                out QuicStreamsBlockedFrame blockedFrame));

            Assert.Equal(default, blockedStream);
            Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
            Assert.Equal(streamLimit, blockedFrame.MaximumStreams);
            Assert.False(state.TryGetStreamSnapshot(blockedStreamId, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamsBlockedMaximumStreamsValuesAtOrBelowTheEncodingLimitRoundTrip()
    {
        foreach ((bool bidirectional, ulong maximumStreams) in new[]
        {
            (true, 0UL),
            (false, 0UL),
            (true, 1UL),
            (false, 63UL),
            (true, QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit - 1),
            (false, QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit),
        })
        {
            byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(
                bidirectional,
                maximumStreams);

            QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(
                encoded,
                bidirectional,
                maximumStreams);
            QuicS19P14StreamsBlockedFrameTestSupport.AssertFormats(
                new QuicStreamsBlockedFrame(bidirectional, maximumStreams),
                encoded);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedStreamsBlockedFramesAboveTheEncodingLimitCloseWithFrameEncodingError()
    {
        foreach ((bool bidirectional, ulong expectedFrameType, ulong maximumStreams) in new[]
        {
            (true, 0x16UL, QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit + 1),
            (false, 0x17UL, QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit + 1),
            (true, 0x16UL, QuicVariableLengthInteger.MaxValue),
            (false, 0x17UL, QuicVariableLengthInteger.MaxValue),
        })
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(new QuicStreamsBlockedFrame(
                bidirectional,
                maximumStreams));

            QuicConnectionTransitionResult result =
                QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
                    runtime,
                    encoded,
                    observedAtTicks: 20);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.NotNull(runtime.TerminalState);
            Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
            Assert.Equal(QuicTransportErrorCode.FrameEncodingError, runtime.TerminalState.Value.Close.TransportErrorCode);
            Assert.Equal(expectedFrameType, runtime.TerminalState.Value.Close.TriggeringFrameType);
        }
    }
}
