// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1293")]
public sealed class REQ_QUIC_RFC9000_1293
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_CountsClosedStreamsAgainstTheAdvertisedCumulativeLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 3, streamData: []),
            out QuicStreamFrame firstClosedStreamFrame));
        Assert.True(state.TryReceiveStreamFrame(firstClosedStreamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryPeekPeerStreamCapacityRelease(3, out QuicMaxStreamsFrame releaseFrame));
        Assert.False(releaseFrame.IsBidirectional);
        Assert.Equal(2UL, releaseFrame.MaximumStreams);
        Assert.True(state.TryCommitPeerStreamCapacityRelease(3, releaseFrame));

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 7, streamData: []),
            out QuicStreamFrame secondClosedStreamFrame));
        Assert.True(state.TryReceiveStreamFrame(secondClosedStreamFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId: 11, streamData: [0x51]),
            out QuicStreamFrame thirdStreamFrame));
        Assert.False(state.TryReceiveStreamFrame(thirdStreamFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_DoesNotFreeClosedStreamCapacityWithoutMaxStreamsIncrease()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 3, streamData: []),
            out QuicStreamFrame closedStreamFrame));
        Assert.True(state.TryReceiveStreamFrame(closedStreamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId: 7, streamData: [0x51]),
            out QuicStreamFrame nextStreamFrame));
        Assert.False(state.TryReceiveStreamFrame(nextStreamFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryReceiveStreamFrame_FuzzCountsClosedStreamsTowardCumulativeLimit()
    {
        for (ulong streamLimit = 1; streamLimit <= 5; streamLimit++)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                incomingUnidirectionalStreamLimit: streamLimit);

            for (ulong streamIndex = 0; streamIndex < streamLimit; streamIndex++)
            {
                ulong closedStreamId = streamIndex * 4 + 3;
                Assert.True(QuicStreamParser.TryParseStreamFrame(
                    QuicStreamTestData.BuildStreamFrame(0x0B, streamId: closedStreamId, streamData: []),
                    out QuicStreamFrame closedStreamFrame));
                Assert.True(state.TryReceiveStreamFrame(closedStreamFrame, out QuicTransportErrorCode errorCode));
                Assert.Equal(default, errorCode);
            }

            ulong nextStreamId = streamLimit * 4 + 3;
            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x08, nextStreamId, streamData: [0x51]),
                out QuicStreamFrame nextStreamFrame));

            Assert.False(state.TryReceiveStreamFrame(nextStreamFrame, out QuicTransportErrorCode finalErrorCode));
            Assert.Equal(QuicTransportErrorCode.StreamLimitError, finalErrorCode);
        }
    }
}
