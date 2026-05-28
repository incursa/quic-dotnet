// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0001")]
public sealed class REQ_QUIC_RFC9000_S4P6_0001
{
    [Theory]
    [InlineData(true, 5UL, 1UL)]
    [InlineData(false, 7UL, 3UL)]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AcceptsStreamsWithinTheCumulativeIncomingLimit(
        bool bidirectional,
        ulong streamId,
        ulong firstStreamIdOfType)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: bidirectional ? 2UL : 4UL,
            incomingUnidirectionalStreamLimit: bidirectional ? 4UL : 2UL);

        byte[] allowedPacket = QuicStreamTestData.BuildStreamFrame(0x0A, streamId, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(allowedPacket, out QuicStreamFrame allowedFrame));

        Assert.True(state.TryReceiveStreamFrame(allowedFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(firstStreamIdOfType, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot targetSnapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, firstSnapshot.ReceiveState);
        Assert.Equal(QuicStreamReceiveState.Recv, targetSnapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_LimitsTheCumulativeNumberOfIncomingStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(incomingBidirectionalStreamLimit: 1);

        byte[] overLimitPacket = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 5, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(overLimitPacket, out QuicStreamFrame overLimitFrame));

        Assert.False(state.TryReceiveStreamFrame(overLimitFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }
}
