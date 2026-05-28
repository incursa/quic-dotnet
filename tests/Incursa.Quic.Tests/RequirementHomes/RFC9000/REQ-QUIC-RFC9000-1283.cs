// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1283")]
public sealed class REQ_QUIC_RFC9000_1283
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AcceptsBytesAtTheLargestAdvertisedStreamCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], offset: 0),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(8UL, snapshot.UniqueBytesReceived);
        Assert.Equal(8UL, snapshot.AccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsBytesBeyondTheAdvertisedStreamCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], offset: 0),
            out QuicStreamFrame initialFrame));

        Assert.True(state.TryReceiveStreamFrame(initialFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(8UL, snapshot.UniqueBytesReceived);
        Assert.Equal(8UL, snapshot.AccountedBytesReceived);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x99], offset: 8),
            out QuicStreamFrame excessFrame));

        Assert.False(state.TryReceiveStreamFrame(excessFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_RejectsFinalSizeBeyondTheAdvertisedStreamCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [], offset: 9),
            out QuicStreamFrame finFrame));

        Assert.False(state.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }
}
