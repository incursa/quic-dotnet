// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1259")]
public sealed class REQ_QUIC_RFC9000_1259
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReceiveStreamFrame_RejectsUncreatedLocalBidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: false);
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(0x0A, streamId: 0x00, streamData: [0xAA]);

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryReceiveStreamFrame_AcceptsCreatedPeerBidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: false);
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(0x0A, streamId: 0x01, streamData: [0xAA]);

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryReceiveStreamFrame_RejectsCreatedLocalSendOnlyStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: false);
        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out _));
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(0x0A, streamId.Value, streamData: [0xAA]);

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }
}
