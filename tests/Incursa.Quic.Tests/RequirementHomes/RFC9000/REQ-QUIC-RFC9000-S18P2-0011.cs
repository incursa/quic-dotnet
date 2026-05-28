// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0011")]
public sealed class REQ_QUIC_RFC9000_S18P2_0011
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_UsesAdvertisedInitialBidirectionalStreamLimit()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
                QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsBidiId,
                2);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsBidi!.Value);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId firstStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(0UL, firstStreamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId secondStreamId,
            out blockedFrame));
        Assert.Equal(4UL, secondStreamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(2UL, blockedFrame.MaximumStreams);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_BlocksBidirectionalStreamsWhenInitialMaxStreamsBidiIsZero()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
                QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsBidiId,
                0);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsBidi!.Value);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0011")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenLocalStream_BlocksBidirectionalStreamsUntilPeerMaxStreamsIncreases()
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            [],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));
        Assert.Null(parsedTransportParameters.InitialMaxStreamsBidi);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsBidi ?? 0);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 1)));
        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out blockedFrame));

        Assert.Equal(0UL, streamId.Value);
        Assert.Equal(default, blockedFrame);
    }
}
