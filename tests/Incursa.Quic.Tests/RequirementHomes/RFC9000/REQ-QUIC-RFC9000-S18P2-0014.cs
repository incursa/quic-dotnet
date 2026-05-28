// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0014")]
public sealed class REQ_QUIC_RFC9000_S18P2_0014
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_UsesAdvertisedInitialUnidirectionalStreamLimit()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
                QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsUniId,
                2);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerUnidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsUni!.Value);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId firstStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(2UL, firstStreamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId secondStreamId,
            out blockedFrame));
        Assert.Equal(6UL, secondStreamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: false,
            out _,
            out blockedFrame));
        Assert.False(blockedFrame.IsBidirectional);
        Assert.Equal(2UL, blockedFrame.MaximumStreams);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_BlocksUnidirectionalStreamsWhenInitialMaxStreamsUniIsZero()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
                QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsUniId,
                0);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerUnidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsUni!.Value);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: false,
            out _,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.False(blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0014")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenLocalStream_BlocksUnidirectionalStreamsUntilPeerMaxStreamsIncreases()
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            [],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));
        Assert.Null(parsedTransportParameters.InitialMaxStreamsUni);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerUnidirectionalStreamLimit: parsedTransportParameters.InitialMaxStreamsUni ?? 0);

        Assert.False(state.TryOpenLocalStream(
            bidirectional: false,
            out _,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.False(blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 1)));
        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out blockedFrame));

        Assert.Equal(2UL, streamId.Value);
        Assert.Equal(default, blockedFrame);
    }
}
