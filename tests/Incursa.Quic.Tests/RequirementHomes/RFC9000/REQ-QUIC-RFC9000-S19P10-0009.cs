// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0009")]
public sealed class REQ_QUIC_RFC9000_S19P10_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_CreditsOnlyTheAffectedStreamId()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            connectionSendLimit: 32);

        Assert.True(state.TryOpenLocalStream(true, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame firstBlockedFrame));
        Assert.Equal(default, firstBlockedFrame);
        Assert.True(state.TryOpenLocalStream(true, out QuicStreamId secondStreamId, out QuicStreamsBlockedFrame secondBlockedFrame));
        Assert.Equal(default, secondBlockedFrame);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(secondStreamId.Value, 20), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.True(state.TryGetStreamSnapshot(secondStreamId.Value, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(8UL, firstSnapshot.SendLimit);
        Assert.Equal(20UL, secondSnapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_DoesNotCreditUnaffectedStreamIds()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            connectionSendLimit: 32);

        Assert.True(state.TryOpenLocalStream(true, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame firstBlockedFrame));
        Assert.Equal(default, firstBlockedFrame);
        Assert.True(state.TryOpenLocalStream(true, out QuicStreamId secondStreamId, out QuicStreamsBlockedFrame secondBlockedFrame));
        Assert.Equal(default, secondBlockedFrame);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(firstStreamId.Value, 20), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(secondStreamId.Value, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(8UL, secondSnapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamDataFrame_PreservesZeroStreamIdAsTheAffectedStream()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId: 0, maximumStreamData: 16);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertParses(encoded, expectedStreamId: 0, expectedMaximumStreamData: 16);
    }
}
