// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-10-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_1276
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S19-10-P2-S2-R01">An endpoint that receives a MAX_STREAM_DATA frame for a receive-only stream MUST terminate the connection with error STREAM_STATE_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_AcceptsBidirectionalSendCapableStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(16UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_RejectsReceiveOnlyStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(3, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(3, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamDataFrame_RejectsReceiveOnlyStreamsAfterTheyWereOpened()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 3, [0x11], offset: 0),
            out QuicStreamFrame streamFrame));
        Assert.True(state.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(3, out QuicConnectionStreamSnapshot openedSnapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, openedSnapshot.ReceiveState);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(3, 16), out errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryApplyMaxStreamDataFrame_RejectsReceiveOnlyStreams()
    {
        (ulong StreamId, ulong SendLimit)[] cases =
        [
            (3, 16),
            (7, 32),
            (11, 64),
            (15, 128),
        ];

        foreach ((ulong streamId, ulong sendLimit) in cases)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 16,
                connectionSendLimit: 16);

            Assert.False(state.TryApplyMaxStreamDataFrame(
                new QuicMaxStreamDataFrame(streamId, sendLimit),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
            Assert.False(state.TryGetStreamSnapshot(streamId, out _));
        }
    }
}
