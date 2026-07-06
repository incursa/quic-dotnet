// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S4-5-P3-S1-R01">The receiver MUST use the final size of the stream to account for all bytes sent on the stream in its connection-level flow controller.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S4-5-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0192
{
    [Fact]
    [Requirement("RFC9000-S4-5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_AccountsFinalSizeAtTheConnectionLevel()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(5UL, snapshot.FinalSize);
        Assert.Equal(5UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("RFC9000-S4-5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AccountsFinalSizeAtTheConnectionLevel()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame leadingFrame));
        Assert.True(state.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x33, 0x44], offset: 4),
            out QuicStreamFrame finFrame));
        Assert.True(state.TryReceiveStreamFrame(finFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(6UL, snapshot.FinalSize);
        Assert.Equal(4UL, snapshot.UniqueBytesReceived);
        Assert.Equal(6UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.Equal(6UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("RFC9000-S4-5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveResetStreamFrame_AccountsFinalSizeAtTheExactConnectionReceiveLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 5,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame leadingFrame));
        Assert.True(state.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(7UL, maxDataFrame.MaximumData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(5UL, snapshot.FinalSize);
        Assert.Equal(5UL, snapshot.AccountedBytesReceived);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("RFC9000-S4-5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_RejectsWhenTheFinalSizeExceedsConnectionReceiveLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, maxDataFrame);
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("RFC9000-S4-5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryReceiveResetStreamFrame_AccountsFinalSizeAtTheConnectionLevel()
    {
        foreach (ulong finalSize in new[] { 2UL, 3UL, 5UL, 8UL, 16UL, 63UL })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
                peerBidirectionalReceiveLimit: QuicVariableLengthInteger.MaxValue);

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x08, 1, [0x11, 0x22], offset: 0),
                out QuicStreamFrame leadingFrame));
            Assert.True(state.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

            Assert.True(state.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize),
                out QuicMaxDataFrame maxDataFrame,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(default, maxDataFrame);
            Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
            Assert.True(snapshot.HasFinalSize);
            Assert.Equal(finalSize, snapshot.FinalSize);
            Assert.Equal(finalSize, snapshot.AccountedBytesReceived);
            Assert.Equal(finalSize, state.ConnectionAccountedBytesReceived);
        }
    }
}
