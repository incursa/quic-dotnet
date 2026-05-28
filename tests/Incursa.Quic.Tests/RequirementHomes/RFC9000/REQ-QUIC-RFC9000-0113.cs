// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0113">An endpoint MUST enter Data Recvd after all data arrives.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0113")]
public sealed class REQ_QUIC_RFC9000_0113
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_EntersDataRecvdAfterAllDataArrives()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8,
            peerUnidirectionalReceiveLimit: 8,
            localBidirectionalReceiveLimit: 8,
            localUnidirectionalSendLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x33, 0x44], offset: 2),
            out QuicStreamFrame tailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame headFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot preCompletionSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, preCompletionSnapshot.ReceiveState);
        Assert.True(preCompletionSnapshot.HasFinalSize);

        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4UL, snapshot.UniqueBytesReceived);
        Assert.Equal(4UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_DoesNotEnterDataRecvdBeforeAllDataArrives()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8,
            peerUnidirectionalReceiveLimit: 8,
            localBidirectionalReceiveLimit: 8,
            localUnidirectionalSendLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x33, 0x44], offset: 2),
            out QuicStreamFrame tailFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.NotEqual(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
    }
}
