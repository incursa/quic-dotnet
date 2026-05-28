// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0109">An endpoint MUST open lower-numbered peer streams first.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0109")]
public sealed class REQ_QUIC_RFC9000_0109
{
    [Property]
    [Requirement("REQ-QUIC-RFC9000-0109")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Property")]
    public void TryApplyMaxStreamDataFrame_OpensLowerNumberedPeerStreamsFirst(byte streamIndex)
    {
        QuicConnectionStreamState state = CreatePeerStreamState();

        ulong streamOrdinal = streamIndex;
        ulong streamId = (streamOrdinal << 2) | 1UL;

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        AssertLowerNumberedPeerStreamsAreOpened(state, streamOrdinal);
        AssertHigherNumberedPeerStreamIsNotOpened(state, streamOrdinal);
    }

    [Property]
    [Requirement("REQ-QUIC-RFC9000-0109")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Property")]
    public void TryReceiveStopSendingFrame_OpensLowerNumberedPeerStreamsFirst(byte streamIndex)
    {
        QuicConnectionStreamState state = CreatePeerStreamState();

        ulong streamOrdinal = streamIndex;
        ulong streamId = (streamOrdinal << 2) | 1UL;

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId, 0x99),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(streamId, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);

        AssertLowerNumberedPeerStreamsAreOpened(state, streamOrdinal);
        AssertHigherNumberedPeerStreamIsNotOpened(state, streamOrdinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0109")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_DoesNotOpenAnyPeerStreamWhenTheTargetExceedsTheLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: 2,
            peerBidirectionalReceiveLimit: 32,
            peerBidirectionalSendLimit: 8);
        ulong overLimitPeerStreamId = (2UL << 2) | 1UL;

        Assert.False(state.TryApplyMaxStreamDataFrame(
            new QuicMaxStreamDataFrame(overLimitPeerStreamId, 16),
            out QuicTransportErrorCode errorCode));

        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(1, out _));
        Assert.False(state.TryGetStreamSnapshot(5, out _));
        Assert.False(state.TryGetStreamSnapshot(overLimitPeerStreamId, out _));
    }

    private static QuicConnectionStreamState CreatePeerStreamState()
    {
        return QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 128,
            connectionSendLimit: 128,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            peerBidirectionalReceiveLimit: 32,
            peerUnidirectionalReceiveLimit: 32,
            localBidirectionalReceiveLimit: 32,
            localUnidirectionalSendLimit: 32,
            peerBidirectionalSendLimit: 8);
    }

    private static void AssertLowerNumberedPeerStreamsAreOpened(QuicConnectionStreamState state, ulong streamOrdinal)
    {
        for (ulong index = 0; index <= streamOrdinal; index++)
        {
            ulong knownStreamId = (index << 2) | 1UL;
            Assert.True(state.TryGetStreamSnapshot(knownStreamId, out QuicConnectionStreamSnapshot _));
        }
    }

    private static void AssertHigherNumberedPeerStreamIsNotOpened(QuicConnectionStreamState state, ulong streamOrdinal)
    {
        ulong higherStreamId = ((streamOrdinal + 1UL) << 2) | 1UL;
        Assert.False(state.TryGetStreamSnapshot(higherStreamId, out _));
    }
}
