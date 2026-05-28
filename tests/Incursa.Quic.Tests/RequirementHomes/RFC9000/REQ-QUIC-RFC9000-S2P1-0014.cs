// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0014">Using a stream ID out of order MUST cause all lower-numbered streams of that type to be opened.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P1-0014")]
public sealed class REQ_QUIC_RFC9000_S2P1_0014
{
    [Theory]
    [InlineData((byte)1)]
    [InlineData((byte)3)]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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

    [Theory]
    [InlineData((byte)1)]
    [InlineData((byte)3)]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S2P1-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_RejectsLocallyInitiatedStreamIds()
    {
        QuicConnectionStreamState state = CreatePeerStreamState();
        ulong streamId = 0UL;

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(streamId, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_RejectsLocallyInitiatedStreamIds()
    {
        QuicConnectionStreamState state = CreatePeerStreamState();
        ulong streamId = 0UL;

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId, 0x99),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(streamId, out _));
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
