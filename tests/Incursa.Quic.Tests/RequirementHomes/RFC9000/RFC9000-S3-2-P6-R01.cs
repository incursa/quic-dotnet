// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S3-2-P6-R01">An endpoint MUST open lower-numbered peer streams first.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S3-2-P6-R01")]
public sealed class RFC9000_S3_2_P6_R01
{
    [Property]
    [Requirement("RFC9000-S3-2-P6-R01")]
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
    [Requirement("RFC9000-S3-2-P6-R01")]
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
    [Requirement("RFC9000-S3-2-P6-R01")]
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

    [Fact]
    [Requirement("RFC9000-S3-2-P6-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PeerControlFrameFuzz_OpensLowerNumberedSameTypePeerStreamsFirst()
    {
        for (ulong streamOrdinal = 0; streamOrdinal < 32; streamOrdinal++)
        {
            QuicConnectionStreamState state = CreatePeerStreamState();
            ulong streamId = (streamOrdinal << 2) | 1UL;
            ulong advertisedSendLimit = 16UL + streamOrdinal;

            Assert.True(state.TryApplyMaxStreamDataFrame(
                new QuicMaxStreamDataFrame(streamId, advertisedSendLimit),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            AssertLowerNumberedPeerStreamsAreOpened(state, streamOrdinal);
            AssertHigherNumberedPeerStreamIsNotOpened(state, streamOrdinal);
        }
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
        AssertLowerNumberedPeerStreamsAreOpened(state, streamOrdinal, streamTypeBits: 1);
    }

    private static void AssertLowerNumberedPeerStreamsAreOpened(
        QuicConnectionStreamState state,
        ulong streamOrdinal,
        ulong streamTypeBits)
    {
        for (ulong index = 0; index <= streamOrdinal; index++)
        {
            ulong knownStreamId = (index << 2) | streamTypeBits;
            Assert.True(state.TryGetStreamSnapshot(knownStreamId, out QuicConnectionStreamSnapshot _));
        }
    }

    private static void AssertHigherNumberedPeerStreamIsNotOpened(QuicConnectionStreamState state, ulong streamOrdinal)
    {
        AssertHigherNumberedPeerStreamIsNotOpened(state, streamOrdinal, streamTypeBits: 1);
    }

    private static void AssertHigherNumberedPeerStreamIsNotOpened(
        QuicConnectionStreamState state,
        ulong streamOrdinal,
        ulong streamTypeBits)
    {
        ulong higherStreamId = ((streamOrdinal + 1UL) << 2) | streamTypeBits;
        Assert.False(state.TryGetStreamSnapshot(higherStreamId, out _));
    }
}
