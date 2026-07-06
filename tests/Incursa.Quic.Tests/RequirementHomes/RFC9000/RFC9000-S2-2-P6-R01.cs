// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S2-2-P6-R01">An endpoint MUST NOT send data on any stream without ensuring that it is within the flow control limits set by its peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S2-2-P6-R01")]
public sealed class REQ_QUIC_RFC9000_0056
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_AllowsBytesWithinTheUpdatedPeerFlowControlLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryApplyPeerTransportParameterSendLimits(
            localBidirectionalLimit: 5,
            peerBidirectionalLimit: 8,
            localUnidirectionalLimit: 8));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot updatedSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, updatedSnapshot.SendState);
        Assert.Equal(5UL, updatedSnapshot.SendLimit);
        Assert.False(updatedSnapshot.HasFinalSize);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 5,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sentSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sentSnapshot.SendState);
        Assert.Equal(5UL, sentSnapshot.SendLimit);
        Assert.Equal(5UL, sentSnapshot.UniqueBytesSent);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_ReturnsStreamDataBlockedWhenPeerStreamLimitIsExhausted()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryApplyPeerTransportParameterSendLimits(
            localBidirectionalLimit: 1,
            peerBidirectionalLimit: 8,
            localUnidirectionalLimit: 8));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot limitedSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, limitedSnapshot.SendState);
        Assert.Equal(1UL, limitedSnapshot.SendLimit);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(streamId.Value, streamDataBlockedFrame.StreamId);
        Assert.Equal(1UL, streamDataBlockedFrame.MaximumStreamData);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot blockedSnapshot));
        Assert.Equal(QuicStreamSendState.Send, blockedSnapshot.SendState);
        Assert.Equal(1UL, blockedSnapshot.SendLimit);
        Assert.Equal(0UL, blockedSnapshot.UniqueBytesSent);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReserveSendCapacity_EnforcesAReducedPeerLimitOnAPartiallySentStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryApplyPeerTransportParameterSendLimits(
            localBidirectionalLimit: 5,
            peerBidirectionalLimit: 8,
            localUnidirectionalLimit: 8));

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 3,
            fin: false,
            out QuicDataBlockedFrame firstDataBlockedFrame,
            out QuicStreamDataBlockedFrame firstStreamDataBlockedFrame,
            out QuicTransportErrorCode firstErrorCode));
        Assert.Equal(default, firstDataBlockedFrame);
        Assert.Equal(default, firstStreamDataBlockedFrame);
        Assert.Equal(default, firstErrorCode);

        Assert.True(state.TryApplyPeerTransportParameterSendLimits(
            localBidirectionalLimit: 4,
            peerBidirectionalLimit: 8,
            localUnidirectionalLimit: 8));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot reducedSnapshot));
        Assert.Equal(QuicStreamSendState.Send, reducedSnapshot.SendState);
        Assert.Equal(4UL, reducedSnapshot.SendLimit);
        Assert.Equal(3UL, reducedSnapshot.UniqueBytesSent);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 3,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(streamId.Value, streamDataBlockedFrame.StreamId);
        Assert.Equal(4UL, streamDataBlockedFrame.MaximumStreamData);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot blockedSnapshot));
        Assert.Equal(QuicStreamSendState.Send, blockedSnapshot.SendState);
        Assert.Equal(4UL, blockedSnapshot.SendLimit);
        Assert.Equal(3UL, blockedSnapshot.UniqueBytesSent);
    }

    [Fact]
    [Requirement("RFC9000-S2-2-P6-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryReserveSendCapacity_StopsAtPeerAdvertisedFlowControlLimits()
    {
        for (int streamLimit = 1; streamLimit <= 8; streamLimit++)
        {
            QuicConnectionStreamState withinLimitState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 32,
                localBidirectionalSendLimit: 32);
            Assert.True(withinLimitState.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId withinLimitStreamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);
            Assert.True(withinLimitState.TryApplyPeerTransportParameterSendLimits(
                localBidirectionalLimit: (ulong)streamLimit,
                peerBidirectionalLimit: 8,
                localUnidirectionalLimit: 32));

            Assert.True(withinLimitState.TryReserveSendCapacity(
                withinLimitStreamId.Value,
                offset: 0,
                length: streamLimit,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            QuicConnectionStreamState overLimitState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 32,
                localBidirectionalSendLimit: 32);
            Assert.True(overLimitState.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId overLimitStreamId,
                out blockedFrame));
            Assert.Equal(default, blockedFrame);
            Assert.True(overLimitState.TryApplyPeerTransportParameterSendLimits(
                localBidirectionalLimit: (ulong)streamLimit,
                peerBidirectionalLimit: 8,
                localUnidirectionalLimit: 32));

            Assert.False(overLimitState.TryReserveSendCapacity(
                overLimitStreamId.Value,
                offset: 0,
                length: streamLimit + 1,
                fin: false,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(overLimitStreamId.Value, streamDataBlockedFrame.StreamId);
            Assert.Equal((ulong)streamLimit, streamDataBlockedFrame.MaximumStreamData);
            Assert.Equal(default, errorCode);
        }
    }
}
