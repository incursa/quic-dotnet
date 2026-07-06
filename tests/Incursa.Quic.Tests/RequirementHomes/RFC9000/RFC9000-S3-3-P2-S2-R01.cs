// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S3-3-P2-S2-R01">A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for a stream in the Reset Sent state or any terminal state after sending a RESET_STREAM frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S3-3-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S3P3_0002
{
    [Fact]
    [Requirement("RFC9000-S3-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_EmitsStreamDataBlockedBeforeResetSent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 0,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, streamDataBlockedFrame.StreamId);
        Assert.Equal(0UL, streamDataBlockedFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
    }

    [Fact]
    [Requirement("RFC9000-S3-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_RejectsStreamFramesAfterResetSent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [Requirement("RFC9000-S3-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReserveSendCapacity_RejectsStreamDataBlockedAfterResetSentAtCreditBoundary()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 0,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, resetSnapshot.SendState);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [Requirement("RFC9000-S3-3-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryReserveSendCapacity_RejectsStreamFramesAfterResetSent()
    {
        (ulong Offset, int Length, bool Fin)[] cases =
        [
            (0, 1, false),
            (0, 1, true),
            (4, 2, false),
            (8, 0, true),
        ];

        foreach ((ulong offset, int length, bool fin) in cases)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                localUnidirectionalSendLimit: 8,
                peerUnidirectionalStreamLimit: 8);

            Assert.True(state.TryOpenLocalStream(
                bidirectional: false,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out ulong finalSize, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(0UL, finalSize);

            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset,
                length,
                fin,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        }
    }
}
