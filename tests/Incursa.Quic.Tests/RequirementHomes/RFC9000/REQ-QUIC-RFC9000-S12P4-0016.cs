// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0016">The contents of frames with the F marking MUST be flow controlled.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0016")]
public sealed class REQ_QUIC_RFC9000_S12P4_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_AllowsStreamDataWithinTheAdvertisedFlowControlLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 4,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(4UL, state.ConnectionUniqueBytesSent);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(4UL, snapshot.UniqueBytesSent);
        Assert.Equal(8UL, snapshot.SendLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_ReturnsDataBlockedWhenConnectionFlowControlCreditIsExhausted()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(0UL, state.ConnectionUniqueBytesSent);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.UniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_ReturnsStreamDataBlockedWhenStreamFlowControlCreditIsExhausted()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            localBidirectionalSendLimit: 1);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(1UL, streamDataBlockedFrame.MaximumStreamData);
        Assert.Equal(0UL, state.ConnectionUniqueBytesSent);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.UniqueBytesSent);
    }
}
