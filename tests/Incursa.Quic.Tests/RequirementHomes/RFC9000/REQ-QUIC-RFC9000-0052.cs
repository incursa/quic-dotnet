// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0052">An endpoint MAY treat receipt of different data at the same offset within a stream as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0052")]
public sealed class REQ_QUIC_RFC9000_0052
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0052")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_PreservesOriginalPayloadWhenConflictingDuplicateDataIsPermitted()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0xAA, 0xBB], offset: 0), out errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22 }.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0052")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_DoesNotTreatConflictingRetransmissionsAtTheSameOffsetAsAProtocolViolation()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0xAA, 0xBB, 0xCC, 0xDD], offset: 0), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(20UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0052")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_PreservesUnreadTailBytesAcrossAPartiallyReadConflictingRetransmissionAtTheSameOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> leadingDestination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            leadingDestination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22 }.AsSpan().SequenceEqual(leadingDestination[..bytesWritten]));
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0xAA, 0xBB, 0xCC, 0xDD], offset: 0), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2UL, snapshot.ReadOffset);
        Assert.Equal(4, snapshot.BufferedReadableBytes);

        Span<byte> trailingDestination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            1,
            trailingDestination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x33, 0x44 }.AsSpan().SequenceEqual(trailingDestination[..bytesWritten]));
        Assert.Equal(20UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0052")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryReceiveStreamFrame_PreservesTheFirstPayloadAcrossConflictingRetransmissionsAtTheSameOffset()
    {
        Random random = new(0x5150_2042);
        const ulong connectionReceiveLimit = 256;
        const ulong peerBidirectionalReceiveLimit = 64;
        byte[] destination = new byte[64];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            int payloadLength = random.Next(1, 33);
            byte[] originalPayload = new byte[payloadLength];
            random.NextBytes(originalPayload);

            byte[] conflictPayload = new byte[payloadLength];
            random.NextBytes(conflictPayload);
            if (conflictPayload.AsSpan().SequenceEqual(originalPayload))
            {
                conflictPayload[0] ^= 0xFF;
            }

            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: connectionReceiveLimit,
                peerBidirectionalReceiveLimit: peerBidirectionalReceiveLimit);

            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, originalPayload, offset: 0), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, conflictPayload, offset: 0), out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal((ulong)payloadLength, state.ConnectionAccountedBytesReceived);

            Assert.True(state.TryReadStreamData(
                1,
                destination,
                out int bytesWritten,
                out bool completed,
                out QuicMaxDataFrame maxDataFrame,
                out QuicMaxStreamDataFrame maxStreamDataFrame,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(payloadLength, bytesWritten);
            Assert.False(completed);
            Assert.True(originalPayload.AsSpan().SequenceEqual(destination.AsSpan(0, bytesWritten)));
            Assert.Equal(connectionReceiveLimit + (ulong)payloadLength, maxDataFrame.MaximumData);
            Assert.Equal(1UL, maxStreamDataFrame.StreamId);
            Assert.Equal(peerBidirectionalReceiveLimit + (ulong)payloadLength, maxStreamDataFrame.MaximumStreamData);
        }
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] data, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, data, offset: offset),
            out QuicStreamFrame frame));
        return frame;
    }
}
