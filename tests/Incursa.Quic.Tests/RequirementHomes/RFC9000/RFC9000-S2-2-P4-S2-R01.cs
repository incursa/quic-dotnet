// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S2-2-P4-S2-R01">The data at a given offset MUST NOT change if it is sent multiple times.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S2-2-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S2P2_0007
{
    [Fact]
    [Requirement("RFC9000-S2-2-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_PreservesAnIdenticalRetransmissionAtTheSameOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out errorCode));
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
    [Requirement("RFC9000-S2-2-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_IgnoresAConflictingRetransmissionAtTheSameOffset()
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
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("RFC9000-S2-2-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_AppendsOnlyTheNewTailBytesOfAnOverlappingRetransmission()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x33, 0x44, 0x55, 0x66], offset: 2), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(6UL, state.ConnectionAccountedBytesReceived);

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
        Assert.Equal(6, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(22UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(14UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("RFC9000-S2-2-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryReceiveStreamFrame_KeepsTheFirstBytesForRetransmittedOffsets()
    {
        for (int iteration = 1; iteration <= 8; iteration++)
        {
            byte[] originalPayload = Enumerable.Range(0, iteration + 2)
                .Select(value => (byte)(0x10 + value + iteration))
                .ToArray();
            byte[] conflictingPayload = originalPayload
                .Select(value => (byte)(value ^ 0x7F))
                .ToArray();
            const ulong offset = 0;
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 32,
                peerBidirectionalReceiveLimit: 16);

            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, originalPayload, offset), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, conflictingPayload, offset), out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal((ulong)originalPayload.Length, state.ConnectionAccountedBytesReceived);

            byte[] destination = new byte[16];
            Assert.True(state.TryReadStreamData(
                1,
                destination,
                out int bytesWritten,
                out bool completed,
                out QuicMaxDataFrame maxDataFrame,
                out QuicMaxStreamDataFrame maxStreamDataFrame,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.False(completed);
            Assert.Equal(originalPayload.Length, bytesWritten);
            Assert.True(originalPayload.AsSpan().SequenceEqual(destination.AsSpan(0, bytesWritten)));
            Assert.Equal((ulong)(32 + originalPayload.Length), maxDataFrame.MaximumData);
            Assert.Equal(1UL, maxStreamDataFrame.StreamId);
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
