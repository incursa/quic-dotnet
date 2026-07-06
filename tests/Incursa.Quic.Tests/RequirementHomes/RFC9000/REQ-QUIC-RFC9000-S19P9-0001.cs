// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0001">A MAX_DATA frame (type=0x10) MUST be used in flow control to inform the peer of the maximum amount of data that can be sent on the connection as a whole.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P9-0001")]
public sealed class REQ_QUIC_RFC9000_S19P9_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_EmitsMaxDataFrameWhenApplicationReleasesConnectionCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 8);
        Assert.True(state.TryReceiveStreamFrame(ParsePeerStreamFrame([0x10, 0x11], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out _,
            out errorCode));

        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, errorCode);
        Assert.Equal(6UL, maxDataFrame.MaximumData);
        Assert.Equal(6UL, state.ConnectionReceiveLimit);
        AssertMaxDataFrameRoundTrips(maxDataFrame);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotEmitMaxDataFrameWhenNoConnectionCreditIsReleased()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 8);
        Assert.True(state.TryReceiveStreamFrame(ParsePeerStreamFrame([0x10], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReadStreamData(
            streamIdValue: 1,
            Span<byte>.Empty,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);
        Assert.Equal(4UL, state.ConnectionReceiveLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_SaturatesMaxDataFrameAtTheMaximumRepresentableConnectionLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue - 1,
            peerBidirectionalReceiveLimit: 8);
        Assert.True(state.TryReceiveStreamFrame(ParsePeerStreamFrame([0x10, 0x11], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 1,
            destination,
            out int bytesWritten,
            out _,
            out QuicMaxDataFrame maxDataFrame,
            out _,
            out errorCode));

        Assert.Equal(2, bytesWritten);
        Assert.Equal(default, errorCode);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, maxDataFrame.MaximumData);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, state.ConnectionReceiveLimit);
        AssertMaxDataFrameRoundTrips(maxDataFrame);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryReadStreamData_FuzzEmitsMaxDataFrameWhenApplicationReleasesConnectionCredit()
    {
        int[] releasedByteCounts = [1, 2, 3, 4];

        foreach (int releasedByteCount in releasedByteCounts)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 8,
                peerBidirectionalReceiveLimit: 16);
            byte[] streamData = Enumerable.Range(0, releasedByteCount).Select(static value => (byte)value).ToArray();
            Assert.True(state.TryReceiveStreamFrame(ParsePeerStreamFrame(streamData, offset: 0), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            byte[] destination = new byte[releasedByteCount];
            Assert.True(state.TryReadStreamData(
                streamIdValue: 1,
                destination,
                out int bytesWritten,
                out bool completed,
                out QuicMaxDataFrame maxDataFrame,
                out _,
                out errorCode));

            Assert.Equal(releasedByteCount, bytesWritten);
            Assert.False(completed);
            Assert.Equal(default, errorCode);
            Assert.Equal((ulong)(8 + releasedByteCount), maxDataFrame.MaximumData);
            Assert.Equal(maxDataFrame.MaximumData, state.ConnectionReceiveLimit);
            AssertMaxDataFrameRoundTrips(maxDataFrame);
        }
    }

    private static QuicStreamFrame ParsePeerStreamFrame(ReadOnlySpan<byte> streamData, ulong offset)
    {
        byte[] frameBytes = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            streamData,
            offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(frameBytes, out QuicStreamFrame frame));
        return frame;
    }

    private static void AssertMaxDataFrameRoundTrips(QuicMaxDataFrame frame)
    {
        Span<byte> buffer = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(frame, buffer, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(buffer[..bytesWritten], out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame, parsed);
    }
}
