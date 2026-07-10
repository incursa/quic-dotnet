// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicStreamReceiveBufferTests
{
    [Fact]
    public void TryReceiveStreamFrame_ReadsSinglePayloadBytesExactly()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = [0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53];
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin: false);

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[payload.Length];
        Assert.True(state.TryReadStreamData(
            frame.StreamId.Value,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.False(completed);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    public void TryReceiveStreamFrame_ReadsContiguousFramesInOrder()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] first = [0x48, 0x45, 0x41, 0x44];
        byte[] second = [0x45, 0x52, 0x53];

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, first, fin: false), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: (ulong)first.Length, second, fin: false), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[first.Length + second.Length];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(destination.Length, bytesWritten);
        Assert.False(completed);
        Assert.True(((ReadOnlySpan<byte>)[0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53]).SequenceEqual(destination));
    }

    [Fact]
    public void TryReceiveStreamFrame_ReadsThreeContiguousFramesAcrossInlineAndListStorage()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[][] payloads = [[0x10, 0x11], [0x20, 0x21], [0x30, 0x31]];

        ulong offset = 0;
        foreach (byte[] payload in payloads)
        {
            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset, payload, fin: false), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            offset += (ulong)payload.Length;
        }

        foreach (byte[] expected in payloads)
        {
            byte[] destination = new byte[expected.Length];
            Assert.True(state.TryReadStreamData(
                streamIdValue: 0,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(expected.Length, bytesWritten);
            Assert.False(completed);
            Assert.Equal(expected, destination);
        }
    }

    [Fact]
    public void TryReceiveStreamFrame_PreservesUnreadTailAfterPartialRead()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = [0x10, 0x11, 0x12, 0x13, 0x14];

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, payload, fin: true), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] firstRead = new byte[2];
        Assert.True(state.TryReadStreamData(0, firstRead, out int firstBytesWritten, out bool firstCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2, firstBytesWritten);
        Assert.False(firstCompleted);
        Assert.True(((ReadOnlySpan<byte>)[0x10, 0x11]).SequenceEqual(firstRead));

        byte[] secondRead = new byte[3];
        Assert.True(state.TryReadStreamData(0, secondRead, out int secondBytesWritten, out bool secondCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(3, secondBytesWritten);
        Assert.True(secondCompleted);
        Assert.True(((ReadOnlySpan<byte>)[0x12, 0x13, 0x14]).SequenceEqual(secondRead));
    }

    [Fact]
    public void TryReceiveStreamFrame_PreservesFirstPayloadForConflictingDuplicate()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0x11, 0x22, 0x33], fin: false), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0xAA, 0xBB, 0xCC], fin: false), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[3];
        Assert.True(state.TryReadStreamData(0, destination, out int bytesWritten, out bool completed, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(3, bytesWritten);
        Assert.False(completed);
        Assert.True(((ReadOnlySpan<byte>)[0x11, 0x22, 0x33]).SequenceEqual(destination));
    }

    [Fact]
    public void TryReceiveStreamFrame_DuplicateAfterPartialReadDoesNotReplaceUnreadTail()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0x11, 0x22, 0x33], fin: true), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] firstRead = new byte[2];
        Assert.True(state.TryReadStreamData(0, firstRead, out int firstBytesWritten, out bool firstCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2, firstBytesWritten);
        Assert.False(firstCompleted);
        Assert.True(((ReadOnlySpan<byte>)[0x11, 0x22]).SequenceEqual(firstRead));

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0xAA, 0xBB, 0xCC], fin: true), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] secondRead = new byte[1];
        Assert.True(state.TryReadStreamData(0, secondRead, out int secondBytesWritten, out bool secondCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(1, secondBytesWritten);
        Assert.True(secondCompleted);
        Assert.Equal(0x33, secondRead[0]);
    }

    [Fact]
    public void TryReceiveStreamFrame_OverlappingFrameAddsOnlyMissingTail()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0x11, 0x22, 0x33], fin: false), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 1, [0xAA, 0xBB, 0x44, 0x55], fin: true), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[5];
        Assert.True(state.TryReadStreamData(0, destination, out int bytesWritten, out bool completed, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(5, bytesWritten);
        Assert.True(completed);
        Assert.True(((ReadOnlySpan<byte>)[0x11, 0x22, 0x33, 0x44, 0x55]).SequenceEqual(destination));
    }

    private static QuicConnectionStreamState CreateServerReceiveState()
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: true,
            InitialConnectionReceiveLimit: 4096,
            InitialConnectionSendLimit: 4096,
            InitialIncomingBidirectionalStreamLimit: 16,
            InitialIncomingUnidirectionalStreamLimit: 16,
            InitialPeerBidirectionalStreamLimit: 16,
            InitialPeerUnidirectionalStreamLimit: 16,
            InitialLocalBidirectionalReceiveLimit: 4096,
            InitialPeerBidirectionalReceiveLimit: 4096,
            InitialPeerUnidirectionalReceiveLimit: 4096,
            InitialLocalBidirectionalSendLimit: 4096,
            InitialLocalUnidirectionalSendLimit: 4096,
            InitialPeerBidirectionalSendLimit: 4096));
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, ulong offset, ReadOnlySpan<byte> payload, bool fin)
    {
        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        byte[] buffer = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(frameType, streamId, offset, payload, buffer, out int bytesWritten));
        Assert.True(QuicStreamParser.TryParseStreamFrame(buffer.AsSpan(0, bytesWritten), out QuicStreamFrame frame));
        Assert.Equal(streamId, frame.StreamId.Value);
        Assert.Equal(offset, frame.Offset);
        Assert.Equal(payload.Length, frame.StreamDataLength);
        Assert.Equal(fin, frame.IsFin);
        Assert.True(payload.SequenceEqual(frame.StreamData));
        return frame;
    }
}
