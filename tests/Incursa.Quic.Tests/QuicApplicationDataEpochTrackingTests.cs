// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicApplicationDataEpochTrackingTests
{
    [Fact]
    public void ZeroRttEpochMarksStreamWithReceivedZeroRttData()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = [0x41, 0x42, 0x43];
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin: false);

        Assert.True(state.TryReceiveStreamFrame(frame, out _, QuicApplicationDataEpoch.ZeroRtt));

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.ReceivedZeroRttData);
        Assert.False(snapshot.ReceivedOneRttData);
    }

    [Fact]
    public void OneRttEpochMarksStreamWithReceivedOneRttData()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = [0x41, 0x42, 0x43];
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin: false);

        Assert.True(state.TryReceiveStreamFrame(frame, out _, QuicApplicationDataEpoch.OneRtt));

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.ReceivedOneRttData);
        Assert.False(snapshot.ReceivedZeroRttData);
    }

    [Fact]
    public void DefaultEpochMarksStreamWithReceivedOneRttData()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = [0x41, 0x42, 0x43];
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin: false);

        Assert.True(state.TryReceiveStreamFrame(frame, out _));

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.ReceivedOneRttData);
        Assert.False(snapshot.ReceivedZeroRttData);
    }

    [Fact]
    public void StreamCanReceiveDataFromBothEpochs()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] zeroRttPayload = [0x41, 0x42, 0x43];
        byte[] oneRttPayload = [0x44, 0x45, 0x46];

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, zeroRttPayload, fin: false),
            out _,
            QuicApplicationDataEpoch.ZeroRtt));
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: (ulong)zeroRttPayload.Length, oneRttPayload, fin: false),
            out _,
            QuicApplicationDataEpoch.OneRtt));

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.ReceivedZeroRttData);
        Assert.True(snapshot.ReceivedOneRttData);
    }

    [Fact]
    public void ZeroRttFinOnlyFrameDoesNotSetReceivedZeroRttData()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, [], fin: true),
            out _,
            QuicApplicationDataEpoch.ZeroRtt));

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.ReceivedZeroRttData);
        Assert.False(snapshot.ReceivedOneRttData);
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
