namespace Incursa.Quic.Tests;

using System.Diagnostics.CodeAnalysis;

public sealed class QuicStreamReadLifecycleTests
{
    [Fact]
    public async Task ReadAsync_AlreadyBufferedDataReturnsExactBytes()
    {
        byte[] payload = [0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53];
        using QuicStream stream = CreateReadableStream(payload, fin: false);

        byte[] destination = new byte[payload.Length];
        int bytesRead = await stream.ReadAsync(destination, 0, destination.Length);

        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    public async Task ReadAsyncMemory_AlreadyBufferedDataReturnsExactBytes()
    {
        byte[] payload = [0x58, 0x59, 0x5A];
        using QuicStream stream = CreateReadableStream(payload, fin: false);

        byte[] destination = new byte[payload.Length];
        int bytesRead = await stream.ReadAsync(destination.AsMemory());

        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    public async Task ReadAsync_PartialReadsPreserveUnreadTailAndOrder()
    {
        using QuicStream stream = CreateReadableStream([0x10, 0x11, 0x12, 0x13, 0x14], fin: false);

        byte[] firstRead = new byte[2];
        int firstBytesRead = await stream.ReadAsync(firstRead, 0, firstRead.Length);

        byte[] secondRead = new byte[3];
        int secondBytesRead = await stream.ReadAsync(secondRead, 0, secondRead.Length);

        Assert.Equal(2, firstBytesRead);
        Assert.True(((ReadOnlySpan<byte>)[0x10, 0x11]).SequenceEqual(firstRead));
        Assert.Equal(3, secondBytesRead);
        Assert.True(((ReadOnlySpan<byte>)[0x12, 0x13, 0x14]).SequenceEqual(secondRead));
    }

    [Fact]
    public async Task ReadAsync_ExactReadThroughFinThenReadAfterFinReturnsZero()
    {
        byte[] payload = [0x21, 0x22, 0x23];
        using QuicStream stream = CreateReadableStream(payload, fin: true);

        byte[] destination = new byte[payload.Length];
        int bytesRead = await stream.ReadAsync(destination, 0, destination.Length);
        int eofBytesRead = await stream.ReadAsync(destination, 0, destination.Length);

        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
        Assert.Equal(0, eofBytesRead);
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task ReadAsync_ZeroLengthReadReturnsZeroAndLeavesBufferedBytes()
    {
        byte[] payload = [0x31, 0x32];
        using QuicStream stream = CreateReadableStream(payload, fin: false);

        byte[] destination = new byte[payload.Length];
        int zeroBytesRead = await stream.ReadAsync(destination, 0, 0);
        int bytesRead = await stream.ReadAsync(destination, 0, destination.Length);

        Assert.Equal(0, zeroBytesRead);
        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    [SuppressMessage(
        "Reliability",
        "CA2022:Avoid inexact read",
        Justification = "This test verifies cancellation before payload delivery and does not consume a successful read result.")]
    public async Task ReadAsync_CanceledBeforeWaitingPreservesCancellation()
    {
        using QuicStream stream = CreateReadableStream([0x41], fin: false);

        byte[] destination = new byte[1];
        Assert.Equal(1, await stream.ReadAsync(destination, 0, destination.Length));

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await stream.ReadAsync(destination, 0, destination.Length, cancellation.Token));
    }

    [Fact]
    [SuppressMessage(
        "Reliability",
        "CA2022:Avoid inexact read",
        Justification = "This test verifies cancellation before payload delivery and does not consume a successful read result.")]
    public async Task ReadAsyncMemory_CanceledBeforeWaitingPreservesCancellation()
    {
        using QuicStream stream = CreateReadableStream([0x42], fin: false);

        byte[] destination = new byte[1];
        Assert.Equal(1, await stream.ReadAsync(destination.AsMemory()));

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await stream.ReadAsync(destination.AsMemory(), cancellation.Token));
    }

    private static QuicStream CreateReadableStream(ReadOnlySpan<byte> payload, bool fin)
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin);
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        return new QuicStream(state, streamId: 0);
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
