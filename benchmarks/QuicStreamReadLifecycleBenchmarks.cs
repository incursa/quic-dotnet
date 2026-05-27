using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks QuicStream read-call allocation after STREAM bytes are already buffered.
/// </summary>
[MemoryDiagnoser]
public class QuicStreamReadLifecycleBenchmarks
{
    private const int Operations = 256;

    private QuicStream[] streams = [];
    private byte[][] readBuffers = [];

    [IterationSetup(Target = nameof(ReadAsyncMemory_AlreadyBufferedRequestSizedPayload))]
    public void SetupMemoryAlreadyBufferedRequestSizedPayload()
    {
        SetupStreams(CreatePayload(64), bufferLength: 64, fin: false);
    }

    [Benchmark(OperationsPerInvoke = Operations)]
    public int ReadAsyncMemory_AlreadyBufferedRequestSizedPayload()
    {
        int total = 0;
        for (int i = 0; i < Operations; i++)
        {
            total += streams[i].ReadAsync(readBuffers[i].AsMemory()).GetAwaiter().GetResult();
        }

        return total;
    }

    [IterationSetup(Target = nameof(ReadAsync_AlreadyBufferedRequestSizedPayload))]
    public void SetupAlreadyBufferedRequestSizedPayload()
    {
        SetupStreams(CreatePayload(64), bufferLength: 64, fin: false);
    }

    [Benchmark(OperationsPerInvoke = Operations)]
    public int ReadAsync_AlreadyBufferedRequestSizedPayload()
    {
        int total = 0;
        for (int i = 0; i < Operations; i++)
        {
            total += streams[i].ReadAsync(readBuffers[i], 0, readBuffers[i].Length).GetAwaiter().GetResult();
        }

        return total;
    }

    [IterationSetup(Target = nameof(ReadAsync_AlreadyBufferedSmallPayload))]
    public void SetupAlreadyBufferedSmallPayload()
    {
        SetupStreams([0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53], bufferLength: 7, fin: false);
    }

    [Benchmark(OperationsPerInvoke = Operations)]
    public int ReadAsync_AlreadyBufferedSmallPayload()
    {
        int total = 0;
        for (int i = 0; i < Operations; i++)
        {
            total += streams[i].ReadAsync(readBuffers[i], 0, readBuffers[i].Length).GetAwaiter().GetResult();
        }

        return total;
    }

    [IterationSetup(Target = nameof(ReadAsync_AlreadyBufferedPartialRead))]
    public void SetupAlreadyBufferedPartialRead()
    {
        SetupStreams([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16], bufferLength: 4, fin: false);
    }

    [Benchmark(OperationsPerInvoke = Operations)]
    public int ReadAsync_AlreadyBufferedPartialRead()
    {
        int total = 0;
        for (int i = 0; i < Operations; i++)
        {
            total += streams[i].ReadAsync(readBuffers[i], 0, readBuffers[i].Length).GetAwaiter().GetResult();
        }

        return total;
    }

    [IterationSetup(Target = nameof(ReadAsync_EndOfStreamAfterBufferedData))]
    public void SetupEndOfStreamAfterBufferedData()
    {
        SetupStreams([0x21, 0x22, 0x23], bufferLength: 3, fin: true);
    }

    [Benchmark(OperationsPerInvoke = Operations)]
    public int ReadAsync_EndOfStreamAfterBufferedData()
    {
        int total = 0;
        for (int i = 0; i < Operations; i++)
        {
            total += streams[i].ReadAsync(readBuffers[i], 0, readBuffers[i].Length).GetAwaiter().GetResult();
        }

        return total;
    }

    [IterationCleanup(
        Targets =
        [
            nameof(ReadAsync_AlreadyBufferedRequestSizedPayload),
            nameof(ReadAsyncMemory_AlreadyBufferedRequestSizedPayload),
            nameof(ReadAsync_AlreadyBufferedSmallPayload),
            nameof(ReadAsync_AlreadyBufferedPartialRead),
            nameof(ReadAsync_EndOfStreamAfterBufferedData),
        ])]
    public void CleanupStream()
    {
        foreach (QuicStream stream in streams)
        {
            stream.Dispose();
        }
    }

    private void SetupStreams(ReadOnlySpan<byte> payload, int bufferLength, bool fin)
    {
        streams = new QuicStream[Operations];
        readBuffers = new byte[Operations][];

        for (int i = 0; i < Operations; i++)
        {
            streams[i] = CreateReadableStream(payload, fin);
            readBuffers[i] = new byte[bufferLength];
        }
    }

    private static QuicStream CreateReadableStream(ReadOnlySpan<byte> payload, bool fin)
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin);
        if (!state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode) || errorCode != default)
        {
            throw new InvalidOperationException("Failed to receive benchmark STREAM frame.");
        }

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

        byte[] buffer = new byte[Math.Max(64, payload.Length + 16)];
        if (!QuicFrameCodec.TryFormatStreamFrame(frameType, streamId, offset, payload, buffer, out int bytesWritten)
            || !QuicStreamParser.TryParseStreamFrame(buffer.AsSpan(0, bytesWritten), out QuicStreamFrame frame))
        {
            throw new InvalidOperationException("Failed to create benchmark STREAM frame.");
        }

        return frame;
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i + 1);
        }

        return payload;
    }
}
