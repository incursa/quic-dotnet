using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

[MemoryDiagnoser]
public class QuicConnectionStreamStateBenchmarks
{
    private byte[] tailFrame = [];
    private byte[] streamData = [];

    [GlobalSetup]
    public void GlobalSetup()
    {
        tailFrame = QuicBenchmarkData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: 1,
            includeOffset: true,
            offset: 32,
            includeLength: true,
            streamData: new byte[32]);
        streamData = new byte[64];
    }

    [Benchmark]
    public ulong ReceiveOutOfOrderTail()
    {
        QuicConnectionStreamState state = CreateState();
        QuicStreamParser.TryParseStreamFrame(tailFrame, out QuicStreamFrame frame);
        state.TryReceiveStreamFrame(frame, out _);
        state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot);
        return snapshot.UniqueBytesReceived;
    }

    [Benchmark]
    public ulong ReceiveHeadAndReadPublishesCredit()
    {
        QuicConnectionStreamState state = CreateState();
        ReadOnlySpan<byte> payload = streamData;
        QuicStreamFrame frame = new(
            0x0F,
            new QuicStreamId(1),
            hasOffset: true,
            offset: 0,
            hasLength: true,
            length: (ulong)payload.Length,
            fin: true,
            payload,
            payload.Length);
        state.TryReceiveStreamFrame(frame, out _);

        Span<byte> destination = stackalloc byte[64];
        state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out _);
        return (ulong)bytesWritten
            + maxDataFrame.MaximumData
            + maxStreamDataFrame.MaximumStreamData
            + (completed ? 1UL : 0UL);
    }

    [Benchmark]
    public ulong ReceiveResetBufferedDataPublishesCredit()
    {
        QuicConnectionStreamState state = CreateState();
        ReadOnlySpan<byte> payload = streamData;
        QuicStreamFrame frame = new(
            0x0E,
            new QuicStreamId(1),
            hasOffset: true,
            offset: 0,
            hasLength: true,
            length: (ulong)payload.Length,
            fin: false,
            payload,
            payload.Length);
        state.TryReceiveStreamFrame(frame, out _);

        state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(1, 0x55, (ulong)payload.Length),
            out QuicMaxDataFrame maxDataFrame,
            out _);
        return maxDataFrame.MaximumData;
    }

    [Benchmark]
    public ulong OpenLocalStreamPublishesStreamsBlockedFrame()
    {
        QuicConnectionStreamState state = CreateState(peerBidirectionalStreamLimit: 1);
        state.TryOpenLocalStream(bidirectional: true, out _, out _);
        state.TryOpenLocalStream(bidirectional: true, out _, out QuicStreamsBlockedFrame blockedFrame);
        return blockedFrame.MaximumStreams;
    }

    [Benchmark]
    public ulong ReserveSendCapacityPublishesDataBlockedFrame()
    {
        QuicConnectionStreamState state = CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _);
        state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out _,
            out _);

        return dataBlockedFrame.MaximumData;
    }

    private static QuicConnectionStreamState CreateState(
        ulong connectionReceiveLimit = 512,
        ulong connectionSendLimit = 512,
        ulong incomingBidirectionalStreamLimit = 4,
        ulong incomingUnidirectionalStreamLimit = 4,
        ulong peerBidirectionalStreamLimit = 4,
        ulong peerUnidirectionalStreamLimit = 4,
        ulong localBidirectionalReceiveLimit = 128,
        ulong peerBidirectionalReceiveLimit = 128,
        ulong peerUnidirectionalReceiveLimit = 128,
        ulong localBidirectionalSendLimit = 128,
        ulong localUnidirectionalSendLimit = 128,
        ulong peerBidirectionalSendLimit = 128)
    {
        return new QuicConnectionStreamState(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: connectionReceiveLimit,
                InitialConnectionSendLimit: connectionSendLimit,
                InitialIncomingBidirectionalStreamLimit: incomingBidirectionalStreamLimit,
                InitialIncomingUnidirectionalStreamLimit: incomingUnidirectionalStreamLimit,
                InitialPeerBidirectionalStreamLimit: peerBidirectionalStreamLimit,
                InitialPeerUnidirectionalStreamLimit: peerUnidirectionalStreamLimit,
                InitialLocalBidirectionalReceiveLimit: localBidirectionalReceiveLimit,
                InitialPeerBidirectionalReceiveLimit: peerBidirectionalReceiveLimit,
                InitialPeerUnidirectionalReceiveLimit: peerUnidirectionalReceiveLimit,
                InitialLocalBidirectionalSendLimit: localBidirectionalSendLimit,
                InitialLocalUnidirectionalSendLimit: localUnidirectionalSendLimit,
                InitialPeerBidirectionalSendLimit: peerBidirectionalSendLimit));
    }
}
