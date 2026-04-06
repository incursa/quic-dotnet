using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

[MemoryDiagnoser]
public class QuicConnectionStreamStateBenchmarks
{
    private byte[] tailFrame = [];
    private byte[] headFrame = [];

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
        headFrame = QuicBenchmarkData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 1,
            includeOffset: true,
            offset: 0,
            includeLength: true,
            streamData: new byte[32]);
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
    public ulong ReceiveHeadAndRead()
    {
        QuicConnectionStreamState state = CreateState();
        QuicStreamParser.TryParseStreamFrame(tailFrame, out QuicStreamFrame tail);
        QuicStreamParser.TryParseStreamFrame(headFrame, out QuicStreamFrame head);
        state.TryReceiveStreamFrame(tail, out _);
        state.TryReceiveStreamFrame(head, out _);

        Span<byte> destination = stackalloc byte[64];
        state.TryReadStreamData(1, destination, out int bytesWritten, out _, out _, out _, out _);
        return (ulong)bytesWritten;
    }

    private static QuicConnectionStreamState CreateState()
    {
        return new QuicConnectionStreamState(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: 512,
                InitialConnectionSendLimit: 512,
                InitialIncomingBidirectionalStreamLimit: 4,
                InitialIncomingUnidirectionalStreamLimit: 4,
                InitialPeerBidirectionalStreamLimit: 4,
                InitialPeerUnidirectionalStreamLimit: 4,
                InitialLocalBidirectionalReceiveLimit: 128,
                InitialPeerBidirectionalReceiveLimit: 128,
                InitialPeerUnidirectionalReceiveLimit: 128,
                InitialLocalBidirectionalSendLimit: 128,
                InitialLocalUnidirectionalSendLimit: 128,
                InitialPeerBidirectionalSendLimit: 128));
    }
}
