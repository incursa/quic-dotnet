using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the QUIC stream identifier and STREAM frame parsing hot paths.
/// </summary>
[MemoryDiagnoser]
public class QuicStreamParsingBenchmarks
{
    private byte[] bidirectionalStreamIdentifier = [];
    private byte[] unidirectionalStreamIdentifier = [];
    private byte[] offsetHeavyStreamFrame = [];
    private byte[] largeRemainderStreamFrame = [];

    /// <summary>
    /// Prepares representative stream payloads.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        bidirectionalStreamIdentifier = QuicBenchmarkData.EncodeVarInt(0x1234UL);
        unidirectionalStreamIdentifier = QuicBenchmarkData.EncodeVarInt(0x1236UL);

        offsetHeavyStreamFrame = QuicBenchmarkData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x1234UL,
            includeOffset: true,
            offset: 0x1234_5678_9ABC_DEF0UL,
            includeLength: true,
            streamData: [0x10, 0x11, 0x12, 0x13]);

        largeRemainderStreamFrame = QuicBenchmarkData.BuildStreamFrame(
            frameType: 0x08,
            streamId: 0x1236UL,
            includeOffset: false,
            offset: 0,
            includeLength: false,
            streamData: new byte[128]);
    }

    /// <summary>
    /// Measures bidirectional stream identifier decoding.
    /// </summary>
    [Benchmark]
    public int ParseBidirectionalStreamIdentifier()
    {
        return QuicStreamParser.TryParseStreamIdentifier(bidirectionalStreamIdentifier, out QuicStreamId streamId, out int bytesConsumed)
            ? unchecked((int)streamId.Value) ^ bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures unidirectional stream identifier decoding.
    /// </summary>
    [Benchmark]
    public int ParseUnidirectionalStreamIdentifier()
    {
        return QuicStreamParser.TryParseStreamIdentifier(unidirectionalStreamIdentifier, out QuicStreamId streamId, out int bytesConsumed)
            ? unchecked((int)streamId.Value) ^ bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures STREAM frame parsing when the frame includes a large offset and length.
    /// </summary>
    [Benchmark]
    public int ParseOffsetHeavyStreamFrame()
    {
        return QuicStreamParser.TryParseStreamFrame(offsetHeavyStreamFrame, out QuicStreamFrame frame)
            ? frame.StreamDataLength ^ frame.ConsumedLength ^ unchecked((int)frame.Offset) ^ (int)frame.StreamType
            : -1;
    }

    /// <summary>
    /// Measures STREAM frame parsing when Stream Data consumes a larger remainder of the packet.
    /// </summary>
    [Benchmark]
    public int ParseLargeRemainderStreamFrame()
    {
        return QuicStreamParser.TryParseStreamFrame(largeRemainderStreamFrame, out QuicStreamFrame frame)
            ? frame.StreamDataLength ^ frame.ConsumedLength ^ (int)frame.StreamType
            : -1;
    }
}
