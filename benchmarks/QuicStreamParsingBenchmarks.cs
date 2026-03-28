using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the QUIC stream identifier and STREAM frame parsing hot paths.
/// </summary>
[MemoryDiagnoser]
public class QuicStreamParsingBenchmarks
{
    private byte[] streamIdentifier = [];
    private byte[] streamFrameWithLength = [];
    private byte[] streamFrameToEnd = [];

    /// <summary>
    /// Prepares representative stream payloads.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        streamIdentifier = QuicBenchmarkData.EncodeVarInt(0x1234);
        streamFrameWithLength = QuicBenchmarkData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x1234,
            includeOffset: true,
            offset: 0x20,
            includeLength: true,
            streamData: [0x10, 0x11, 0x12, 0x13]);

        streamFrameToEnd = QuicBenchmarkData.BuildStreamFrame(
            frameType: 0x08,
            streamId: 0x1234,
            includeOffset: false,
            offset: 0,
            includeLength: false,
            streamData: [0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
    }

    /// <summary>
    /// Measures stream identifier decoding.
    /// </summary>
    [Benchmark]
    public int ParseStreamIdentifier()
    {
        return QuicStreamParser.TryParseStreamIdentifier(streamIdentifier, out QuicStreamId streamId, out int bytesConsumed)
            ? unchecked((int)streamId.Value) ^ bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures STREAM frame parsing when the frame includes offset and length fields.
    /// </summary>
    [Benchmark]
    public int ParseStreamFrameWithLength()
    {
        return QuicStreamParser.TryParseStreamFrame(streamFrameWithLength, out QuicStreamFrame frame)
            ? frame.StreamDataLength ^ frame.ConsumedLength ^ unchecked((int)frame.Offset) ^ (int)frame.StreamType
            : -1;
    }

    /// <summary>
    /// Measures STREAM frame parsing when Stream Data consumes the remainder of the packet.
    /// </summary>
    [Benchmark]
    public int ParseStreamFrameToEnd()
    {
        return QuicStreamParser.TryParseStreamFrame(streamFrameToEnd, out QuicStreamFrame frame)
            ? frame.StreamDataLength ^ frame.ConsumedLength ^ (int)frame.StreamType
            : -1;
    }
}
