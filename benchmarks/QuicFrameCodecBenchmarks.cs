using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the CRYPTO frame parse and format hot path, plus STREAM frame formatting.
/// </summary>
[MemoryDiagnoser]
public class QuicFrameCodecBenchmarks
{
    private byte[] cryptoFrame = [];
    private byte[] cryptoData = [];
    private byte[] streamData = [];
    private byte[] destination = [];

    /// <summary>
    /// Prepares representative CRYPTO frame bytes and output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        cryptoData = [0xAA, 0xBB, 0xCC, 0xDD];
        cryptoFrame = QuicBenchmarkData.BuildCryptoFrame(0x1122_3344, cryptoData);
        streamData = [0x10, 0x11, 0x12, 0x13];
        destination = new byte[64];
    }

    /// <summary>
    /// Measures CRYPTO frame parsing.
    /// </summary>
    [Benchmark]
    public int ParseCryptoFrame()
    {
        return QuicFrameCodec.TryParseCryptoFrame(cryptoFrame, out QuicCryptoFrame frame, out int bytesConsumed)
            ? bytesConsumed ^ unchecked((int)frame.Offset) ^ frame.CryptoData.Length
            : -1;
    }

    /// <summary>
    /// Measures CRYPTO frame formatting.
    /// </summary>
    [Benchmark]
    public int FormatCryptoFrame()
    {
        QuicCryptoFrame frame = new(0x1122_3344, cryptoData);
        return QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures STREAM frame formatting.
    /// </summary>
    [Benchmark]
    public int FormatStreamFrame()
    {
        return QuicFrameCodec.TryFormatStreamFrame(
            0x0F,
            0x1234,
            0x20,
            streamData,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }
}
