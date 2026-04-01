using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the CRYPTO frame parse and format hot path.
/// </summary>
[MemoryDiagnoser]
public class QuicFrameCodecBenchmarks
{
    private byte[] cryptoFrame = [];
    private byte[] cryptoData = [];
    private byte[] destination = [];

    /// <summary>
    /// Prepares representative CRYPTO frame bytes and output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        cryptoData = [0xAA, 0xBB, 0xCC, 0xDD];
        cryptoFrame = QuicBenchmarkData.BuildCryptoFrame(0x1122_3344, cryptoData);
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
}
