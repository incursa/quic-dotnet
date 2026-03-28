using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the QUIC variable-length integer decode and encode hot paths.
/// </summary>
[MemoryDiagnoser]
public class QuicVariableLengthIntegerBenchmarks
{
    private byte[] oneByteEncoded = [];
    private byte[] twoByteEncoded = [];
    private byte[] fourByteEncoded = [];
    private byte[] eightByteEncoded = [];
    private byte[] destination = [];

    /// <summary>
    /// Prepares representative varint encodings and an output buffer.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        oneByteEncoded = QuicBenchmarkData.EncodeVarInt(0x3F);
        twoByteEncoded = QuicBenchmarkData.EncodeVarInt(0x3FFF);
        fourByteEncoded = QuicBenchmarkData.EncodeVarInt(0x3FFF_FFFF);
        eightByteEncoded = QuicBenchmarkData.EncodeVarInt(0x1234_5678_9ABC_DEF0UL);
        destination = new byte[8];
    }

    /// <summary>
    /// Measures 1-byte varint decoding.
    /// </summary>
    [Benchmark]
    public int ParseOneByte()
    {
        return QuicVariableLengthInteger.TryParse(oneByteEncoded, out ulong value, out int bytesConsumed)
            ? unchecked((int)value) ^ bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures 2-byte varint decoding.
    /// </summary>
    [Benchmark]
    public int ParseTwoByte()
    {
        return QuicVariableLengthInteger.TryParse(twoByteEncoded, out ulong value, out int bytesConsumed)
            ? unchecked((int)value) ^ bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures 4-byte varint decoding.
    /// </summary>
    [Benchmark]
    public int ParseFourByte()
    {
        return QuicVariableLengthInteger.TryParse(fourByteEncoded, out ulong value, out int bytesConsumed)
            ? unchecked((int)value) ^ bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures 8-byte varint decoding.
    /// </summary>
    [Benchmark]
    public int ParseEightByte()
    {
        return QuicVariableLengthInteger.TryParse(eightByteEncoded, out ulong value, out int bytesConsumed)
            ? unchecked((int)value) ^ bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures 1-byte varint encoding.
    /// </summary>
    [Benchmark]
    public int FormatOneByte()
    {
        return QuicVariableLengthInteger.TryFormat(0x3F, destination, out int bytesWritten)
            ? destination[0] ^ bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures 2-byte varint encoding.
    /// </summary>
    [Benchmark]
    public int FormatTwoByte()
    {
        return QuicVariableLengthInteger.TryFormat(0x3FFF, destination, out int bytesWritten)
            ? destination[0] ^ bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures 4-byte varint encoding.
    /// </summary>
    [Benchmark]
    public int FormatFourByte()
    {
        return QuicVariableLengthInteger.TryFormat(0x3FFF_FFFF, destination, out int bytesWritten)
            ? destination[0] ^ bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures 8-byte varint encoding.
    /// </summary>
    [Benchmark]
    public int FormatEightByte()
    {
        return QuicVariableLengthInteger.TryFormat(0x1234_5678_9ABC_DEF0UL, destination, out int bytesWritten)
            ? destination[0] ^ bytesWritten
            : -1;
    }
}
